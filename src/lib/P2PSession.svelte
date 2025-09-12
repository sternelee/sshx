<script lang="ts">
  import {
    onDestroy,
    onMount,
    tick,
    beforeUpdate,
    afterUpdate,
  } from "svelte";
  import { fade } from "svelte/transition";
  import { debounce, throttle } from "lodash-es";

  import { Encrypt } from "./encrypt";
  import { createLock } from "./lock";
  import { initApi } from "./sshx-api";
  import type { SshxAPI } from "./sshx-api";
  import type { SshxEvent, User, Winsize } from "./sshx-api";
  import { makeToast } from "./toast";
  import Chat, { type ChatMessage } from "./ui/Chat.svelte";
  import ChooseName from "./ui/ChooseName.svelte";
  import NameList from "./ui/NameList.svelte";
  import NetworkInfo from "./ui/NetworkInfo.svelte";
  import Settings from "./ui/Settings.svelte";
  import Toolbar from "./ui/Toolbar.svelte";
  import XTerm from "./ui/XTerm.svelte";
  import Avatars from "./ui/Avatars.svelte";
  import LiveCursor from "./ui/LiveCursor.svelte";
  import { slide } from "./action/slide";
  import { TouchZoom, INITIAL_ZOOM } from "./action/touchZoom";
  import { arrangeNewTerminal } from "./arrange";
  import { settings } from "./settings";
  import { EyeIcon } from "svelte-feather-icons";


  // The magic numbers "left" and "top" are used to approximately center the
  // terminal at the time that it is first created.
  const CONSTANT_OFFSET_LEFT = 378;
  const CONSTANT_OFFSET_TOP = 240;

  const OFFSET_LEFT_CSS = `calc(50vw - ${CONSTANT_OFFSET_LEFT}px)`;
  const OFFSET_TOP_CSS = `calc(50vh - ${CONSTANT_OFFSET_TOP}px)`;
  const OFFSET_TRANSFORM_ORIGIN_CSS = `calc(-1 * ${OFFSET_LEFT_CSS}) calc(-1 * ${OFFSET_TOP_CSS})`;

  // Terminal width and height limits.
  const TERM_MIN_ROWS = 8;
  const TERM_MIN_COLS = 32;

  function getConstantOffset() {
    return [
      0.5 * window.innerWidth - CONSTANT_OFFSET_LEFT,
      0.5 * window.innerHeight - CONSTANT_OFFSET_TOP,
    ];
  }

  let fabricEl: HTMLElement;
  let touchZoom: TouchZoom;
  let center = [0, 0];
  let zoom = INITIAL_ZOOM;

  let showChat = false; // @hmr:keep
  let settingsOpen = false; // @hmr:keep
  let showNetworkInfo = false; // @hmr:keep

  onMount(() => {
    touchZoom = new TouchZoom(fabricEl);
    touchZoom.onMove(() => {
      center = touchZoom.center;
      zoom = touchZoom.zoom;

      // Blur if the user is currently focused on a terminal.
      //
      // This makes it so that panning does not stop when the cursor happens to
      // intersect with the textarea, which absorbs wheel and touch events.
      if (document.activeElement) {
        const classList = [...document.activeElement.classList];
        if (classList.includes("xterm-helper-textarea")) {
          (document.activeElement as HTMLElement).blur();
        }
      }

      showNetworkInfo = false;
    });
  });

  /** Returns the mouse position in infinite grid coordinates, offset transformations and zoom. */
  function normalizePosition(event: MouseEvent): [number, number] {
    const [ox, oy] = getConstantOffset();
    return [
      Math.round(center[0] + event.pageX / zoom - ox),
      Math.round(center[1] + event.pageY / zoom - oy),
    ];
  }

  let encrypt: Encrypt;
  let sshxApi: SshxAPI | null = null;
  let currentSessionId: string | null = null;

  // Add these variables to store encrypted zeros
  let encryptedZeros: Uint8Array;
  let writeEncryptedZeros: Uint8Array | null;

  let connected = false;
  let exitReason: string | null = null;

  /** Bound "write" method for each terminal. */
  const writers: Record<number, (data: string) => void> = {};
  const termWrappers: Record<number, HTMLDivElement> = {};
  const termElements: Record<number, HTMLDivElement> = {};
  const chunknums: Record<number, number> = {};
  const locks: Record<number, any> = {};
  let userId = 0;
  let users: [number, User][] = [];
  let shells: [number, Winsize][] = [];
  let subscriptions = new Set<number>();

  // May be undefined before `users` is first populated.
  $: hasWriteAccess = users.find(([uid]) => uid === userId)?.[1]?.canWrite;

  let moving = -1; // Terminal ID that is being dragged.
  let movingOrigin = [0, 0]; // Coordinates of mouse at origin when drag started.
  let movingSize: Winsize; // New [x, y] position of the dragged terminal.
  let movingIsDone = false; // Moving finished but hasn't been acknowledged.

  let resizing = -1; // Terminal ID that is being resized.
  let resizingOrigin = [0, 0]; // Coordinates of top-left origin when resize started.
  let resizingCell = [0, 0]; // Pixel dimensions of a single terminal cell.
  let resizingSize: Winsize; // Last resize message sent.

  let chatMessages: ChatMessage[] = [];
  let newMessages = false;

  let serverLatencies: number[] = [];
  let shellLatencies: number[] = [];

  onMount(async () => {
    // The page hash sets the end-to-end encryption key.
    const key = window.location.hash?.slice(1).split(",")[0] ?? "";
    const writePassword = window.location.hash?.slice(1).split(",")[1] ?? null;

    encrypt = await Encrypt.new(key);
    encryptedZeros = await encrypt.zeros();

    writeEncryptedZeros = writePassword
      ? await (await Encrypt.new(writePassword)).zeros()
      : null;

    // Initialize the sshx API
    try {
      // const { initApi } = import("./sshx-api");
      sshxApi = await initApi();
    } catch (error) {
      console.error("Failed to initialize sshx API:", error);
      exitReason = "Failed to initialize P2P connection.";
      return;
    }

    // Try to create or join session based on URL
    const ticket = new URLSearchParams(window.location.search).get("ticket");

    try {
      if (ticket) {
        currentSessionId = await sshxApi.joinSession(ticket);
      } else {
        currentSessionId = await sshxApi.createSession();
        // Get the ticket for sharing
        const newTicket = sshxApi.getSessionTicket(currentSessionId);
        // Update URL with the new ticket
        const url = new URL(window.location.href);
        url.searchParams.set("ticket", newTicket);
        window.history.pushState({}, "", url.toString());
      }

      // Subscribe to session events
      if (currentSessionId) {
        sshxApi.subscribeToEvents(currentSessionId, handleEvent);
      }
    } catch (error) {
      console.error("Failed to create/join session:", error);
      exitReason = "Failed to connect to P2P session.";
    }
  });

  function handleEvent(event: SshxEvent) {
    console.log("Received event:", event);
    if (event.hello) {
      // For P2P mode, we simulate the hello event
      userId = Math.floor(Math.random() * 1000000);
      connected = true;
      exitReason = null;

      // Create initial shell
      setTimeout(() => {
        if (connected) {
          makeToast({
            kind: "success",
            message: `Connected to P2P network.`,
          });
        }
      }, 100);
    } else if (event.invalidAuth) {
      exitReason = "The URL is not correct, invalid end-to-end encryption key.";
      connected = false;
    } else if (event.chunks) {
      let [id, seqnum, chunks] = event.chunks;
      if (writers[id]) {
        locks[id](async () => {
          await tick();
          chunknums[id] += chunks.length;
          for (const data of chunks) {
            const dataArray =
              data instanceof Uint8Array ? data : new Uint8Array(data);
            const buf = await encrypt.segment(
              0x100000000n | BigInt(id),
              BigInt(seqnum),
              dataArray,
            );
            seqnum += dataArray.length;
            writers[id](new TextDecoder().decode(buf));
          }
        });
      }
    } else if (event.users) {
      users = event.users;
    } else if (event.userDiff) {
      const [id, update] = event.userDiff;
      users = users.filter(([uid]) => uid !== id);
      if (update !== null) {
        users = [...users, [id, update]];
      }
    } else if (event.shells) {
      shells = event.shells;
      if (movingIsDone) {
        moving = -1;
      }
      for (const [id] of event.shells) {
        if (!subscriptions.has(id)) {
          chunknums[id] ??= 0;
          locks[id] ??= createLock();
          subscriptions.add(id);
          // For P2P mode, we don't need to send subscribe messages
          // The shell will automatically start receiving data
        }
      }
    } else if (event.hear) {
      const [uid, name, msg] = event.hear;
      chatMessages.push({ uid, name, msg, sentAt: new Date() });
      chatMessages = chatMessages;
      if (!showChat) newMessages = true;
    } else if (event.shellLatency !== undefined) {
      const shellLatency = Number(event.shellLatency);
      shellLatencies = [...shellLatencies, shellLatency].slice(-10);
    } else if (event.error) {
      console.warn("P2P error: " + event.error);
    }
  }

  // Helper function to send commands
  async function sendCommand(command: any): Promise<void> {
    if (!currentSessionId || !sshxApi) {
      console.warn("Cannot send command: session not available");
      return;
    }

    // Convert command to ClientMessage format and send as binary data
    let clientMessage;

    if (command.authenticate) {
      clientMessage = {
        type: "Hello",
        data: { content: "auth" },
      };
    } else if (command.setName) {
      clientMessage = {
        type: "Hello",
        data: { content: command.setName },
      };
    } else if (command.create) {
      // Send ClientMessage::CreatedShell to acknowledge shell creation
      // Generate a valid u32 ID (max 4,294,967,295)
      const id = Math.floor(Math.random() * 4294967295);
      clientMessage = {
        type: "CreatedShell",
        data: {
          id: id,
        },
      };
    } else if (command.close) {
      // Send ClientMessage::ClosedShell to acknowledge shell closure
      clientMessage = {
        type: "ClosedShell",
        data: {
          id: command.close,
        },
      };
    } else if (command.move) {
      // This will be handled by the backend
      return;
    } else if (command.subscribe) {
      // This will be handled by the backend
      return;
    } else if (command.setCursor) {
      // This will be handled by the backend
      return;
    } else if (command.setFocus) {
      // This will be handled by the backend
      return;
    } else if (command.ping) {
      // Ping/Pong events removed - no-op
      return;
    } else if (command.chat) {
      // This will be handled by the backend
      return;
    } else {
      console.warn("Unknown command type:", command);
      return;
    }

    const encoder = new TextEncoder();
    const data = encoder.encode(JSON.stringify(clientMessage));
    await sshxApi.sendData(currentSessionId, data);
  }

  onDestroy(() => {
    if (currentSessionId && sshxApi) {
      sshxApi.closeSession(currentSessionId);
    }
  });

  // Ping/Pong events removed - no periodic ping needed

  function integerMedian(values: number[]) {
    if (values.length === 0) {
      return null;
    }
    const sorted = values.toSorted();
    const mid = Math.floor(sorted.length / 2);
    return sorted.length % 2 !== 0
      ? sorted[mid]
      : Math.round((sorted[mid - 1] + sorted[mid]) / 2);
  }

  $: if ($settings.name) {
    sendCommand({ setName: $settings.name });
  }

  let counter = 0n;

  async function handleCreate() {
    // if (hasWriteAccess === false) {
    //   makeToast({
    //     kind: "info",
    //     message: "You are in read-only mode and cannot create new terminals.",
    //   });
    //   return;
    // }
    if (shells.length >= 14) {
      makeToast({
        kind: "error",
        message: "You can only create up to 14 terminals.",
      });
      return;
    }
    const existing = shells.map(([id, winsize]) => ({
      x: winsize.x,
      y: winsize.y,
      width: termWrappers[id].clientWidth,
      height: termWrappers[id].clientHeight,
    }));
    const { x, y } = arrangeNewTerminal(existing);
    sendCommand({ create: [x, y] });
    touchZoom.moveTo([x, y], INITIAL_ZOOM);
  }

  async function handleInput(id: number, data: Uint8Array) {
    if (counter === 0n) {
      // On the first call, initialize the counter to a random 64-bit integer.
      const array = new Uint8Array(8);
      crypto.getRandomValues(array);
      counter = new DataView(array.buffer).getBigUint64(0);
    }
    const offset = counter;
    counter += BigInt(data.length); // Must increment before the `await`.
    const encrypted = await encrypt.segment(0x200000000n, offset, data);

    // Send encrypted data through P2P client as ClientMessage::Data
    if (currentSessionId && sshxApi) {
      const message = {
        type: "Data",
        data: {
          id: id,
          data: Array.from(encrypted), // Convert Uint8Array to array for JSON serialization
          seq: Number(offset),
        },
      };
      const encoder = new TextEncoder();
      const dataToSend = encoder.encode(JSON.stringify(message));
      await sshxApi.sendData(currentSessionId, dataToSend);
    }
  }

  // Stupid hack to preserve input focus when terminals are reordered.
  // See: https://github.com/sveltejs/svelte/issues/3973
  let activeElement: Element | null = null;

  beforeUpdate(() => {
    activeElement = document.activeElement;
  });

  afterUpdate(() => {
    if (activeElement instanceof HTMLElement) activeElement.focus();
  });

  // Global mouse handler logic follows, attached to the window element for smoothness.
  onMount(() => {
    // 50 milliseconds between successive terminal move updates.
    const sendMove = throttle((message: any) => {
      sendCommand(message);
    }, 50);

    // 80 milliseconds between successive cursor updates.
    const sendCursor = throttle((message: any) => {
      sendCommand(message);
    }, 80);

    function handleMouse(event: MouseEvent) {
      if (moving !== -1 && !movingIsDone) {
        const [x, y] = normalizePosition(event);
        movingSize = {
          ...movingSize,
          x: Math.round(x - movingOrigin[0]),
          y: Math.round(y - movingOrigin[1]),
        };
        sendMove({ move: [moving, movingSize] });
      }

      if (resizing !== -1) {
        const cols = Math.max(
          Math.floor((event.pageX - resizingOrigin[0]) / resizingCell[0]),
          TERM_MIN_COLS, // Minimum number of columns.
        );
        const rows = Math.max(
          Math.floor((event.pageY - resizingOrigin[1]) / resizingCell[1]),
          TERM_MIN_ROWS, // Minimum number of rows.
        );
        if (rows !== resizingSize.rows || cols !== resizingSize.cols) {
          resizingSize = { ...resizingSize, rows, cols };
          sendCommand({ move: [resizing, resizingSize] });
        }
      }

      sendCursor({ setCursor: normalizePosition(event) });
    }

    function handleMouseEnd(event: MouseEvent) {
      if (moving !== -1) {
        movingIsDone = true;
        sendMove.cancel();
        sendCommand({ move: [moving, movingSize] });
      }

      if (resizing !== -1) {
        resizing = -1;
      }

      if (event.type === "mouseleave") {
        sendCursor.cancel();
        sendCommand({ setCursor: null });
      }
    }

    window.addEventListener("mousemove", handleMouse);
    window.addEventListener("mouseup", handleMouseEnd);
    document.body.addEventListener("mouseleave", handleMouseEnd);
    return () => {
      window.removeEventListener("mousemove", handleMouse);
      window.removeEventListener("mouseup", handleMouseEnd);
      document.body.removeEventListener("mouseleave", handleMouseEnd);
    };
  });

  let focused: number[] = [];
  $: setFocus(focused);

  // Wait a small amount of time, since blur events happen before focus events.
  const setFocus = debounce((focused: number[]) => {
    sendCommand({ setFocus: focused[0] ?? null });
  }, 20);
</script>

<!-- Wheel handler stops native macOS Chrome zooming on pinch. -->
<main
  class="p-8"
  class:cursor-nwse-resize={resizing !== -1}
  on:wheel={(event) => event.preventDefault()}
>
  <div
    class="absolute top-8 inset-x-0 flex justify-center pointer-events-none z-10"
  >
    <Toolbar
      {connected}
      {newMessages}
      {hasWriteAccess}
      on:create={handleCreate}
      on:chat={() => {
        showChat = !showChat;
        newMessages = false;
      }}
      on:settings={() => {
        settingsOpen = true;
      }}
      on:networkInfo={() => {
        showNetworkInfo = !showNetworkInfo;
      }}
    />

    {#if showNetworkInfo}
      <div class="absolute top-20 translate-x-[116.5px]">
        <NetworkInfo
          status={connected
            ? "connected"
            : exitReason
              ? "no-shell"
              : "no-server"}
          serverLatency={integerMedian(serverLatencies)}
          shellLatency={integerMedian(shellLatencies)}
        />
      </div>
    {/if}
  </div>

  {#if showChat}
    <div
      class="absolute flex flex-col justify-end inset-y-4 right-4 w-80 pointer-events-none z-10"
    >
      <Chat
        {userId}
        messages={chatMessages}
        on:chat={(event) => {
          sendCommand({ chat: event.detail });
        }}
        on:close={() => (showChat = false)}
      />
    </div>
  {/if}

  <Settings open={settingsOpen} on:close={() => (settingsOpen = false)} />

  <ChooseName />

  <!--
    Dotted circle background appears underneath the rest of the elements, but
    moves and zooms with the fabric of the canvas.
  -->
  <div
    class="absolute inset-0 -z-10"
    style:background-image="radial-gradient(#333 {zoom}px, transparent 0)"
    style:background-size="{24 * zoom}px {24 * zoom}px"
    style:background-position="{-zoom * center[0]}px {-zoom * center[1]}px"
  />

  <div class="py-2">
    {#if exitReason !== null}
      <div class="text-red-400">{exitReason}</div>
    {:else if connected}
      <div class="flex items-center">
        <div class="text-green-400">You are connected via P2P!</div>
        {#if userId && hasWriteAccess === false}
          <div
            class="bg-yellow-900 text-yellow-200 px-1 py-0.5 rounded ml-3 inline-flex items-center gap-1"
          >
            <EyeIcon size="14" />
            <span class="text-xs">Read-only</span>
          </div>
        {/if}
      </div>
    {:else}
      <div class="text-yellow-400">Connecting to P2P network…</div>
    {/if}

    <div class="mt-4">
      <NameList {users} />
    </div>
  </div>

  <div class="absolute inset-0 overflow-hidden touch-none" bind:this={fabricEl}>
    {#each shells as [id, winsize] (id)}
      {@const ws = id === moving ? movingSize : winsize}
      <div
        class="absolute"
        style:left={OFFSET_LEFT_CSS}
        style:top={OFFSET_TOP_CSS}
        style:transform-origin={OFFSET_TRANSFORM_ORIGIN_CSS}
        transition:fade|local
        use:slide={{ x: ws.x, y: ws.y, center, zoom, immediate: id === moving }}
        bind:this={termWrappers[id]}
      >
        <XTerm
          rows={ws.rows}
          cols={ws.cols}
          bind:write={writers[id]}
          bind:termEl={termElements[id]}
          on:data={({ detail: data }) =>
            hasWriteAccess && handleInput(id, data)}
          on:close={() => {
            sendCommand({ close: id });
          }}
          on:shrink={() => {
            if (!hasWriteAccess) return;
            const rows = Math.max(ws.rows - 4, TERM_MIN_ROWS);
            const cols = Math.max(ws.cols - 10, TERM_MIN_COLS);
            if (rows !== ws.rows || cols !== ws.cols) {
              sendCommand({ move: [id, { ...ws, rows, cols }] });
            }
          }}
          on:expand={() => {
            if (!hasWriteAccess) return;
            const rows = ws.rows + 4;
            const cols = ws.cols + 10;
            sendCommand({ move: [id, { ...ws, rows, cols }] });
          }}
          on:bringToFront={() => {
            if (!hasWriteAccess) return;
            showNetworkInfo = false;
            sendCommand({ move: [id, null] });
          }}
          on:startMove={({ detail: event }) => {
            if (!hasWriteAccess) return;
            const [x, y] = normalizePosition(event);
            moving = id;
            movingOrigin = [x - ws.x, y - ws.y];
            movingSize = ws;
            movingIsDone = false;
          }}
          on:focus={() => {
            if (!hasWriteAccess) return;
            focused = [...focused, id];
          }}
          on:blur={() => {
            focused = focused.filter((i) => i !== id);
          }}
        />

        <!-- User avatars -->
        <div class="absolute bottom-2.5 right-2.5 pointer-events-none">
          <Avatars
            users={users.filter(
              ([uid, user]) => uid !== userId && user.focus === id,
            )}
          />
        </div>

        <!-- Interactable element for resizing -->
        <div
          class="absolute w-5 h-5 -bottom-1 -right-1 cursor-nwse-resize"
          on:mousedown={(event) => {
            const canvasEl = termElements[id].querySelector(".xterm-screen");
            if (canvasEl) {
              resizing = id;
              const r = canvasEl.getBoundingClientRect();
              resizingOrigin = [event.pageX - r.width, event.pageY - r.height];
              resizingCell = [r.width / ws.cols, r.height / ws.rows];
              resizingSize = ws;
            }
          }}
          on:pointerdown={(event) => event.stopPropagation()}
        />
      </div>
    {/each}

    {#each users.filter(([id, user]) => id !== userId && user.cursor !== null) as [id, user] (id)}
      <div
        class="absolute"
        style:left={OFFSET_LEFT_CSS}
        style:top={OFFSET_TOP_CSS}
        style:transform-origin={OFFSET_TRANSFORM_ORIGIN_CSS}
        transition:fade|local={{ duration: 200 }}
        use:slide={{
          x: user.cursor?.[0] ?? 0,
          y: user.cursor?.[1] ?? 0,
          center,
          zoom,
        }}
      >
        <LiveCursor {user} />
      </div>
    {/each}
  </div>
</main>
