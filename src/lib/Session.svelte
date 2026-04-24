<script lang="ts">
  import {
    onDestroy,
    onMount,
    tick,
    beforeUpdate,
    afterUpdate,
    createEventDispatcher,
  } from "svelte";
  import { fade } from "svelte/transition";
  import { debounce, throttle } from "./utils";

  import { Encrypt } from "./encrypt";
  import { createLock } from "./lock";
  import { Srocket } from "./srocket";
  import type { WsClient, WsServer, WsUser, WsWinsize } from "./protocol";
  import { makeToast } from "./toast";
  import Chat, { type ChatMessage } from "./ui/Chat.svelte";
  import ChooseName from "./ui/ChooseName.svelte";
  import NameList from "./ui/NameList.svelte";
  import NetworkInfo from "./ui/NetworkInfo.svelte";
  import Settings from "./ui/Settings.svelte";
  import Toolbar from "./ui/Toolbar.svelte";
  import XTerm from "./ui/XTerm.svelte";
  import TabbedTerminal from "./ui/TabbedTerminal.svelte";
  import Avatars from "./ui/Avatars.svelte";
  import LiveCursor from "./ui/LiveCursor.svelte";
  import { slide } from "./action/slide";
  import { TouchZoom, INITIAL_ZOOM } from "./action/touchZoom";
  import { arrangeNewTerminal } from "./arrange";
  import { settings } from "./settings";
  import { EyeIcon } from "svelte-feather-icons";

  export let id: string;

  const dispatch = createEventDispatcher<{ receiveName: string }>();

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
  let srocket: Srocket<WsServer, WsClient> | null = null;

  let connected = false;
  let exitReason: string | null = null;

  /** Bound "write" method for each terminal. */
  const writers: Record<number, (data: string) => void> = {};
  const termWrappers: Record<number, HTMLDivElement> = {};
  const termElements: Record<number, HTMLDivElement> = {};
  const termCharWidths: Record<number, number> = {};
  const termRowHeights: Record<number, number> = {};
  const chunknums: Record<number, number> = {};
  const locks: Record<number, any> = {};
  let userId = 0;
  let users: [number, WsUser][] = [];
  let shells: [number, WsWinsize][] = [];
  let subscriptions = new Set<number>();

  // Layout mode — persisted to localStorage
  let layoutMode: "canvas" | "tabs" =
    typeof localStorage !== "undefined" &&
    localStorage.getItem("sshx-layout") === "tabs"
      ? "tabs"
      : "canvas";

  let activeTabId = -1;
  let tabGroupX = 0;
  let tabGroupY = 0;
  let tabGroupCols = 220;
  let tabGroupRows = 50;

  // Height of the toolbar wrapper div (bound via bind:clientHeight).
  // Used to compute the top offset for the TabbedTerminal fixed overlay.
  let toolbarWrapperHeight = 0;
  // top-8 = 32px + wrapper height + 8px gap
  $: toolbarBottom = 32 + toolbarWrapperHeight + 8;

  // Ensure activeTabId stays valid when shells change in tab mode
  $: if (layoutMode === "tabs" && shells.length > 0) {
    if (!shells.find(([id]) => id === activeTabId)) {
      activeTabId = shells[shells.length - 1][0];
    }
  }
  $: if (layoutMode === "tabs" && shells.length === 0) {
    activeTabId = -1;
  }

  // May be undefined before `users` is first populated.
  $: hasWriteAccess = users.find(([uid]) => uid === userId)?.[1]?.canWrite;

  let moving = -1; // Terminal ID that is being dragged.
  let movingOrigin = [0, 0]; // Coordinates of mouse at origin when drag started.
  let movingSize: WsWinsize; // New [x, y] position of the dragged terminal.
  let movingIsDone = false; // Moving finished but hasn't been acknowledged.
  let movingPointerId = -1; // Pointer ID for the active drag.

  let resizing = -1; // Terminal ID that is being resized.
  let resizingOrigin = [0, 0]; // Coordinates of top-left origin when resize started.
  let resizingCell = [0, 0]; // Pixel dimensions of a single terminal cell.
  let resizingSize: WsWinsize; // Last resize message sent.
  let resizingPointerId = -1; // Pointer ID for the active resize.

  const TERM_MAX_ROWS = 200;
  const TERM_MAX_COLS = 400;

  let chatMessages: ChatMessage[] = [];
  let newMessages = false;

  let serverLatencies: number[] = [];
  let shellLatencies: number[] = [];

  // Track whether we've already shown the initial connection toast.
  // Avoids spamming "Connected to the server." on every reconnect.
  let hasShownConnectToast = false;

  // Throttled send functions for move and cursor updates.
  // Defined at component scope so they can be used by both the global
  // pointer handlers and inline event handlers in the template.
  const sendMove = throttle((message: WsClient) => {
    srocket?.send(message);
  }, 50);

  const sendCursor = throttle((message: WsClient) => {
    srocket?.send(message);
  }, 80);

  onMount(async () => {
    // The page hash sets the end-to-end encryption key.
    const key = window.location.hash?.slice(1).split(",")[0] ?? "";
    const writePassword = window.location.hash?.slice(1).split(",")[1] ?? null;

    let v2Tried = false;

    async function tryConnect(useV1: boolean) {
      encrypt = useV1
        ? await Encrypt.new_v1(key)
        : await Encrypt.new(key);
      const encryptedZeros = await encrypt.zeros();

      const writeEncrypt = writePassword
        ? useV1
          ? await Encrypt.new_v1(writePassword)
          : await Encrypt.new(writePassword)
        : null;
      const writeEncryptedZeros = writeEncrypt
        ? await writeEncrypt.zeros()
        : null;

      srocket = new Srocket<WsServer, WsClient>(`/api/s/${id}`, {
        onMessage(message: WsServer) {
          if (message.h) {
            userId = message.h[0];
            dispatch("receiveName", message.h[1]);
            if (!hasShownConnectToast) {
              hasShownConnectToast = true;
              makeToast({
                kind: "success",
                message: `Connected to the server.`,
              });
            }
            exitReason = null;
          } else if (message.a) {
            if (!v2Tried && !useV1) {
              v2Tried = true;
              srocket?.dispose();
              tryConnect(true);
              return;
            }
            exitReason =
              "The URL is not correct, invalid end-to-end encryption key.";
            srocket?.dispose();
          } else if (message.c) {
          let [id, seqnum, chunks] = message.c;
          locks[id](async () => {
            await tick();
            chunknums[id] += chunks.length;
            for (const data of chunks) {
              const buf = await encrypt.decrypt(
                0x100000000n | BigInt(id),
                BigInt(seqnum),
                data,
              );
              seqnum += buf.length;
              writers[id](new TextDecoder().decode(buf));
            }
          });
        } else if (message.u) {
          users = message.u;
        } else if (message.d) {
          const [id, update] = message.d;
          users = users.filter(([uid]) => uid !== id);
          if (update !== null) {
            users = [...users, [id, update]];
          }
        } else if (message.s) {
          shells = message.s;
          if (movingIsDone) {
            moving = -1;
          }
          for (const [id] of message.s) {
            if (!subscriptions.has(id)) {
              chunknums[id] ??= 0;
              locks[id] ??= createLock();
              subscriptions.add(id);
              srocket?.send({ s: [id, chunknums[id]] });
              // In tab mode, new shells should match the current tab dimensions
              // so the PTY is sized correctly from the start.
              if (
                layoutMode === "tabs" &&
                tabGroupCols > 0 &&
                tabGroupRows > 0
              ) {
                srocket?.send({
                  m: [
                    id,
                    {
                      x: tabGroupX,
                      y: tabGroupY,
                      rows: tabGroupRows,
                      cols: tabGroupCols,
                    },
                  ],
                });
              }
            }
          }
        } else if (message.e) {
          const [uid, name, msg] = message.e;
          chatMessages.push({ uid, name, msg, sentAt: new Date() });
          chatMessages = chatMessages;
          if (!showChat) newMessages = true;
        } else if (message.l !== undefined) {
          const shellLatency = Number(message.l);
          shellLatencies = [...shellLatencies, shellLatency].slice(-10);
        } else if (message.p !== undefined) {
          const serverLatency = Date.now() - Number(message.p);
          serverLatencies = [...serverLatencies, serverLatency].slice(-10);
        } else if (message.x) {
          console.warn("Server error: " + message.x);
        }
      },

      onConnect() {
        srocket?.send({ a: [encryptedZeros, writeEncryptedZeros] });
        if ($settings.name) {
          srocket?.send({ n: $settings.name });
        }
        connected = true;
      },

      onDisconnect() {
        connected = false;
        subscriptions.clear();
        users = [];
        serverLatencies = [];
        shellLatencies = [];
      },

      onClose(event: CloseEvent) {
        if (event.code === 4404) {
          exitReason = "Failed to connect: " + event.reason;
        } else if (event.code === 4500) {
          exitReason = "Internal server error: " + event.reason;
        }
      },
    });
    }

    tryConnect(false);
  });

  onDestroy(() => srocket?.dispose());

  // Send periodic ping messages for latency estimation.
  onMount(() => {
    const pingIntervalId = window.setInterval(() => {
      if (srocket?.connected) {
        srocket.send({ p: BigInt(Date.now()) });
      }
    }, 2000);
    return () => window.clearInterval(pingIntervalId);
  });

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
    srocket?.send({ n: $settings.name });
  }

  let counter = 0n;

  async function handleCreate() {
    if (hasWriteAccess === false) {
      makeToast({
        kind: "info",
        message: "You are in read-only mode and cannot create new terminals.",
      });
      return;
    }
    if (shells.length >= 14) {
      makeToast({
        kind: "error",
        message: "You can only create up to 14 terminals.",
      });
      return;
    }

    if (layoutMode === "tabs") {
      // In tab mode, position is irrelevant — use the group's current position
      srocket?.send({ e: [tabGroupX, tabGroupY] });
    } else {
      const existing = shells.map(([id, winsize]) => ({
        x: winsize.x,
        y: winsize.y,
        width: termWrappers[id]?.clientWidth ?? 752,
        height: termWrappers[id]?.clientHeight ?? 515,
      }));
      const { x, y } = arrangeNewTerminal(existing);
      srocket?.send({ e: [x, y] });
      touchZoom.moveTo([x, y], INITIAL_ZOOM);
    }
  }

  function handleLayoutChange(mode: "canvas" | "tabs") {
    if (mode === layoutMode) return;
    layoutMode = mode;
    localStorage.setItem("sshx-layout", mode);
    if (mode === "tabs" && shells.length > 0) {
      const [, firstWinsize] = shells[0];
      tabGroupX = firstWinsize.x;
      tabGroupY = firstWinsize.y;
      // cols/rows will be recomputed by TabbedTerminal's auto-fit on mount
      activeTabId = shells[shells.length - 1][0];
    }
  }

  function handleTabResize(
    event: CustomEvent<{ cols: number; rows: number }>,
  ) {
    tabGroupCols = event.detail.cols;
    tabGroupRows = event.detail.rows;
    // Sync all shells to the new size so PTYs resize properly
    for (const [id, ws] of shells) {
      srocket?.send({ m: [id, { ...ws, rows: event.detail.rows, cols: event.detail.cols }] });
    }
  }

  function handleTabData(event: CustomEvent<{ id: number; data: Uint8Array }>) {
    if (hasWriteAccess) handleInput(event.detail.id, event.detail.data);
  }

  function handleTabFocus(event: CustomEvent<{ id: number }>) {
    if (!hasWriteAccess) return;
    focused = [...focused, event.detail.id];
  }

  function handleTabBlur(event: CustomEvent<{ id: number }>) {
    focused = focused.filter((i) => i !== event.detail.id);
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
    const encrypted = await encrypt.encrypt(0x200000000n, offset, data);
    srocket?.send({ d: [id, encrypted, offset] });
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

  // Global pointer handler logic follows, attached to the window element for smoothness.
  // These handlers only process events for the resize handle (not terminal title drag,
  // which is handled inline by XTerm.svelte) and cursor position updates.
  onMount(() => {
    function handlePointer(event: PointerEvent) {
      // Terminal title drag is handled entirely by XTerm.svelte inline handlers.
      // Only handle resize events here.
      if (resizing !== -1 && event.pointerId === resizingPointerId) {
        const cols = Math.min(
          Math.max(
            Math.floor((event.pageX - resizingOrigin[0]) / resizingCell[0]),
            TERM_MIN_COLS,
          ),
          TERM_MAX_COLS,
        );
        const rows = Math.min(
          Math.max(
            Math.floor((event.pageY - resizingOrigin[1]) / resizingCell[1]),
            TERM_MIN_ROWS,
          ),
          TERM_MAX_ROWS,
        );
        if (rows !== resizingSize.rows || cols !== resizingSize.cols) {
          resizingSize = { ...resizingSize, rows, cols };
          srocket?.send({ m: [resizing, resizingSize] });
        }
      }

      // Update cursor position for all pointer moves
      if (event.pointerType === "mouse") {
        sendCursor({ c: normalizePosition(event) });
      }
    }

    function handlePointerEnd(event: PointerEvent) {
      if (resizing !== -1 && event.pointerId === resizingPointerId) {
        resizing = -1;
        resizingPointerId = -1;
      }

      if (event.type === "pointerleave" && event.pointerType === "mouse") {
        sendCursor.cancel();
        srocket?.send({ c: null });
      }
    }

    window.addEventListener("pointermove", handlePointer);
    window.addEventListener("pointerup", handlePointerEnd);
    window.addEventListener("pointercancel", handlePointerEnd);
    document.body.addEventListener("pointerleave", handlePointerEnd);
    return () => {
      window.removeEventListener("pointermove", handlePointer);
      window.removeEventListener("pointerup", handlePointerEnd);
      window.removeEventListener("pointercancel", handlePointerEnd);
      document.body.removeEventListener("pointerleave", handlePointerEnd);
      sendMove.cancel();
      sendCursor.cancel();
    };
  });

  let focused: number[] = [];
  $: setFocus(focused);

  // Wait a small amount of time, since blur events happen before focus events.
  const setFocus = debounce((focused: number[]) => {
    srocket?.send({ f: focused[0] ?? null });
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
    bind:clientHeight={toolbarWrapperHeight}
  >
    <Toolbar
      {connected}
      {newMessages}
      {hasWriteAccess}
      {layoutMode}
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
      on:layoutChange={({ detail }) => handleLayoutChange(detail)}
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
        on:chat={(event) => srocket?.send({ t: event.detail })}
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
        <div class="text-green-400">You are connected!</div>
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
      <div class="text-yellow-400">Connecting…</div>
    {/if}

    <div class="mt-4">
      <NameList {users} />
    </div>
  </div>

  <div class="absolute inset-0 overflow-hidden touch-none" bind:this={fabricEl}>
    {#if layoutMode === "canvas"}
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
            on:cellsize={({ detail }) => {
              termCharWidths[id] = detail.charWidth;
              termRowHeights[id] = detail.rowHeight;
            }}
            on:data={({ detail: data }) =>
              hasWriteAccess && handleInput(id, data)}
            on:close={() => srocket?.send({ x: id })}
            on:shrink={() => {
              if (!hasWriteAccess) return;
              const rows = Math.max(
                Math.min(ws.rows - 4, TERM_MAX_ROWS),
                TERM_MIN_ROWS,
              );
              const cols = Math.max(
                Math.min(ws.cols - 10, TERM_MAX_COLS),
                TERM_MIN_COLS,
              );
              if (rows !== ws.rows || cols !== ws.cols) {
                srocket?.send({ m: [id, { ...ws, rows, cols }] });
              }
            }}
            on:expand={() => {
              if (!hasWriteAccess) return;
              const rows = Math.min(ws.rows + 4, TERM_MAX_ROWS);
              const cols = Math.min(ws.cols + 10, TERM_MAX_COLS);
              srocket?.send({ m: [id, { ...ws, rows, cols }] });
            }}
            on:bringToFront={() => {
              if (!hasWriteAccess) return;
              showNetworkInfo = false;
              srocket?.send({ m: [id, null] });
            }}
            on:startMove={({ detail: event }) => {
              if (!hasWriteAccess) return;
              if (event.type === "pointerdown") {
                const [x, y] = normalizePosition(event);
                // Set movingSize BEFORE moving = id, so that if Svelte's reactive
                // system re-evaluates `ws = id === moving ? movingSize : winsize`
                // during the `moving = id` assignment, movingSize is already
                // defined and `ws` will not be undefined.
                movingSize = ws;
                moving = id;
                movingPointerId = event.pointerId;
                movingOrigin = [x - movingSize.x, y - movingSize.y];
                movingIsDone = false;
              } else if (
                event.type === "pointermove" &&
                moving === id &&
                !movingIsDone
              ) {
                const [x, y] = normalizePosition(event);
                movingSize = {
                  ...movingSize,
                  x: Math.round(x - movingOrigin[0]),
                  y: Math.round(y - movingOrigin[1]),
                };
                sendMove({ m: [moving, movingSize] });
              } else if (event.type === "pointerup" && moving === id) {
                movingIsDone = true;
                sendMove.cancel();
                srocket?.send({ m: [moving, movingSize] });
                movingPointerId = -1;
              }
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
            on:pointerdown={(event) => {
              event.stopPropagation();
              if (!hasWriteAccess) return;
              const cw = termCharWidths[id];
              const rh = termRowHeights[id];
              if (cw > 0 && rh > 0) {
                resizing = id;
                resizingPointerId = event.pointerId;
                (event.currentTarget as HTMLElement).setPointerCapture(
                  event.pointerId,
                );
                resizingOrigin = [
                  event.pageX - ws.cols * cw,
                  event.pageY - ws.rows * rh,
                ];
                resizingCell = [cw, rh];
                resizingSize = ws;
              }
            }}
            on:pointerup={(event) => {
              if (resizing === id && event.pointerId === resizingPointerId) {
                resizing = -1;
                resizingPointerId = -1;
                (event.currentTarget as HTMLElement).releasePointerCapture(
                  event.pointerId,
                );
              }
            }}
            on:pointercancel={(event) => {
              if (resizing === id && event.pointerId === resizingPointerId) {
                resizing = -1;
                resizingPointerId = -1;
                (event.currentTarget as HTMLElement).releasePointerCapture(
                  event.pointerId,
                );
              }
            }}
          />
        </div>
      {/each}
    {:else}
      <!-- Tab mode: full-viewport TabbedTerminal overlay -->
      <TabbedTerminal
        {shells}
        {activeTabId}
        {toolbarBottom}
        {connected}
        {writers}
        {termElements}
        {hasWriteAccess}
        on:switchTab={({ detail: { id } }) => (activeTabId = id)}
        on:newTab={handleCreate}
        on:closeTab={({ detail: { id } }) => srocket?.send({ x: id })}
        on:resize={handleTabResize}
        on:data={handleTabData}
        on:bringToFront={() => {
          showNetworkInfo = false;
        }}
        on:focus={handleTabFocus}
        on:blur={handleTabBlur}
      />
    {/if}

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
