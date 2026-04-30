<script lang="ts">
  import {
    onDestroy,
    onMount,
    tick,
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

  let {
    id,
    onreceiveName,
  }: {
    id: string;
    onreceiveName?: (name: string) => void;
  } = $props();

  const CONSTANT_OFFSET_LEFT = 378;
  const CONSTANT_OFFSET_TOP = 240;

  const OFFSET_LEFT_CSS = `calc(50vw - ${CONSTANT_OFFSET_LEFT}px)`;
  const OFFSET_TOP_CSS = `calc(50vh - ${CONSTANT_OFFSET_TOP}px)`;
  const OFFSET_TRANSFORM_ORIGIN_CSS = `calc(-1 * ${OFFSET_LEFT_CSS}) calc(-1 * ${OFFSET_TOP_CSS})`;

  const TERM_MIN_ROWS = 8;
  const TERM_MIN_COLS = 32;
  const TERM_MAX_ROWS = 200;
  const TERM_MAX_COLS = 400;

  function getConstantOffset() {
    return [
      0.5 * window.innerWidth - CONSTANT_OFFSET_LEFT,
      0.5 * window.innerHeight - CONSTANT_OFFSET_TOP,
    ];
  }

  let fabricEl = $state<HTMLElement>(null as any);
  let touchZoom: TouchZoom;
  let center = $state([0, 0]);
  let zoom = $state(INITIAL_ZOOM);

  let showChat = $state(false); // @hmr:keep
  let settingsOpen = $state(false); // @hmr:keep
  let showNetworkInfo = $state(false); // @hmr:keep

  onMount(() => {
    touchZoom = new TouchZoom(fabricEl);
    touchZoom.onMove(() => {
      center = touchZoom.center;
      zoom = touchZoom.zoom;
      if (document.activeElement) {
        const classList = [...document.activeElement.classList];
        if (classList.includes("xterm-helper-textarea")) {
          (document.activeElement as HTMLElement).blur();
        }
      }
      showNetworkInfo = false;
    });
  });

  function normalizePosition(event: MouseEvent): [number, number] {
    const [ox, oy] = getConstantOffset();
    return [
      Math.round(center[0] + event.pageX / zoom - ox),
      Math.round(center[1] + event.pageY / zoom - oy),
    ];
  }

  let encrypt: Encrypt;
  let srocket = $state<Srocket<WsServer, WsClient> | null>(null);

  let connected = $state(false);
  let exitReason = $state<string | null>(null);

  const writers: Record<number, (data: string) => void> = {};
  const termWrappers: Record<number, HTMLDivElement> = {};
  const termElements: Record<number, HTMLDivElement> = {};
  const termCharWidths: Record<number, number> = {};
  const termRowHeights: Record<number, number> = {};
  const chunknums: Record<number, number> = {};
  const locks: Record<number, any> = {};
  let userId = $state(0);
  let users = $state<[number, WsUser][]>([]);
  let shells = $state<[number, WsWinsize][]>([]);
  let subscriptions = new Set<number>();

  let layoutMode = $state<"canvas" | "tabs">(
    typeof localStorage !== "undefined" &&
    localStorage.getItem("sshx-layout") === "tabs"
      ? "tabs"
      : "canvas",
  );

  let activeTabId = $state(-1);
  let tabGroupX = $state(0);
  let tabGroupY = $state(0);
  let tabGroupCols = $state(220);
  let tabGroupRows = $state(50);

  let toolbarWrapperHeight = $state(0);
  const toolbarBottom = $derived(32 + toolbarWrapperHeight + 8);

  const hasWriteAccess = $derived(
    users.find(([uid]) => uid === userId)?.[1]?.canWrite,
  );

  // Ensure activeTabId stays valid when shells change in tab mode
  $effect(() => {
    if (layoutMode === "tabs" && shells.length > 0) {
      if (!shells.find(([sid]) => sid === activeTabId)) {
        activeTabId = shells[shells.length - 1][0];
      }
    }
    if (layoutMode === "tabs" && shells.length === 0) {
      activeTabId = -1;
    }
  });

  let moving = $state(-1);
  let movingOrigin = [0, 0];
  let movingSize = $state<WsWinsize>(null as any);
  let movingIsDone = false;
  let movingPointerId = -1;

  let resizing = $state(-1);
  let resizingOrigin = [0, 0];
  let resizingCell = [0, 0];
  let resizingSize = $state<WsWinsize>(null as any);
  let resizingPointerId = -1;

  let chatMessages = $state<ChatMessage[]>([]);
  let newMessages = $state(false);

  let serverLatencies = $state<number[]>([]);
  let shellLatencies = $state<number[]>([]);

  let hasShownConnectToast = false;

  const sendMove = throttle((message: WsClient) => {
    srocket?.send(message);
  }, 50);

  const sendCursor = throttle((message: WsClient) => {
    srocket?.send(message);
  }, 80);

  onMount(async () => {
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
            onreceiveName?.(message.h[1]);
            if (!hasShownConnectToast) {
              hasShownConnectToast = true;
              makeToast({ kind: "success", message: `Connected to the server.` });
            }
            exitReason = null;
          } else if (message.a) {
            if (!v2Tried && !useV1) {
              v2Tried = true;
              srocket?.dispose();
              tryConnect(true);
              return;
            }
            exitReason = "The URL is not correct, invalid end-to-end encryption key.";
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
            if (movingIsDone) moving = -1;
            for (const [id] of message.s) {
              if (!subscriptions.has(id)) {
                chunknums[id] ??= 0;
                locks[id] ??= createLock();
                subscriptions.add(id);
                srocket?.send({ s: [id, chunknums[id]] });
                if (layoutMode === "tabs" && tabGroupCols > 0 && tabGroupRows > 0) {
                  srocket?.send({
                    m: [id, { x: tabGroupX, y: tabGroupY, rows: tabGroupRows, cols: tabGroupCols }],
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
            shellLatencies = [...shellLatencies, Number(message.l)].slice(-10);
          } else if (message.p !== undefined) {
            serverLatencies = [...serverLatencies, Date.now() - Number(message.p)].slice(-10);
          } else if (message.x) {
            console.warn("Server error: " + message.x);
          }
        },

        onConnect() {
          srocket?.send({ a: [encryptedZeros, writeEncryptedZeros] });
          if ($settings.name) srocket?.send({ n: $settings.name });
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

  onMount(() => {
    const pingIntervalId = window.setInterval(() => {
      if (srocket?.connected) srocket.send({ p: BigInt(Date.now()) });
    }, 2000);
    return () => window.clearInterval(pingIntervalId);
  });

  function integerMedian(values: number[]) {
    if (values.length === 0) return null;
    const sorted = values.toSorted();
    const mid = Math.floor(sorted.length / 2);
    return sorted.length % 2 !== 0
      ? sorted[mid]
      : Math.round((sorted[mid - 1] + sorted[mid]) / 2);
  }

  $effect(() => {
    if ($settings.name) srocket?.send({ n: $settings.name });
  });

  let counter = 0n;

  async function handleCreate() {
    if (hasWriteAccess === false) {
      makeToast({ kind: "info", message: "You are in read-only mode and cannot create new terminals." });
      return;
    }
    if (shells.length >= 14) {
      makeToast({ kind: "error", message: "You can only create up to 14 terminals." });
      return;
    }
    if (layoutMode === "tabs") {
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
      activeTabId = shells[shells.length - 1][0];
    }
  }

  function handleTabResize(detail: { id: number; cols: number; rows: number }) {
    const { id, cols, rows } = detail;
    tabGroupCols = cols;
    tabGroupRows = rows;
    const target = shells.find(([sid]) => sid === id);
    if (!target) return;
    const [, ws] = target;
    srocket?.send({ m: [id, { ...ws, rows, cols }] });
  }

  function handleSplitTab(_detail: { fromId: number; pos: "right" | "left" | "up" | "down" }) {
    handleCreate();
  }

  async function handleInput(id: number, data: Uint8Array) {
    if (counter === 0n) {
      const array = new Uint8Array(8);
      crypto.getRandomValues(array);
      counter = new DataView(array.buffer).getBigUint64(0);
    }
    const offset = counter;
    counter += BigInt(data.length);
    const encrypted = await encrypt.encrypt(0x200000000n, offset, data);
    srocket?.send({ d: [id, encrypted, offset] });
  }

  // Preserve input focus across reactive DOM updates that might move elements.
  // In runes mode beforeUpdate/afterUpdate are not available; we instead use
  // a tick-based effect that restores the active element after each render.
  let _savedFocus: HTMLElement | null = null;
  $effect(() => {
    // Reading any reactive state here is intentional — the effect runs after
    // every render, which is the closest equivalent to afterUpdate.
    shells; users; layoutMode;
    const saved = _savedFocus;
    if (saved && document.activeElement !== saved) {
      saved.focus();
    }
    _savedFocus = null;
  });

  function saveFocus() {
    if (document.activeElement instanceof HTMLElement) {
      _savedFocus = document.activeElement;
    }
  }

  onMount(() => {
    function handlePointer(event: PointerEvent) {
      if (resizing !== -1 && event.pointerId === resizingPointerId) {
        const cols = Math.min(
          Math.max(Math.floor((event.pageX - resizingOrigin[0]) / resizingCell[0]), TERM_MIN_COLS),
          TERM_MAX_COLS,
        );
        const rows = Math.min(
          Math.max(Math.floor((event.pageY - resizingOrigin[1]) / resizingCell[1]), TERM_MIN_ROWS),
          TERM_MAX_ROWS,
        );
        if (rows !== resizingSize.rows || cols !== resizingSize.cols) {
          resizingSize = { ...resizingSize, rows, cols };
          srocket?.send({ m: [resizing, resizingSize] });
        }
      }
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

  let focused = $state<number[]>([]);
  $effect(() => setFocus(focused));

  const setFocus = debounce((focused: number[]) => {
    srocket?.send({ f: focused[0] ?? null });
  }, 20);
</script>

<main
  class="p-8"
  class:cursor-nwse-resize={resizing !== -1}
  onwheel={(event) => event.preventDefault()}
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
      oncreate={handleCreate}
      onchat={() => {
        showChat = !showChat;
        newMessages = false;
      }}
      onsettings={() => (settingsOpen = true)}
      onnetworkInfo={() => (showNetworkInfo = !showNetworkInfo)}
      onlayoutChange={(mode) => handleLayoutChange(mode)}
    />

    {#if showNetworkInfo}
      <div class="absolute top-20 translate-x-[116.5px]">
        <NetworkInfo
          status={connected ? "connected" : exitReason ? "no-shell" : "no-server"}
          serverLatency={integerMedian(serverLatencies)}
          shellLatency={integerMedian(shellLatencies)}
        />
      </div>
    {/if}
  </div>

  {#if showChat}
    <div class="absolute flex flex-col justify-end inset-y-4 right-4 w-80 pointer-events-none z-10">
      <Chat
        {userId}
        messages={chatMessages}
        onchat={(text) => srocket?.send({ t: text })}
        onclose={() => (showChat = false)}
      />
    </div>
  {/if}

  <Settings
    open={settingsOpen}
    onclose={() => (settingsOpen = false)}
  />

  <ChooseName />

  <div
    class="absolute inset-0 -z-10"
    style:background-image="radial-gradient(#333 {zoom}px, transparent 0)"
    style:background-size="{24 * zoom}px {24 * zoom}px"
    style:background-position="{-zoom * center[0]}px {-zoom * center[1]}px"
  ></div>

  <div class="py-2">
    {#if exitReason !== null}
      <div class="text-red-400">{exitReason}</div>
    {:else if connected}
      <div class="flex items-center">
        <div class="text-green-400">You are connected!</div>
        {#if userId && hasWriteAccess === false}
          <div class="bg-yellow-900 text-yellow-200 px-1 py-0.5 rounded ml-3 inline-flex items-center gap-1">
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
            oncellsize={({ charWidth, rowHeight }) => {
              termCharWidths[id] = charWidth;
              termRowHeights[id] = rowHeight;
            }}
            ondata={(data) => hasWriteAccess && handleInput(id, data)}
            onclose={() => srocket?.send({ x: id })}
            onshrink={() => {
              if (!hasWriteAccess) return;
              const rows = Math.max(Math.min(ws.rows - 4, TERM_MAX_ROWS), TERM_MIN_ROWS);
              const cols = Math.max(Math.min(ws.cols - 10, TERM_MAX_COLS), TERM_MIN_COLS);
              if (rows !== ws.rows || cols !== ws.cols) {
                srocket?.send({ m: [id, { ...ws, rows, cols }] });
              }
            }}
            onexpand={() => {
              if (!hasWriteAccess) return;
              const rows = Math.min(ws.rows + 4, TERM_MAX_ROWS);
              const cols = Math.min(ws.cols + 10, TERM_MAX_COLS);
              srocket?.send({ m: [id, { ...ws, rows, cols }] });
            }}
            onbringToFront={() => {
              if (!hasWriteAccess) return;
              showNetworkInfo = false;
              srocket?.send({ m: [id, null] });
            }}
            onstartMove={(event) => {
              if (!hasWriteAccess) return;
              if (event.type === "pointerdown") {
                const [x, y] = normalizePosition(event);
                movingSize = ws;
                moving = id;
                movingPointerId = event.pointerId;
                movingOrigin = [x - movingSize.x, y - movingSize.y];
                movingIsDone = false;
              } else if (event.type === "pointermove" && moving === id && !movingIsDone) {
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
            onfocus={() => {
              if (!hasWriteAccess) return;
              focused = [...focused, id];
            }}
            onblur={() => {
              focused = focused.filter((i) => i !== id);
            }}
          />

          <div class="absolute bottom-2.5 right-2.5 pointer-events-none">
            <Avatars
              users={users.filter(([uid, user]) => uid !== userId && user.focus === id)}
            />
          </div>

          <div
            class="absolute w-5 h-5 -bottom-1 -right-1 cursor-nwse-resize"
            role="presentation"
            onpointerdown={(event) => {
              event.stopPropagation();
              if (!hasWriteAccess) return;
              const cw = termCharWidths[id];
              const rh = termRowHeights[id];
              if (cw > 0 && rh > 0) {
                resizing = id;
                resizingPointerId = event.pointerId;
                (event.currentTarget as HTMLElement).setPointerCapture(event.pointerId);
                resizingOrigin = [event.pageX - ws.cols * cw, event.pageY - ws.rows * rh];
                resizingCell = [cw, rh];
                resizingSize = ws;
              }
            }}
            onpointerup={(event) => {
              if (resizing === id && event.pointerId === resizingPointerId) {
                resizing = -1;
                resizingPointerId = -1;
                (event.currentTarget as HTMLElement).releasePointerCapture(event.pointerId);
              }
            }}
            onpointercancel={(event) => {
              if (resizing === id && event.pointerId === resizingPointerId) {
                resizing = -1;
                resizingPointerId = -1;
                (event.currentTarget as HTMLElement).releasePointerCapture(event.pointerId);
              }
            }}
          ></div>
        </div>
      {/each}
    {:else}
      <TabbedTerminal
        {shells}
        {activeTabId}
        {toolbarBottom}
        {connected}
        {writers}
        {termElements}
        {hasWriteAccess}
        onswitchTab={({ id }) => (activeTabId = id)}
        onnewTab={handleCreate}
        onsplitTab={handleSplitTab}
        oncloseTab={({ id }) => srocket?.send({ x: id })}
        onresize={handleTabResize}
        ondata={({ id, data }) => hasWriteAccess && handleInput(id, data)}
        onbringToFront={() => (showNetworkInfo = false)}
        onfocus={({ id }) => { if (hasWriteAccess) focused = [...focused, id]; }}
        onblur={({ id }) => { focused = focused.filter((i) => i !== id); }}
      />
    {/if}

    {#each users.filter(([uid, user]) => uid !== userId && user.cursor !== null) as [id, user] (id)}
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
