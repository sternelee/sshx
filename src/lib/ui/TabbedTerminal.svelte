<!-- @component Tabbed terminal window with tiling split panes (right/left/up/down). -->
<script lang="ts">
  import { fade } from "svelte/transition";
  import { untrack } from "svelte";
  import type { WsWinsize } from "$lib/protocol";
  import XTerm from "./XTerm.svelte";
  import CircleButtons from "./CircleButtons.svelte";
  import CircleButton from "./CircleButton.svelte";

  let {
    shells,
    activeTabId,
    toolbarBottom = 96,
    writers,
    termElements,
    hasWriteAccess,
    connected = false,
    onswitchTab,
    onnewTab,
    onsplitTab,
    oncloseTab,
    onresize,
    ondata,
    onbringToFront,
    onfocus,
    onblur,
  }: {
    /** Server-authoritative list of all shells. */
    shells: [number, WsWinsize][];
    /** Shell id currently visible. */
    activeTabId: number;
    /** Pixel distance from the top of the viewport where this overlay starts. */
    toolbarBottom?: number;
    /** Shared writers record from Session — XTerm binds into this object. */
    writers: Record<number, (data: string) => void>;
    /** Shared termElements record from Session. */
    termElements: Record<number, HTMLDivElement>;
    /** Whether the user has write access. */
    hasWriteAccess: boolean | undefined;
    /** Whether the WebSocket is currently connected. */
    connected?: boolean;
    onswitchTab?: (detail: { id: number }) => void;
    onnewTab?: () => void;
    onsplitTab?: (detail: {
      fromId: number;
      pos: "right" | "left" | "up" | "down";
    }) => void;
    oncloseTab?: (detail: { id: number }) => void;
    onresize?: (detail: { id: number; cols: number; rows: number }) => void;
    ondata?: (detail: { id: number; data: Uint8Array }) => void;
    onbringToFront?: () => void;
    onfocus?: (detail: { id: number }) => void;
    onblur?: (detail: { id: number }) => void;
  } = $props();

  const TERM_MIN_ROWS = 8;
  const TERM_MIN_COLS = 32;
  const TERM_MAX_ROWS = 200;
  const TERM_MAX_COLS = 400;
  const SPLITTER_PX = 4;
  const MIN_FRAC = 0.08;
  // .term-container chrome: wterm padding 12px×2 + border 1px×2 = 26px per axis
  const TERM_CHROME_PX = 26;

  // ---------------------------------------------------------------------------
  // Layout tree
  // ---------------------------------------------------------------------------
  type Leaf = { type: "leaf"; id: number };
  type Split = {
    type: "split";
    dir: "h" | "v";
    children: LayoutNode[];
    sizes: number[];
  };
  type LayoutNode = Leaf | Split;

  let groups = $state<LayoutNode[]>([]);
  let activeGroupIdx = $state(0);
  let activePaneId = $state(-1);
  let pendingSplit = $state<{
    fromId: number;
    pos: "right" | "left" | "up" | "down";
  } | null>(null);

  function collectIds(n: LayoutNode, out: Set<number>) {
    if (n.type === "leaf") out.add(n.id);
    else for (const c of n.children) collectIds(c, out);
  }

  function findGroupIdx(id: number): number {
    for (let i = 0; i < groups.length; i++) {
      const ids = new Set<number>();
      collectIds(groups[i], ids);
      if (ids.has(id)) return i;
    }
    return -1;
  }

  function removeMissing(n: LayoutNode, valid: Set<number>): LayoutNode | null {
    if (n.type === "leaf") return valid.has(n.id) ? n : null;
    const newChildren: LayoutNode[] = [];
    const newSizes: number[] = [];
    for (let i = 0; i < n.children.length; i++) {
      const c = removeMissing(n.children[i], valid);
      if (c !== null) {
        newChildren.push(c);
        newSizes.push(n.sizes[i]);
      }
    }
    if (newChildren.length === 0) return null;
    if (newChildren.length === 1) return newChildren[0];
    const sum = newSizes.reduce((a, b) => a + b, 0) || 1;
    return {
      type: "split",
      dir: n.dir,
      children: newChildren,
      sizes: newSizes.map((s) => s / sum),
    };
  }

  function insertSplit(
    n: LayoutNode,
    fromId: number,
    newId: number,
    pos: "right" | "left" | "up" | "down",
  ): LayoutNode {
    if (n.type === "leaf") {
      if (n.id !== fromId) return n;
      const dir: "h" | "v" = pos === "right" || pos === "left" ? "h" : "v";
      const before = pos === "left" || pos === "up";
      const newLeaf: Leaf = { type: "leaf", id: newId };
      const children: LayoutNode[] = before ? [newLeaf, n] : [n, newLeaf];
      return { type: "split", dir, children, sizes: [0.5, 0.5] };
    }
    const dirMatch =
      (n.dir === "h" && (pos === "right" || pos === "left")) ||
      (n.dir === "v" && (pos === "down" || pos === "up"));
    if (dirMatch) {
      const idx = n.children.findIndex(
        (c) => c.type === "leaf" && c.id === fromId,
      );
      if (idx >= 0) {
        const before = pos === "left" || pos === "up";
        const insertAt = before ? idx : idx + 1;
        const splitFrac = n.sizes[idx] / 2;
        const newChildren = [...n.children];
        const newSizes = [...n.sizes];
        newChildren.splice(insertAt, 0, { type: "leaf", id: newId });
        newSizes[idx] = splitFrac;
        newSizes.splice(insertAt, 0, splitFrac);
        const sum = newSizes.reduce((a, b) => a + b, 0) || 1;
        return {
          type: "split",
          dir: n.dir,
          children: newChildren,
          sizes: newSizes.map((s) => s / sum),
        };
      }
    }
    let changed = false;
    const newChildren = n.children.map((c) => {
      const updated = insertSplit(c, fromId, newId, pos);
      if (updated !== c) changed = true;
      return updated;
    });
    if (!changed) return n;
    return { type: "split", dir: n.dir, children: newChildren, sizes: n.sizes };
  }

  function syncGroups(shellList: [number, WsWinsize][]) {
    const validIds = new Set(shellList.map(([id]) => id));
    const pruned: LayoutNode[] = [];
    for (const g of groups) {
      const r = removeMissing(g, validIds);
      if (r !== null) pruned.push(r);
    }
    groups = pruned;

    const placed = new Set<number>();
    for (const g of groups) collectIds(g, placed);

    for (const [id] of shellList) {
      if (placed.has(id)) continue;
      if (pendingSplit && placed.has(pendingSplit.fromId)) {
        const gi = findGroupIdx(pendingSplit.fromId);
        if (gi >= 0) {
          groups[gi] = insertSplit(groups[gi], pendingSplit.fromId, id, pendingSplit.pos);
          activeGroupIdx = gi;
          activePaneId = id;
          pendingSplit = null;
          placed.add(id);
          continue;
        }
        pendingSplit = null;
      }
      groups = [...groups, { type: "leaf", id }];
      activeGroupIdx = groups.length - 1;
      activePaneId = id;
      placed.add(id);
    }

    groups = groups;
    if (activeGroupIdx >= groups.length) {
      activeGroupIdx = Math.max(0, groups.length - 1);
    }
  }

  // Sync on shells change — wrap in untrack so reads/writes inside
  // syncGroups (groups, pendingSplit, …) don't register as dependencies
  // of this effect and cause an infinite loop.
  $effect(() => {
    const currentShells = shells;
    untrack(() => syncGroups(currentShells));
  });

  // External activeTabId → align internal active group/pane
  $effect(() => {
    if (activeTabId && groups.length > 0) {
      const gi = findGroupIdx(activeTabId);
      if (gi >= 0) {
        activeGroupIdx = gi;
        activePaneId = activeTabId;
      }
    }
  });

  const activeGroupIds = $derived.by(() => {
    const s = new Set<number>();
    if (groups[activeGroupIdx]) collectIds(groups[activeGroupIdx], s);
    return s;
  });

  // Validate activePaneId is in active group
  $effect(() => {
    if (groups[activeGroupIdx] && !activeGroupIds.has(activePaneId)) {
      activePaneId = activeGroupIds.values().next().value ?? -1;
    }
  });

  // ---------------------------------------------------------------------------
  // Per-tab title tracking
  // ---------------------------------------------------------------------------
  let tabTitles = $state<Record<number, string>>({});

  $effect(() => {
    // Use untrack to read tabTitles so writes don't retrigger this effect.
    const current = untrack(() => tabTitles);
    for (const [id] of shells) {
      if (!(id in current)) tabTitles[id] = "Terminal";
    }
  });

  function groupTitle(g: LayoutNode | undefined): string {
    if (!g) return "Terminal";
    const ids = new Set<number>();
    collectIds(g, ids);
    const count = ids.size;
    const primary = ids.has(activePaneId) ? activePaneId : ids.values().next().value;
    const title = tabTitles[primary as number] ?? "Terminal";
    return count > 1 ? `${title} (${count})` : title;
  }

  // ---------------------------------------------------------------------------
  // Tab-bar scroll: keep active group visible
  // ---------------------------------------------------------------------------
  let tabListEl = $state<HTMLDivElement | undefined>(undefined);

  $effect(() => {
    activeGroupIdx; // track
    if (tabListEl) {
      const el = tabListEl.querySelector<HTMLElement>(`[data-tabidx="${activeGroupIdx}"]`);
      el?.scrollIntoView({ block: "nearest", inline: "nearest" });
    }
  });

  // ---------------------------------------------------------------------------
  // Refocus active pane on switch
  // ---------------------------------------------------------------------------
  $effect(() => {
    const id = activePaneId;
    if (id > 0) {
      requestAnimationFrame(() => {
        const el = termElements[id];
        if (!el) return;
        const focusable = el.querySelector<HTMLElement>('textarea, [tabindex="0"]');
        focusable?.focus();
      });
    }
  });

  // ---------------------------------------------------------------------------
  // Char & term-area dimensions
  // ---------------------------------------------------------------------------
  let charWidth = $state(0);
  let rowHeight = $state(0);
  let termAreaWidth = $state(0);
  let termAreaHeight = $state(0);

  function observeSize(el: HTMLDivElement) {
    const ro = new ResizeObserver(([entry]) => {
      termAreaWidth = Math.floor(entry.contentRect.width);
      termAreaHeight = Math.floor(entry.contentRect.height);
    });
    ro.observe(el);
    return { destroy: () => ro.disconnect() };
  }

  // ---------------------------------------------------------------------------
  // Pane geometry
  // ---------------------------------------------------------------------------
  type Rect = { x: number; y: number; w: number; h: number };
  type SplitterInfo = {
    key: string;
    dir: "h" | "v";
    path: number[];
    leftIdx: number;
    rect: Rect;
  };

  function computeLayout(root: LayoutNode, width: number, height: number) {
    const rects: Record<number, Rect> = {};
    const sps: SplitterInfo[] = [];
    walk(root, 0, 0, width, height, []);
    return { rects, splitters: sps };

    function walk(n: LayoutNode, x: number, y: number, w: number, h: number, path: number[]) {
      if (n.type === "leaf") { rects[n.id] = { x, y, w, h }; return; }
      const totalGap = SPLITTER_PX * (n.children.length - 1);
      if (n.dir === "h") {
        const usable = Math.max(0, w - totalGap);
        let cx = x;
        for (let i = 0; i < n.children.length; i++) {
          const cw = n.sizes[i] * usable;
          walk(n.children[i], cx, y, cw, h, [...path, i]);
          cx += cw;
          if (i < n.children.length - 1) {
            sps.push({ key: path.join(",") + ":" + i + "h", dir: "h", path, leftIdx: i, rect: { x: cx, y, w: SPLITTER_PX, h } });
            cx += SPLITTER_PX;
          }
        }
      } else {
        const usable = Math.max(0, h - totalGap);
        let cy = y;
        for (let i = 0; i < n.children.length; i++) {
          const ch = n.sizes[i] * usable;
          walk(n.children[i], x, cy, w, ch, [...path, i]);
          cy += ch;
          if (i < n.children.length - 1) {
            sps.push({ key: path.join(",") + ":" + i + "v", dir: "v", path, leftIdx: i, rect: { x, y: cy, w, h: SPLITTER_PX } });
            cy += SPLITTER_PX;
          }
        }
      }
    }
  }

  const layout = $derived.by(() => {
    if (groups[activeGroupIdx] && termAreaWidth > 0 && termAreaHeight > 0) {
      return computeLayout(groups[activeGroupIdx], termAreaWidth, termAreaHeight);
    }
    return { rects: {} as Record<number, Rect>, splitters: [] as SplitterInfo[] };
  });

  const paneRects = $derived(layout.rects);
  const splitters = $derived(layout.splitters);

  // ---------------------------------------------------------------------------
  // Per-pane cols/rows
  // ---------------------------------------------------------------------------
  let paneSizes = $state<Record<number, { cols: number; rows: number }>>({});

  function clamp(v: number, lo: number, hi: number) {
    return Math.max(lo, Math.min(hi, v));
  }

  $effect(() => {
    if (charWidth <= 0 || rowHeight <= 0) return;
    const next: Record<number, { cols: number; rows: number }> = {};
    // Read previous sizes without tracking so the write below doesn't loop.
    const prev = untrack(() => paneSizes);
    let changed = false;
    for (const idStr in paneRects) {
      const id = +idStr;
      const r = paneRects[id];
      const innerW = Math.max(0, r.w - TERM_CHROME_PX);
      const innerH = Math.max(0, r.h - TERM_CHROME_PX);
      const c = clamp(Math.floor(innerW / charWidth), TERM_MIN_COLS, TERM_MAX_COLS);
      const rr = clamp(Math.floor(innerH / rowHeight), TERM_MIN_ROWS, TERM_MAX_ROWS);
      next[id] = { cols: c, rows: rr };
      const p = prev[id];
      if (!p || p.cols !== c || p.rows !== rr) {
        changed = true;
        onresize?.({ id, cols: c, rows: rr });
      }
    }
    // Only reassign when something actually changed to avoid a reactive loop
    // caused by a new object reference triggering this effect again.
    if (changed || Object.keys(next).length !== Object.keys(prev).length) {
      paneSizes = next;
    }
  });

  // ---------------------------------------------------------------------------
  // Splitter drag
  // ---------------------------------------------------------------------------
  let drag = $state<{
    splitter: SplitterInfo;
    startPx: number;
    startSizes: number[];
    parentUsable: number;
    pointerId: number;
  } | null>(null);

  function getNodeAtPath(root: LayoutNode, path: number[]): LayoutNode {
    let n = root;
    for (const i of path) {
      if (n.type !== "split") return n;
      n = n.children[i];
    }
    return n;
  }

  function setNodeAtPath(root: LayoutNode, path: number[], updater: (n: Split) => Split): LayoutNode {
    if (path.length === 0) {
      if (root.type !== "split") return root;
      return updater(root);
    }
    if (root.type !== "split") return root;
    const [head, ...rest] = path;
    const newChildren = root.children.map((c, i) =>
      i === head ? setNodeAtPath(c, rest, updater) : c,
    );
    return { ...root, children: newChildren };
  }

  function onSplitterDown(e: PointerEvent, s: SplitterInfo) {
    if (!groups[activeGroupIdx]) return;
    const parent = getNodeAtPath(groups[activeGroupIdx], s.path);
    if (parent.type !== "split") return;
    const totalGap = SPLITTER_PX * (parent.children.length - 1);
    const usable = s.dir === "h"
      ? Math.max(1, termAreaWidth - totalGap)
      : Math.max(1, termAreaHeight - totalGap);
    drag = {
      splitter: s,
      startPx: s.dir === "h" ? e.clientX : e.clientY,
      startSizes: [...parent.sizes],
      parentUsable: usable,
      pointerId: e.pointerId,
    };
    (e.currentTarget as HTMLElement).setPointerCapture(e.pointerId);
    e.preventDefault();
    e.stopPropagation();
  }

  function onSplitterMove(e: PointerEvent) {
    if (!drag) return;
    const s = drag.splitter;
    const cur = s.dir === "h" ? e.clientX : e.clientY;
    const deltaFrac = (cur - drag.startPx) / drag.parentUsable;
    const i = s.leftIdx;
    const a = drag.startSizes[i];
    const b = drag.startSizes[i + 1];
    const sum = a + b;
    let newA = Math.max(MIN_FRAC, Math.min(sum - MIN_FRAC, a + deltaFrac));
    let newB = sum - newA;
    const newSizes = [...drag.startSizes];
    newSizes[i] = newA;
    newSizes[i + 1] = newB;
    groups = groups.map((g, gi) =>
      gi === activeGroupIdx
        ? setNodeAtPath(g, s.path, (sp) => ({ ...sp, sizes: newSizes }))
        : g,
    );
  }

  function onSplitterUp(e: PointerEvent) {
    if (!drag) return;
    try { (e.currentTarget as HTMLElement).releasePointerCapture(drag.pointerId); } catch { /* noop */ }
    drag = null;
  }

  // ---------------------------------------------------------------------------
  // Split actions
  // ---------------------------------------------------------------------------
  function requestSplit(pos: "right" | "left" | "up" | "down") {
    if (!hasWriteAccess || !connected || activePaneId < 0) return;
    pendingSplit = { fromId: activePaneId, pos };
    onsplitTab?.({ fromId: activePaneId, pos });
  }

  // ---------------------------------------------------------------------------
  // Yellow / green button resize
  // ---------------------------------------------------------------------------
  function adjustActive(dCols: number, dRows: number) {
    if (!hasWriteAccess) return;
    const cur = paneSizes[activePaneId];
    if (!cur) return;
    const newCols = clamp(cur.cols + dCols, TERM_MIN_COLS, TERM_MAX_COLS);
    const newRows = clamp(cur.rows + dRows, TERM_MIN_ROWS, TERM_MAX_ROWS);
    if (newCols !== cur.cols || newRows !== cur.rows) {
      paneSizes = { ...paneSizes, [activePaneId]: { cols: newCols, rows: newRows } };
      onresize?.({ id: activePaneId, cols: newCols, rows: newRows });
    }
  }
  const handleShrink = () => adjustActive(-10, -4);
  const handleExpand = () => adjustActive(10, 4);
</script>

<div
  class="tab-overlay"
  style:top="{toolbarBottom}px"
  transition:fade|local
  onmousedown={() => onbringToFront?.()}
  onpointerdown={(e) => e.stopPropagation()}
  role="presentation"
>
  <div class="tabbed-window">
    <!-- Tab bar -->
    <div class="tab-bar">
      <!-- Circle buttons -->
      <div class="flex-shrink-0 px-2 flex items-center">
        <CircleButtons>
          <CircleButton
            kind="red"
            onmousedown={(e) => {
              if (e.button !== 0) return;
              e.preventDefault();
              for (const [id] of shells) oncloseTab?.({ id });
            }}
          />
          <CircleButton
            kind="yellow"
            onmousedown={(e) => {
              if (e.button !== 0) return;
              e.preventDefault();
              handleShrink();
            }}
          />
          <CircleButton
            kind="green"
            onmousedown={(e) => {
              if (e.button !== 0) return;
              e.preventDefault();
              handleExpand();
            }}
          />
        </CircleButtons>
      </div>

      <div class="tab-divider"></div>

      <!-- Tab list -->
      <div class="tab-list" bind:this={tabListEl}>
        {#each groups as g, gi (gi + ":" + (g.type === "leaf" ? g.id : "s"))}
          {@const ids = (() => { const s = new Set<number>(); collectIds(g, s); return s; })()}
          <button
            class="tab-item"
            class:active={gi === activeGroupIdx}
            data-tabidx={gi}
            onmousedown={(e) => {
              if (e.button !== 0) return;
              e.preventDefault();
              activeGroupIdx = gi;
              const firstId = ids.has(activePaneId)
                ? activePaneId
                : (ids.values().next().value as number);
              activePaneId = firstId;
              onswitchTab?.({ id: firstId });
            }}
            title={groupTitle(g)}
          >
            <span class="tab-title">{groupTitle(g)}</span>
            <span
              class="tab-close"
              role="button"
              tabindex="-1"
              onmousedown={(e) => {
                e.stopPropagation();
                if (e.button !== 0) return;
                e.preventDefault();
                for (const id of ids) oncloseTab?.({ id });
              }}
            >×</span>
          </button>
        {/each}
      </div>

      <!-- Split buttons -->
      <div class="split-btns">
        {#each (["left", "up", "down", "right"] as const) as pos}
          {@const label = pos === "left" ? "⇤" : pos === "up" ? "⤒" : pos === "down" ? "⤓" : "⇥"}
          <button
            class="split-btn"
            disabled={!connected || !hasWriteAccess || activePaneId < 0}
            title="Split {pos.charAt(0).toUpperCase() + pos.slice(1)}"
            onmousedown={(e) => {
              if (e.button === 0) { e.preventDefault(); requestSplit(pos); }
            }}
          >{label}</button>
        {/each}
      </div>

      <!-- New tab button -->
      <button
        class="new-tab-btn"
        disabled={!connected || !hasWriteAccess}
        onmousedown={(e) => {
          if (e.button === 0 && connected && hasWriteAccess) {
            e.preventDefault();
            onnewTab?.();
          }
        }}
        title="New terminal"
      >＋</button>
    </div>

    <!-- Terminal content area -->
    <div class="term-area" use:observeSize>
      {#each shells as [id] (id)}
        {@const inActive = activeGroupIds.has(id)}
        {@const r = paneRects[id]}
        {@const sz = paneSizes[id] ?? { cols: 80, rows: 24 }}
        <div
          class="pane-wrapper"
          class:visible={inActive && r !== undefined}
          class:active-pane={inActive && id === activePaneId}
          style:left="{r?.x ?? 0}px"
          style:top="{r?.y ?? 0}px"
          style:width="{r?.w ?? 0}px"
          style:height="{r?.h ?? 0}px"
          role="presentation"
          onmousedown={() => {
            if (inActive && id !== activePaneId) {
              activePaneId = id;
              onswitchTab?.({ id });
            }
          }}
        >
          <XTerm
            rows={sz.rows}
            cols={sz.cols}
            showTitleBar={false}
            visible={inActive}
            onregisterWrite={(fn) => { writers[id] = fn; }}
            onregisterTermEl={(el) => { termElements[id] = el; }}
            oncellsize={({ charWidth: cw, rowHeight: rh }) => {
              charWidth = cw;
              rowHeight = rh;
            }}
            ontitle={(t) => { tabTitles[id] = t; tabTitles = { ...tabTitles }; }}
            ondata={(data) => hasWriteAccess && ondata?.({ id, data })}
            onclose={() => oncloseTab?.({ id })}
            onshrink={handleShrink}
            onexpand={handleExpand}
            onbringToFront={() => onbringToFront?.()}
            onfocus={() => onfocus?.({ id })}
            onblur={() => onblur?.({ id })}
          />
        </div>
      {/each}

      <!-- Splitter handles -->
      {#each splitters as s (s.key)}
        <div
          class="splitter"
          class:vertical={s.dir === "h"}
          class:horizontal={s.dir === "v"}
          style:left="{s.rect.x}px"
          style:top="{s.rect.y}px"
          style:width="{s.rect.w}px"
          style:height="{s.rect.h}px"
          role="separator"
          tabindex="-1"
          onpointerdown={(e) => onSplitterDown(e, s)}
          onpointermove={onSplitterMove}
          onpointerup={onSplitterUp}
          onpointercancel={onSplitterUp}
        ></div>
      {/each}

      {#if shells.length === 0}
        <div class="empty-state">
          <p>No terminals open.</p>
          <button
            disabled={!connected || !hasWriteAccess}
            onmousedown={(e) => {
              if (e.button === 0 && connected && hasWriteAccess) {
                e.preventDefault();
                onnewTab?.();
              }
            }}
          >New Terminal</button>
        </div>
      {/if}
    </div>
  </div>
</div>

<style>
  .tab-overlay {
    position: fixed;
    left: 50%;
    transform: translateX(-50%);
    width: 96%;
    bottom: 0;
    display: flex;
    flex-direction: column;
    z-index: 5;
  }

  .tabbed-window {
    flex: 1;
    min-height: 0;
    display: flex;
    flex-direction: column;
    background: #09090b;
    border: 1px solid rgb(63, 63, 70);
    border-bottom: none;
    border-radius: 0.5rem 0.5rem 0 0;
    overflow: hidden;
  }

  .tab-bar {
    display: flex;
    align-items: center;
    background: rgb(39, 39, 42);
    border-bottom: 1px solid rgb(63, 63, 70);
    border-radius: 0.5rem 0.5rem 0 0;
    user-select: none;
    min-height: 36px;
    flex-shrink: 0;
    overflow: hidden;
  }

  .tab-divider {
    width: 1px;
    height: 16px;
    background: rgb(63, 63, 70);
    flex-shrink: 0;
    margin: 0 2px;
  }

  .tab-list {
    display: flex;
    align-items: center;
    flex: 1;
    min-width: 0;
    padding: 4px 2px;
    overflow: hidden;
  }

  .tab-item {
    display: flex;
    align-items: center;
    gap: 4px;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 12px;
    white-space: nowrap;
    flex: 1 1 0;
    min-width: 0;
    overflow: hidden;
    color: rgb(113, 113, 122);
    background: none;
    border: none;
    cursor: pointer;
    transition: background-color 150ms;
  }

  .tab-item:hover,
  .tab-item.active {
    background: rgb(63, 63, 70);
    color: rgb(228, 228, 231);
  }

  .tab-title {
    flex: 1;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .tab-close {
    color: rgb(113, 113, 122);
    font-size: 14px;
    line-height: 1;
    flex-shrink: 0;
    opacity: 0.6;
    transition: opacity 150ms;
    cursor: pointer;
  }

  .tab-close:hover {
    opacity: 1;
    color: rgb(239, 68, 68);
  }

  .split-btns {
    display: flex;
    align-items: center;
    gap: 2px;
    flex-shrink: 0;
    padding: 0 4px;
    border-left: 1px solid rgb(63, 63, 70);
    margin-left: 2px;
  }

  .split-btn {
    background: none;
    border: none;
    color: rgb(113, 113, 122);
    font-size: 14px;
    line-height: 1;
    padding: 4px 6px;
    border-radius: 4px;
    cursor: pointer;
    transition: color 150ms, background-color 150ms;
  }

  .split-btn:hover:not(:disabled) {
    color: rgb(228, 228, 231);
    background: rgb(63, 63, 70);
  }

  .split-btn:disabled {
    opacity: 0.4;
    cursor: default;
  }

  .new-tab-btn {
    flex-shrink: 0;
    padding: 2px 10px;
    color: rgb(113, 113, 122);
    font-size: 16px;
    background: none;
    border: none;
    cursor: pointer;
    transition: color 150ms;
    line-height: 1;
  }

  .new-tab-btn:hover:not(:disabled) { color: rgb(228, 228, 231); }
  .new-tab-btn:disabled { opacity: 0.5; cursor: default; }

  .term-area {
    flex: 1;
    min-height: 0;
    position: relative;
    overflow: hidden;
  }

  .pane-wrapper {
    position: absolute;
    overflow: hidden;
    display: none;
  }

  .pane-wrapper.visible { display: block; }

  .pane-wrapper.active-pane {
    outline: 1px solid rgb(99, 102, 241);
    outline-offset: -1px;
  }

  .splitter {
    position: absolute;
    background: transparent;
    z-index: 10;
  }

  .splitter.vertical { cursor: col-resize; }
  .splitter.horizontal { cursor: row-resize; }
  .splitter:hover { background: rgba(99, 102, 241, 0.5); }

  .empty-state {
    padding: 2rem;
    text-align: center;
    color: rgb(113, 113, 122);
    font-size: 14px;
  }

  .empty-state button {
    margin-top: 0.5rem;
    padding: 4px 12px;
    background: rgb(63, 63, 70);
    border: none;
    border-radius: 4px;
    color: rgb(228, 228, 231);
    cursor: pointer;
    font-size: 13px;
  }
</style>
