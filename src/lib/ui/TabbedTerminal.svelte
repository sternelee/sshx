<!-- @component Tabbed terminal window with tiling split panes (right/left/up/down). -->
<script lang="ts">
  import { createEventDispatcher } from "svelte";
  import { fade } from "svelte/transition";
  import type { WsWinsize } from "$lib/protocol";
  import XTerm from "./XTerm.svelte";
  import CircleButtons from "./CircleButtons.svelte";
  import CircleButton from "./CircleButton.svelte";

  /** Server-authoritative list of all shells. */
  export let shells: [number, WsWinsize][];
  /** Shell id currently visible. */
  export let activeTabId: number;
  /**
   * Pixel distance from the top of the viewport where this overlay starts
   * (i.e. the bottom edge of the toolbar + gap). Passed from Session.
   */
  export let toolbarBottom: number = 96;
  /** Shared writers record from Session — XTerm binds into this object. */
  export let writers: Record<number, (data: string) => void>;
  /** Shared termElements record from Session. */
  export let termElements: Record<number, HTMLDivElement>;
  /** Whether the user has write access. */
  export let hasWriteAccess: boolean | undefined;
  /** Whether the WebSocket is currently connected. */
  export let connected: boolean = false;

  const TERM_MIN_ROWS = 8;
  const TERM_MIN_COLS = 32;
  const TERM_MAX_ROWS = 200;
  const TERM_MAX_COLS = 400;
  const SPLITTER_PX = 4;
  const MIN_FRAC = 0.08;
  // .term-container chrome around the wterm grid:
  //   - .wterm has padding: 12px on all sides (24px per axis)
  //   - .term-container has a 1px border on all sides (2px per axis)
  // The rendered terminal occupies `cols*charWidth + 26` by
  // `rows*rowHeight + 26` px (see XTerm.updateSize). We must subtract this
  // chrome from the available pane rect when computing cols/rows, otherwise
  // the rendered terminal overflows the pane-wrapper and the right/bottom
  // edges get clipped — most visible after Split Left/Right/Up/Down.
  const TERM_CHROME_PX = 26;

  const dispatch = createEventDispatcher<{
    /** User switched to a different tab/pane. */
    switchTab: { id: number };
    /** User clicked + to create a new terminal (no split). */
    newTab: void;
    /** User requested a split — Session should create a new shell, which
     *  this component will then place next to `fromId` in the layout tree. */
    splitTab: { fromId: number; pos: "right" | "left" | "up" | "down" };
    /** User clicked × on a tab/pane (close that shell). */
    closeTab: { id: number };
    /** A pane resized — used to sync that PTY's dimensions. */
    resize: { id: number; cols: number; rows: number };
    /** Keystroke from a terminal. */
    data: { id: number; data: Uint8Array };
    /** mousedown on window — used to close overlay panels in Session. */
    bringToFront: void;
    /** Active terminal gained focus. */
    focus: { id: number };
    /** Active terminal lost focus. */
    blur: { id: number };
  }>();

  // ---------------------------------------------------------------------------
  // Layout tree — each top-level node is a "tab"; leaves are shell ids.
  // ---------------------------------------------------------------------------
  type Leaf = { type: "leaf"; id: number };
  type Split = {
    type: "split";
    dir: "h" | "v";
    children: LayoutNode[];
    sizes: number[]; // weights, normalized to sum=1
  };
  type LayoutNode = Leaf | Split;

  let groups: LayoutNode[] = [];
  let activeGroupIdx = 0;
  let activePaneId = -1;
  /** When set, the next new shell will be inserted as a sibling of fromId. */
  let pendingSplit:
    | { fromId: number; pos: "right" | "left" | "up" | "down" }
    | null = null;

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

  function removeMissing(
    n: LayoutNode,
    valid: Set<number>,
  ): LayoutNode | null {
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

  /** Insert `newId` as sibling of `fromId` according to `pos`. */
  function insertSplit(
    n: LayoutNode,
    fromId: number,
    newId: number,
    pos: "right" | "left" | "up" | "down",
  ): LayoutNode {
    if (n.type === "leaf") {
      if (n.id !== fromId) return n;
      const dir: "h" | "v" =
        pos === "right" || pos === "left" ? "h" : "v";
      const before = pos === "left" || pos === "up";
      const newLeaf: Leaf = { type: "leaf", id: newId };
      const children: LayoutNode[] = before ? [newLeaf, n] : [n, newLeaf];
      return { type: "split", dir, children, sizes: [0.5, 0.5] };
    }

    // Try to insert as sibling within this split if direction matches and
    // fromId is a direct leaf child.
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

    // Recurse into children.
    let changed = false;
    const newChildren = n.children.map((c) => {
      const updated = insertSplit(c, fromId, newId, pos);
      if (updated !== c) changed = true;
      return updated;
    });
    if (!changed) return n;
    return { type: "split", dir: n.dir, children: newChildren, sizes: n.sizes };
  }

  /** Sync the layout tree to the authoritative shells list. */
  function syncGroups(shellList: [number, WsWinsize][]) {
    const validIds = new Set(shellList.map(([id]) => id));

    // Remove leaves no longer present.
    const pruned: LayoutNode[] = [];
    for (const g of groups) {
      const r = removeMissing(g, validIds);
      if (r !== null) pruned.push(r);
    }
    groups = pruned;

    // Track which ids are already placed.
    const placed = new Set<number>();
    for (const g of groups) collectIds(g, placed);

    // Add new shells.
    for (const [id] of shellList) {
      if (placed.has(id)) continue;
      if (pendingSplit && placed.has(pendingSplit.fromId)) {
        const gi = findGroupIdx(pendingSplit.fromId);
        if (gi >= 0) {
          groups[gi] = insertSplit(
            groups[gi],
            pendingSplit.fromId,
            id,
            pendingSplit.pos,
          );
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

    // Force reactivity.
    groups = groups;

    // Clamp activeGroupIdx.
    if (activeGroupIdx >= groups.length) {
      activeGroupIdx = Math.max(0, groups.length - 1);
    }
  }

  $: syncGroups(shells);

  // External activeTabId → align internal active group/pane.
  $: if (activeTabId && groups.length > 0) {
    const gi = findGroupIdx(activeTabId);
    if (gi >= 0) {
      activeGroupIdx = gi;
      activePaneId = activeTabId;
    }
  }

  // Compute set of ids visible in the active group.
  let activeGroupIds = new Set<number>();
  $: {
    activeGroupIds = new Set<number>();
    if (groups[activeGroupIdx]) collectIds(groups[activeGroupIdx], activeGroupIds);
  }

  // Validate activePaneId is in active group.
  $: if (groups[activeGroupIdx] && !activeGroupIds.has(activePaneId)) {
    activePaneId = activeGroupIds.values().next().value ?? -1;
  }

  // ---------------------------------------------------------------------------
  // Per-tab title tracking
  // ---------------------------------------------------------------------------
  let tabTitles: Record<number, string> = {};
  $: for (const [id] of shells) {
    if (!(id in tabTitles)) tabTitles[id] = "Terminal";
  }

  function groupTitle(g: LayoutNode | undefined): string {
    if (!g) return "Terminal";
    const ids = new Set<number>();
    collectIds(g, ids);
    const count = ids.size;
    const primary =
      ids.has(activePaneId) ? activePaneId : ids.values().next().value;
    const title = tabTitles[primary as number] ?? "Terminal";
    return count > 1 ? `${title} (${count})` : title;
  }

  // ---------------------------------------------------------------------------
  // Tab-bar scroll: keep active group visible.
  // ---------------------------------------------------------------------------
  let tabListEl: HTMLDivElement;
  $: if (activeGroupIdx >= 0 && tabListEl) {
    const el = tabListEl.querySelector<HTMLElement>(
      `[data-tabidx="${activeGroupIdx}"]`,
    );
    el?.scrollIntoView({ block: "nearest", inline: "nearest" });
  }

  // ---------------------------------------------------------------------------
  // Refocus active pane on switch.
  // ---------------------------------------------------------------------------
  $: if (activePaneId > 0) {
    requestAnimationFrame(() => {
      const el = termElements[activePaneId];
      if (!el) return;
      const focusable = el.querySelector<HTMLElement>(
        'textarea, [tabindex="0"]',
      );
      focusable?.focus();
    });
  }

  // ---------------------------------------------------------------------------
  // Char & term-area dimensions.
  // ---------------------------------------------------------------------------
  let charWidth = 0;
  let rowHeight = 0;
  let termAreaWidth = 0;
  let termAreaHeight = 0;

  function observeSize(el: HTMLDivElement) {
    const ro = new ResizeObserver(([entry]) => {
      termAreaWidth = Math.floor(entry.contentRect.width);
      termAreaHeight = Math.floor(entry.contentRect.height);
    });
    ro.observe(el);
    return { destroy: () => ro.disconnect() };
  }

  // ---------------------------------------------------------------------------
  // Pane geometry — compute rects for each leaf in the active group.
  // ---------------------------------------------------------------------------
  type Rect = { x: number; y: number; w: number; h: number };
  type SplitterInfo = {
    key: string;
    dir: "h" | "v"; // parent direction; "h" → vertical splitter line
    path: number[]; // path to parent split node from active group root
    leftIdx: number; // index of child to the left/top of the splitter
    rect: Rect;
  };

  let paneRects: Record<number, Rect> = {};
  let splitters: SplitterInfo[] = [];

  function computeLayout(
    root: LayoutNode,
    width: number,
    height: number,
  ): { rects: Record<number, Rect>; splitters: SplitterInfo[] } {
    const rects: Record<number, Rect> = {};
    const sps: SplitterInfo[] = [];
    walk(root, 0, 0, width, height, []);
    return { rects, splitters: sps };

    function walk(
      n: LayoutNode,
      x: number,
      y: number,
      w: number,
      h: number,
      path: number[],
    ) {
      if (n.type === "leaf") {
        rects[n.id] = { x, y, w, h };
        return;
      }
      const nChildren = n.children.length;
      const totalGap = SPLITTER_PX * (nChildren - 1);
      if (n.dir === "h") {
        const usable = Math.max(0, w - totalGap);
        let cx = x;
        for (let i = 0; i < nChildren; i++) {
          const cw = n.sizes[i] * usable;
          walk(n.children[i], cx, y, cw, h, [...path, i]);
          cx += cw;
          if (i < nChildren - 1) {
            sps.push({
              key: path.join(",") + ":" + i + "h",
              dir: "h",
              path,
              leftIdx: i,
              rect: { x: cx, y, w: SPLITTER_PX, h },
            });
            cx += SPLITTER_PX;
          }
        }
      } else {
        const usable = Math.max(0, h - totalGap);
        let cy = y;
        for (let i = 0; i < nChildren; i++) {
          const ch = n.sizes[i] * usable;
          walk(n.children[i], x, cy, w, ch, [...path, i]);
          cy += ch;
          if (i < nChildren - 1) {
            sps.push({
              key: path.join(",") + ":" + i + "v",
              dir: "v",
              path,
              leftIdx: i,
              rect: { x, y: cy, w, h: SPLITTER_PX },
            });
            cy += SPLITTER_PX;
          }
        }
      }
    }
  }

  $: if (groups[activeGroupIdx] && termAreaWidth > 0 && termAreaHeight > 0) {
    const out = computeLayout(
      groups[activeGroupIdx],
      termAreaWidth,
      termAreaHeight,
    );
    paneRects = out.rects;
    splitters = out.splitters;
  } else {
    paneRects = {};
    splitters = [];
  }

  // ---------------------------------------------------------------------------
  // Per-pane cols/rows — dispatch resize per-id when changed.
  // ---------------------------------------------------------------------------
  let paneSizes: Record<number, { cols: number; rows: number }> = {};
  function clamp(v: number, lo: number, hi: number) {
    return Math.max(lo, Math.min(hi, v));
  }

  $: if (charWidth > 0 && rowHeight > 0) {
    const next: Record<number, { cols: number; rows: number }> = {};
    for (const idStr in paneRects) {
      const id = +idStr;
      const r = paneRects[id];
      const innerW = Math.max(0, r.w - TERM_CHROME_PX);
      const innerH = Math.max(0, r.h - TERM_CHROME_PX);
      const c = clamp(
        Math.floor(innerW / charWidth),
        TERM_MIN_COLS,
        TERM_MAX_COLS,
      );
      const rr = clamp(
        Math.floor(innerH / rowHeight),
        TERM_MIN_ROWS,
        TERM_MAX_ROWS,
      );
      next[id] = { cols: c, rows: rr };
      const prev = paneSizes[id];
      if (!prev || prev.cols !== c || prev.rows !== rr) {
        dispatch("resize", { id, cols: c, rows: rr });
      }
    }
    paneSizes = next;
  }

  // ---------------------------------------------------------------------------
  // Splitter drag.
  // ---------------------------------------------------------------------------
  let drag: {
    splitter: SplitterInfo;
    startPx: number; // start client x or y
    startSizes: number[];
    parentUsable: number; // usable px in the parent split (excluding gaps)
    pointerId: number;
  } | null = null;

  function getNodeAtPath(root: LayoutNode, path: number[]): LayoutNode {
    let n = root;
    for (const i of path) {
      if (n.type !== "split") return n;
      n = n.children[i];
    }
    return n;
  }

  function setNodeAtPath(
    root: LayoutNode,
    path: number[],
    updater: (n: Split) => Split,
  ): LayoutNode {
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
    const usable =
      s.dir === "h"
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
    const deltaPx = cur - drag.startPx;
    const deltaFrac = deltaPx / drag.parentUsable;
    const i = s.leftIdx;
    const a = drag.startSizes[i];
    const b = drag.startSizes[i + 1];
    const sum = a + b;
    let newA = a + deltaFrac;
    let newB = b - deltaFrac;
    if (newA < MIN_FRAC) {
      newA = MIN_FRAC;
      newB = sum - MIN_FRAC;
    }
    if (newB < MIN_FRAC) {
      newB = MIN_FRAC;
      newA = sum - MIN_FRAC;
    }
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
    try {
      (e.currentTarget as HTMLElement).releasePointerCapture(drag.pointerId);
    } catch {
      /* noop */
    }
    drag = null;
  }

  // ---------------------------------------------------------------------------
  // Split actions.
  // ---------------------------------------------------------------------------
  function requestSplit(pos: "right" | "left" | "up" | "down") {
    if (!hasWriteAccess || !connected) return;
    if (activePaneId < 0) return;
    pendingSplit = { fromId: activePaneId, pos };
    dispatch("splitTab", { fromId: activePaneId, pos });
  }

  // ---------------------------------------------------------------------------
  // Active pane chrome resize (yellow/green buttons).
  // ---------------------------------------------------------------------------
  function adjustActive(dCols: number, dRows: number) {
    if (!hasWriteAccess) return;
    const cur = paneSizes[activePaneId];
    if (!cur) return;
    const newCols = clamp(cur.cols + dCols, TERM_MIN_COLS, TERM_MAX_COLS);
    const newRows = clamp(cur.rows + dRows, TERM_MIN_ROWS, TERM_MAX_ROWS);
    if (newCols !== cur.cols || newRows !== cur.rows) {
      paneSizes = {
        ...paneSizes,
        [activePaneId]: { cols: newCols, rows: newRows },
      };
      dispatch("resize", { id: activePaneId, cols: newCols, rows: newRows });
    }
  }
  const handleShrink = () => adjustActive(-10, -4);
  const handleExpand = () => adjustActive(10, 4);
</script>

<!--
  Fixed overlay that fills the viewport from the bottom of the toolbar to the
  bottom of the screen.
-->
<div
  class="tab-overlay"
  style:top="{toolbarBottom}px"
  transition:fade|local
  on:mousedown={() => dispatch("bringToFront")}
  on:pointerdown={(e) => e.stopPropagation()}
>
  <div class="tabbed-window">
    <!-- Tab bar -->
    <div class="tab-bar">
      <!-- Circle buttons -->
      <div class="flex-shrink-0 px-2 flex items-center" data-circlebtn>
        <CircleButtons>
          <CircleButton
            kind="red"
            on:mousedown={(e) => {
              if (e.button !== 0) return;
              e.preventDefault();
              for (const [id] of shells) dispatch("closeTab", { id });
            }}
          />
          <CircleButton
            kind="yellow"
            on:mousedown={(e) => {
              if (e.button !== 0) return;
              e.preventDefault();
              handleShrink();
            }}
          />
          <CircleButton
            kind="green"
            on:mousedown={(e) => {
              if (e.button !== 0) return;
              e.preventDefault();
              handleExpand();
            }}
          />
        </CircleButtons>
      </div>

      <!-- Divider -->
      <div class="tab-divider"></div>

      <!-- Tab list (one entry per group) -->
      <div class="tab-list" bind:this={tabListEl}>
        {#each groups as g, gi (gi + ":" + (g.type === "leaf" ? g.id : "s"))}
          {@const ids = (() => {
            const s = new Set<number>();
            collectIds(g, s);
            return s;
          })()}
          <button
            class="tab-item"
            class:active={gi === activeGroupIdx}
            data-tabidx={gi}
            on:mousedown={(e) => {
              if (e.button !== 0) return;
              e.preventDefault();
              activeGroupIdx = gi;
              const firstId =
                ids.has(activePaneId)
                  ? activePaneId
                  : (ids.values().next().value as number);
              activePaneId = firstId;
              dispatch("switchTab", { id: firstId });
            }}
            title={groupTitle(g)}
          >
            <span class="tab-title">{groupTitle(g)}</span>
            <span
              class="tab-close"
              on:mousedown|stopPropagation={(e) => {
                if (e.button !== 0) return;
                e.preventDefault();
                for (const id of ids) dispatch("closeTab", { id });
              }}
            >×</span>
          </button>
        {/each}
      </div>

      <!-- Split buttons -->
      <div class="split-btns" data-splitbtn>
        <button
          class="split-btn"
          disabled={!connected || !hasWriteAccess || activePaneId < 0}
          title="Split Left"
          on:mousedown={(e) => {
            if (e.button === 0) {
              e.preventDefault();
              requestSplit("left");
            }
          }}
        >⇤</button>
        <button
          class="split-btn"
          disabled={!connected || !hasWriteAccess || activePaneId < 0}
          title="Split Up"
          on:mousedown={(e) => {
            if (e.button === 0) {
              e.preventDefault();
              requestSplit("up");
            }
          }}
        >⤒</button>
        <button
          class="split-btn"
          disabled={!connected || !hasWriteAccess || activePaneId < 0}
          title="Split Down"
          on:mousedown={(e) => {
            if (e.button === 0) {
              e.preventDefault();
              requestSplit("down");
            }
          }}
        >⤓</button>
        <button
          class="split-btn"
          disabled={!connected || !hasWriteAccess || activePaneId < 0}
          title="Split Right"
          on:mousedown={(e) => {
            if (e.button === 0) {
              e.preventDefault();
              requestSplit("right");
            }
          }}
        >⇥</button>
      </div>

      <!-- New tab button -->
      <button
        class="new-tab-btn"
        data-newbtn
        disabled={!connected || !hasWriteAccess}
        on:mousedown={(e) => {
          if (e.button === 0 && connected && hasWriteAccess) {
            e.preventDefault();
            dispatch("newTab");
          }
        }}
        title="New terminal"
      >＋</button>
    </div>

    <!-- Terminal content area: panes positioned absolutely from layout tree -->
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
          on:mousedown={() => {
            if (inActive && id !== activePaneId) {
              activePaneId = id;
              dispatch("switchTab", { id });
            }
          }}
        >
          <XTerm
            rows={sz.rows}
            cols={sz.cols}
            showTitleBar={false}
            visible={inActive}
            bind:write={writers[id]}
            bind:termEl={termElements[id]}
            on:cellsize={({ detail }) => {
              charWidth = detail.charWidth;
              rowHeight = detail.rowHeight;
            }}
            on:title={({ detail }) => {
              tabTitles[id] = detail;
              tabTitles = tabTitles;
            }}
            on:data={({ detail: data }) =>
              hasWriteAccess && dispatch("data", { id, data })}
            on:close={() => dispatch("closeTab", { id })}
            on:shrink={handleShrink}
            on:expand={handleExpand}
            on:bringToFront={() => dispatch("bringToFront")}
            on:focus={() => dispatch("focus", { id })}
            on:blur={() => dispatch("blur", { id })}
          />
        </div>
      {/each}

      <!-- Splitter handles for the active group -->
      {#each splitters as s (s.key)}
        <div
          class="splitter"
          class:vertical={s.dir === "h"}
          class:horizontal={s.dir === "v"}
          style:left="{s.rect.x}px"
          style:top="{s.rect.y}px"
          style:width="{s.rect.w}px"
          style:height="{s.rect.h}px"
          on:pointerdown={(e) => onSplitterDown(e, s)}
          on:pointermove={onSplitterMove}
          on:pointerup={onSplitterUp}
          on:pointercancel={onSplitterUp}
        ></div>
      {/each}

      <!-- Empty state when no shells -->
      {#if shells.length === 0}
        <div class="empty-state">
          <p>No terminals open.</p>
          <button
            disabled={!connected || !hasWriteAccess}
            on:mousedown={(e) => {
              if (e.button === 0 && connected && hasWriteAccess) {
                e.preventDefault();
                dispatch("newTab");
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

  .new-tab-btn:hover:not(:disabled) {
    color: rgb(228, 228, 231);
  }

  .new-tab-btn:disabled {
    opacity: 0.5;
    cursor: default;
  }

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

  .pane-wrapper.visible {
    display: block;
  }

  .pane-wrapper.active-pane {
    outline: 1px solid rgb(99, 102, 241);
    outline-offset: -1px;
  }

  .splitter {
    position: absolute;
    background: transparent;
    z-index: 10;
  }

  .splitter.vertical {
    cursor: col-resize;
  }

  .splitter.horizontal {
    cursor: row-resize;
  }

  .splitter:hover {
    background: rgba(99, 102, 241, 0.5);
  }

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
