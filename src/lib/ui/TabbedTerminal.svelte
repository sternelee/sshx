<!-- @component Tabbed terminal window: all shells in one draggable window -->
<script lang="ts">
  import { createEventDispatcher } from "svelte";
  import { fade } from "svelte/transition";
  import type { WsWinsize } from "$lib/protocol";
  import { slide } from "$lib/action/slide";
  import XTerm from "./XTerm.svelte";
  import CircleButtons from "./CircleButtons.svelte";
  import CircleButton from "./CircleButton.svelte";

  /** Server-authoritative list of all shells. */
  export let shells: [number, WsWinsize][];
  /** Shell id currently visible. */
  export let activeTabId: number;
  /** Canvas grid position X of this window. */
  export let x: number;
  /** Canvas grid position Y of this window. */
  export let y: number;
  /** Shared cols for all tabs. */
  export let cols: number;
  /** Shared rows for all tabs. */
  export let rows: number;
  /** Shared writers record from Session — XTerm binds into this object. */
  export let writers: Record<number, (data: string) => void>;
  /** Shared termElements record from Session. */
  export let termElements: Record<number, HTMLDivElement>;
  /** Canvas center and zoom, forwarded from Session for the slide action. */
  export let center: number[];
  export let zoom: number;
  /** Whether the user has write access. */
  export let hasWriteAccess: boolean | undefined;

  const TERM_MIN_ROWS = 8;
  const TERM_MIN_COLS = 32;
  const TERM_MAX_ROWS = 200;
  const TERM_MAX_COLS = 400;

  const dispatch = createEventDispatcher<{
    /** User switched to a different tab. */
    switchTab: { id: number };
    /** User clicked + to create a new terminal. */
    newTab: void;
    /** User clicked × on a tab (close that shell). */
    closeTab: { id: number };
    /** Window was dragged to a new canvas position. */
    move: { x: number; y: number };
    /** Window was resized (cols/rows). */
    resize: { cols: number; rows: number };
    /** Keystroke from the active terminal. */
    data: { id: number; data: Uint8Array };
    /** mousedown on window — bring to front. */
    bringToFront: void;
    /** Active terminal gained focus. */
    focus: { id: number };
    /** Active terminal lost focus. */
    blur: { id: number };
  }>();

  // Per-tab title tracking (updated from XTerm title events)
  let tabTitles: Record<number, string> = {};

  $: for (const [id] of shells) {
    if (!(id in tabTitles)) tabTitles[id] = "Terminal";
  }

  // Tab scroll — keep active tab visible
  let tabListEl: HTMLDivElement;

  $: if (activeTabId && tabListEl) {
    const activeEl = tabListEl.querySelector<HTMLElement>(
      `[data-tabid="${activeTabId}"]`,
    );
    activeEl?.scrollIntoView({ block: "nearest", inline: "nearest" });
  }

  // Drag state
  let isDragging = false;
  let dragPointerId = -1;
  let dragOriginPageX = 0;
  let dragOriginPageY = 0;
  let dragStartX = 0;
  let dragStartY = 0;

  function handleTabBarPointerDown(event: PointerEvent) {
    if (event.button !== 0) return;
    if (!hasWriteAccess) return;
    const target = event.target as HTMLElement;
    // Only drag on the bar background — ignore clicks on tab items, +, circle buttons
    if (
      target.closest("[data-tabitem]") ||
      target.closest("[data-newbtn]") ||
      target.closest("[data-circlebtn]")
    )
      return;
    isDragging = true;
    dragPointerId = event.pointerId;
    (event.currentTarget as HTMLElement).setPointerCapture(event.pointerId);
    dragOriginPageX = event.pageX;
    dragOriginPageY = event.pageY;
    dragStartX = x;
    dragStartY = y;
  }

  function handleTabBarPointerMove(event: PointerEvent) {
    if (!isDragging || event.pointerId !== dragPointerId) return;
    const dx = (event.pageX - dragOriginPageX) / zoom;
    const dy = (event.pageY - dragOriginPageY) / zoom;
    dispatch("move", {
      x: Math.round(dragStartX + dx),
      y: Math.round(dragStartY + dy),
    });
  }

  function handleTabBarPointerUp(event: PointerEvent) {
    if (!isDragging || event.pointerId !== dragPointerId) return;
    isDragging = false;
    dragPointerId = -1;
    (event.currentTarget as HTMLElement).releasePointerCapture(event.pointerId);
    const dx = (event.pageX - dragOriginPageX) / zoom;
    const dy = (event.pageY - dragOriginPageY) / zoom;
    dispatch("move", {
      x: Math.round(dragStartX + dx),
      y: Math.round(dragStartY + dy),
    });
  }

  // Resize state
  let isResizing = false;
  let resizePointerId = -1;
  let resizeOriginPageX = 0;
  let resizeOriginPageY = 0;
  // Measured from active terminal's cellsize event
  let charWidth = 0;
  let rowHeight = 0;

  function handleResizePointerDown(event: PointerEvent) {
    if (event.button !== 0 || !hasWriteAccess) return;
    event.stopPropagation();
    isResizing = true;
    resizePointerId = event.pointerId;
    (event.currentTarget as HTMLElement).setPointerCapture(event.pointerId);
    resizeOriginPageX = event.pageX - cols * charWidth;
    resizeOriginPageY = event.pageY - rows * rowHeight;
  }

  function handleResizePointerMove(event: PointerEvent) {
    if (!isResizing || event.pointerId !== resizePointerId) return;
    if (charWidth <= 0 || rowHeight <= 0) return;
    const newCols = Math.min(
      Math.max(
        Math.floor((event.pageX - resizeOriginPageX) / charWidth),
        TERM_MIN_COLS,
      ),
      TERM_MAX_COLS,
    );
    const newRows = Math.min(
      Math.max(
        Math.floor((event.pageY - resizeOriginPageY) / rowHeight),
        TERM_MIN_ROWS,
      ),
      TERM_MAX_ROWS,
    );
    if (newCols !== cols || newRows !== rows) {
      dispatch("resize", { cols: newCols, rows: newRows });
    }
  }

  function handleResizePointerUp(event: PointerEvent) {
    if (!isResizing || event.pointerId !== resizePointerId) return;
    isResizing = false;
    resizePointerId = -1;
    (event.currentTarget as HTMLElement).releasePointerCapture(event.pointerId);
  }

  function handleShrink() {
    if (!hasWriteAccess) return;
    const newRows = Math.max(Math.min(rows - 4, TERM_MAX_ROWS), TERM_MIN_ROWS);
    const newCols = Math.max(Math.min(cols - 10, TERM_MAX_COLS), TERM_MIN_COLS);
    if (newRows !== rows || newCols !== cols) {
      dispatch("resize", { cols: newCols, rows: newRows });
    }
  }

  function handleExpand() {
    if (!hasWriteAccess) return;
    const newRows = Math.min(rows + 4, TERM_MAX_ROWS);
    const newCols = Math.min(cols + 10, TERM_MAX_COLS);
    dispatch("resize", { cols: newCols, rows: newRows });
  }
</script>

<!--
  Outer positioned wrapper — uses the slide action for smooth canvas movement,
  same pattern as each XTerm wrapper in Session.svelte.
-->
<div
  class="absolute"
  style:left="calc(50vw - 378px)"
  style:top="calc(50vh - 240px)"
  style:transform-origin="calc(-1 * calc(50vw - 378px)) calc(-1 * calc(50vh - 240px))"
  transition:fade|local
  use:slide={{ x, y, center, zoom, immediate: isDragging }}
  on:mousedown={() => dispatch("bringToFront")}
  on:pointerdown={(e) => e.stopPropagation()}
>
  <div class="tabbed-window" class:dragging={isDragging}>
    <!-- Tab bar -->
    <div
      class="tab-bar"
      on:pointerdown={handleTabBarPointerDown}
      on:pointermove={handleTabBarPointerMove}
      on:pointerup={handleTabBarPointerUp}
      on:pointercancel={handleTabBarPointerUp}
    >
      <!-- Circle buttons -->
      <div class="flex-shrink-0 px-2 flex items-center" data-circlebtn>
        <CircleButtons>
          <CircleButton
            kind="red"
            on:mousedown={(e) => {
              if (e.button !== 0) return;
              // Close all shells in the group
              for (const [id] of shells) dispatch("closeTab", { id });
            }}
          />
          <CircleButton
            kind="yellow"
            on:mousedown={(e) => e.button === 0 && handleShrink()}
          />
          <CircleButton
            kind="green"
            on:mousedown={(e) => e.button === 0 && handleExpand()}
          />
        </CircleButtons>
      </div>

      <!-- Divider -->
      <div class="tab-divider" />

      <!-- Tab list (scrollable) -->
      <div class="tab-list" bind:this={tabListEl}>
        {#each shells as [id] (id)}
          <button
            class="tab-item"
            class:active={id === activeTabId}
            data-tabitem
            data-tabid={id}
            on:mousedown={(e) => {
              if (e.button === 0) dispatch("switchTab", { id });
            }}
            title={tabTitles[id] ?? "Terminal"}
          >
            <span class="tab-title">{tabTitles[id] ?? "Terminal"}</span>
            <span
              class="tab-close"
              on:mousedown|stopPropagation={(e) => {
                if (e.button === 0) dispatch("closeTab", { id });
              }}
            >×</span>
          </button>
        {/each}
      </div>

      <!-- New tab button -->
      <button
        class="new-tab-btn"
        data-newbtn
        disabled={!hasWriteAccess}
        on:mousedown={(e) => {
          if (e.button === 0 && hasWriteAccess) dispatch("newTab");
        }}
        title="New terminal"
      >＋</button>
    </div>

    <!-- Terminal content area: all XTerms mounted, only active one visible -->
    <div class="term-area">
      {#each shells as [id, winsize] (id)}
        <XTerm
          {rows}
          {cols}
          showTitleBar={false}
          visible={id === activeTabId}
          bind:write={writers[id]}
          bind:termEl={termElements[id]}
          on:cellsize={({ detail }) => {
            if (id === activeTabId) {
              charWidth = detail.charWidth;
              rowHeight = detail.rowHeight;
            }
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
      {/each}

      <!-- Empty state when no shells -->
      {#if shells.length === 0}
        <div class="empty-state">
          <p>No terminals open.</p>
          <button
            disabled={!hasWriteAccess}
            on:click={() => dispatch("newTab")}
          >New Terminal</button>
        </div>
      {/if}
    </div>

    <!-- Resize handle (bottom-right corner) -->
    <div
      class="resize-handle"
      class:resizing={isResizing}
      on:pointerdown={handleResizePointerDown}
      on:pointermove={handleResizePointerMove}
      on:pointerup={handleResizePointerUp}
      on:pointercancel={handleResizePointerUp}
    >
      ⠿
    </div>
  </div>
</div>

<style>
  .tabbed-window {
    display: inline-block;
    border-radius: 0.5rem;
    border: 1px solid rgb(63, 63, 70);
    opacity: 0.9;
    transition: opacity 200ms;
    background: #09090b;
    position: relative;
  }

  .tabbed-window.dragging {
    opacity: 0.85;
    box-shadow: 0 8px 30px rgba(0, 0, 0, 0.4);
    transition: none;
  }

  .tab-bar {
    display: flex;
    align-items: center;
    background: rgb(39, 39, 42);
    border-radius: 0.5rem 0.5rem 0 0;
    border-bottom: 1px solid rgb(63, 63, 70);
    user-select: none;
    min-height: 36px;
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
    gap: 2px;
    overflow-x: auto;
    flex: 1;
    min-width: 0;
    scrollbar-width: none;
    padding: 4px 2px;
  }

  .tab-list::-webkit-scrollbar {
    display: none;
  }

  .tab-item {
    display: flex;
    align-items: center;
    gap: 4px;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 12px;
    white-space: nowrap;
    flex-shrink: 0;
    color: rgb(113, 113, 122);
    background: none;
    border: none;
    cursor: pointer;
    max-width: 160px;
    transition: background-color 150ms;
  }

  .tab-item:hover {
    background: rgb(63, 63, 70);
    color: rgb(228, 228, 231);
  }

  .tab-item.active {
    background: rgb(63, 63, 70);
    color: rgb(228, 228, 231);
  }

  .tab-title {
    overflow: hidden;
    text-overflow: ellipsis;
    max-width: 110px;
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
    position: relative;
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

  .resize-handle {
    position: absolute;
    bottom: -4px;
    right: -4px;
    width: 20px;
    height: 20px;
    cursor: nwse-resize;
    color: rgb(63, 63, 70);
    font-size: 12px;
    display: flex;
    align-items: center;
    justify-content: center;
    transition: color 150ms;
  }

  .resize-handle:hover,
  .resize-handle.resizing {
    color: rgb(113, 113, 122);
  }
</style>
