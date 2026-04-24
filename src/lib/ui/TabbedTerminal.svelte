<!-- @component Tabbed terminal window: full-viewport fixed overlay below toolbar -->
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

  const dispatch = createEventDispatcher<{
    /** User switched to a different tab. */
    switchTab: { id: number };
    /** User clicked + to create a new terminal. */
    newTab: void;
    /** User clicked × on a tab (close that shell). */
    closeTab: { id: number };
    /** Terminal area resized — used to sync PTY dimensions. */
    resize: { cols: number; rows: number };
    /** Keystroke from the active terminal. */
    data: { id: number; data: Uint8Array };
    /** mousedown on window — used to close overlay panels in Session. */
    bringToFront: void;
    /** Active terminal gained focus. */
    focus: { id: number };
    /** Active terminal lost focus. */
    blur: { id: number };
  }>();

  // Internal terminal dimensions — computed from available space by auto-fit
  let cols = 80;
  let rows = 24;

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

  // Char dimensions — reported by XTerm's cellsize event
  let charWidth = 0;
  let rowHeight = 0;

  // Term-area pixel dimensions — measured by ResizeObserver
  let termAreaWidth = 0;
  let termAreaHeight = 0;

  /**
   * Svelte use: action — attaches a ResizeObserver to the term-area element
   * so we know the available pixel space for auto-fitting cols/rows.
   */
  function observeSize(el: HTMLDivElement) {
    const ro = new ResizeObserver(([entry]) => {
      termAreaWidth = Math.floor(entry.contentRect.width);
      termAreaHeight = Math.floor(entry.contentRect.height);
    });
    ro.observe(el);
    return {
      destroy() {
        ro.disconnect();
      },
    };
  }

  /**
   * Auto-fit: recompute cols/rows whenever the term-area size or char
   * dimensions change. Only dispatches resize when the values actually change.
   */
  $: if (charWidth > 0 && rowHeight > 0 && termAreaWidth > 0 && termAreaHeight > 0) {
    const newCols = Math.min(
      TERM_MAX_COLS,
      Math.max(TERM_MIN_COLS, Math.floor(termAreaWidth / charWidth)),
    );
    const newRows = Math.min(
      TERM_MAX_ROWS,
      Math.max(TERM_MIN_ROWS, Math.floor(termAreaHeight / rowHeight)),
    );
    if (newCols !== cols || newRows !== rows) {
      cols = newCols;
      rows = newRows;
      dispatch("resize", { cols, rows });
    }
  }

  function handleShrink() {
    if (!hasWriteAccess) return;
    const newRows = Math.max(Math.min(rows - 4, TERM_MAX_ROWS), TERM_MIN_ROWS);
    const newCols = Math.max(Math.min(cols - 10, TERM_MAX_COLS), TERM_MIN_COLS);
    if (newRows !== rows || newCols !== cols) {
      cols = newCols;
      rows = newRows;
      dispatch("resize", { cols: newCols, rows: newRows });
    }
  }

  function handleExpand() {
    if (!hasWriteAccess) return;
    const newRows = Math.min(rows + 4, TERM_MAX_ROWS);
    const newCols = Math.min(cols + 10, TERM_MAX_COLS);
    if (newRows !== rows || newCols !== cols) {
      cols = newCols;
      rows = newRows;
      dispatch("resize", { cols: newCols, rows: newRows });
    }
  }
</script>

<!--
  Fixed overlay that fills the viewport from the bottom of the toolbar to the
  bottom of the screen. Not canvas-relative — ignores pan and zoom.
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
      <div class="tab-divider"></div>

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
        disabled={!connected || !hasWriteAccess}
        on:mousedown={(e) => {
          if (e.button === 0 && connected && hasWriteAccess) dispatch("newTab");
        }}
        title="New terminal"
      >＋</button>
    </div>

    <!-- Terminal content area: fills remaining height, XTerms overflow-clipped -->
    <div class="term-area" use:observeSize>
      {#each shells as [id, winsize] (id)}
        <XTerm
          {rows}
          {cols}
          showTitleBar={false}
          visible={id === activeTabId}
          bind:write={writers[id]}
          bind:termEl={termElements[id]}
          on:cellsize={({ detail }) => {
            // All tabs share the same font/size, so any cellsize reading is valid.
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
      {/each}

      <!-- Empty state when no shells -->
      {#if shells.length === 0}
        <div class="empty-state">
          <p>No terminals open.</p>
          <button
            disabled={!connected || !hasWriteAccess}
            on:mousedown={(e) => {
              if (e.button === 0 && connected && hasWriteAccess)
                dispatch("newTab");
            }}
          >New Terminal</button>
        </div>
      {/if}
    </div>
  </div>
</div>

<style>
  /* Full-viewport fixed overlay below the toolbar, 96% wide and centered */
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

  /* Window chrome — fills the overlay, column flex */
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

  .tab-item:hover {
    background: rgb(63, 63, 70);
    color: rgb(228, 228, 231);
  }

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

  /* Fills remaining height; XTerm content overflows and is clipped here */
  .term-area {
    flex: 1;
    min-height: 0;
    position: relative;
    overflow: hidden;
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
