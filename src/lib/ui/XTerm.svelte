<!-- @component Interactive terminal rendered with wterm -->
<script lang="ts" context="module">
  import { makeToast } from "$lib/toast";

  // Deduplicated terminal font loading.
  const waitForFonts = (() => {
    let state: "initial" | "loading" | "loaded" = "initial";
    const waitlist: (() => void)[] = [];

    return async function waitForFonts() {
      if (state === "loaded") return;
      else if (state === "initial") {
        const FontFaceObserver = (await import("fontfaceobserver")).default;
        state = "loading";
        try {
          await new FontFaceObserver("Fira Code VF").load();
        } catch (error) {
          makeToast({
            kind: "error",
            message: "Could not load terminal font.",
          });
        }
        state = "loaded";
        for (const fn of waitlist) fn();
      } else {
        await new Promise<void>((resolve) => {
          if (state === "loaded") resolve();
          else waitlist.push(resolve);
        });
      }
    };
  })();
</script>

<script lang="ts">
  import { browser } from "$app/environment";

  import { createEventDispatcher, onDestroy, onMount } from "svelte";
  import { WTerm } from "@wterm/dom";

  import themes, { applyTheme } from "./themes";
  import CircleButton from "./CircleButton.svelte";
  import CircleButtons from "./CircleButtons.svelte";
  import { settings } from "$lib/settings";

  /** Used to determine Cmd versus Ctrl keyboard shortcuts. */
  const isMac = browser && navigator.platform.startsWith("Mac");

  const dispatch = createEventDispatcher<{
    data: Uint8Array;
    close: void;
    shrink: void;
    expand: void;
    bringToFront: void;
    startMove: PointerEvent;
    focus: void;
    blur: void;
    cellsize: { charWidth: number; rowHeight: number };
  }>();

  export let rows: number, cols: number;
  export let write: (data: string) => void; // bound function prop

  export let termEl: HTMLDivElement = null as any; // suppress "missing prop" warning
  let term: WTerm | null = null;
  export let charWidth = 0;
  export let rowHeight = 0;

  $: theme = themes[$settings.theme];

  $: if (term && termEl) {
    applyTheme(termEl, theme);
  }

  let loaded = false;
  let focused = false;
  let currentTitle = "Remote Terminal";
  let _focusCleanup: (() => void) | null = null;
  const utf8 = new TextEncoder();

  // Keyboard shortcuts for natural text editing.
  function handleKeydown(event: KeyboardEvent) {
    if (!focused) return;
    const target = event.target as HTMLElement;
    if (target.tagName === "INPUT" || target.tagName === "TEXTAREA") return;

    if (
      (isMac && event.metaKey && !event.ctrlKey && !event.altKey) ||
      (!isMac && !event.metaKey && event.ctrlKey && !event.altKey)
    ) {
      if (event.key === "ArrowLeft") {
        event.preventDefault();
        dispatch("data", new Uint8Array([0x01]));
        return;
      } else if (event.key === "ArrowRight") {
        event.preventDefault();
        dispatch("data", new Uint8Array([0x05]));
        return;
      } else if (event.key === "Backspace") {
        event.preventDefault();
        dispatch("data", new Uint8Array([0x15]));
        return;
      }
    }
  }

  function handleWheel(event: WheelEvent) {
    if (focused) {
      event.stopPropagation();
    }
  }

  let isDragging = false;

  function handleTitlePointerDown(event: PointerEvent) {
    if (event.button !== 0) return;
    isDragging = true;
    (event.currentTarget as HTMLElement).setPointerCapture(event.pointerId);
    dispatch("startMove", event);
  }

  function handleTitlePointerMove(event: PointerEvent) {
    if (!isDragging) return;
    dispatch("startMove", event);
  }

  function handleTitlePointerUp(event: PointerEvent) {
    if (!isDragging) return;
    isDragging = false;
    (event.currentTarget as HTMLElement).releasePointerCapture(event.pointerId);
    dispatch("startMove", event);
  }

  const preloadBuffer: string[] = [];

  write = (data: string) => {
    if (!term) {
      preloadBuffer.push(data);
    } else {
      console.log("[XTerm] Writing to terminal:", data);
      term.write(data);
    }
  };

  function measureCharSize() {
    if (!termEl) return;
    const grid = termEl.querySelector(".term-grid") as HTMLElement | null;
    if (!grid) return;

    // Create a single-character block identical to how wterm renders cells,
    // using the same class so CSS (font, line-height, row-height) is inherited.
    const row = document.createElement("div");
    row.className = "term-row";
    row.style.visibility = "hidden";
    row.style.position = "absolute";
    row.style.top = "0";
    row.style.left = "0";
    const block = document.createElement("span");
    block.className = "term-block";
    block.textContent = "W";
    row.appendChild(block);
    grid.appendChild(row);

    const rowRect = row.getBoundingClientRect();
    const blockRect = block.getBoundingClientRect();
    const measuredRowHeight = rowRect.height;
    const measuredCharWidth = blockRect.width;
    row.remove();

    // Sanity-check: reject implausible measurements that can occur when the
    // grid is mid-render or CSS is not yet fully applied.
    if (measuredRowHeight >= 4 && measuredRowHeight <= 200) {
      rowHeight = measuredRowHeight;
    } else if (!rowHeight) {
      rowHeight = 17; // safe fallback
    }
    if (measuredCharWidth >= 1 && measuredCharWidth <= 100) {
      charWidth = measuredCharWidth;
    } else if (!charWidth) {
      charWidth = 9; // safe fallback
    }

    // Keep wterm's internal CSS variable in sync so that its renderer does
    // not create rows with an exploding height.
    termEl.style.setProperty("--term-row-height", `${rowHeight}px`);
  }

  function updateSize(c: number, r: number) {
    if (!termEl || charWidth <= 0 || rowHeight <= 0) return;
    if (!Number.isFinite(c) || !Number.isFinite(r)) return;
    if (c < 1 || r < 1) return;
    const padding = 12 * 2; // wterm .wterm padding: 12px
    let w = c * charWidth + padding;
    let h = r * rowHeight + padding;
    // Hard pixel limits as a last line of defence against exploding sizes.
    w = Math.min(w, 3000);
    h = Math.min(h, 4000);
    termEl.style.boxSizing = "border-box";
    termEl.style.width = `${w}px`;
    termEl.style.height = `${h}px`;
  }

  $: if (
    term &&
    charWidth > 0 &&
    Number.isFinite(cols) &&
    Number.isFinite(rows)
  ) {
    term.resize(cols, rows);
    updateSize(cols, rows);
  }

  onMount(async () => {
    await waitForFonts();

    // wterm requires element to be in DOM before init
    term = new WTerm(termEl, {
      cols,
      rows,
      cursorBlink: false,
      autoResize: false,
      onData: (data: string) => {
        dispatch("data", utf8.encode(data));
      },
      onTitle: (title: string) => {
        currentTitle = title;
      },
    });

    // Apply CSS variables for theme without overwriting inline styles
    applyTheme(termEl, theme);

    try {
      await term.init();
    } catch (err) {
      console.error("[XTerm] wterm init failed:", err);
      return;
    }

    measureCharSize();
    updateSize(cols, rows);
    dispatch("cellsize", { charWidth, rowHeight });

    // Track real focus state using focusin/focusout, which bubble from the
    // wterm hidden textarea inside termEl. This is more accurate than
    // window.blur because it fires correctly when focus moves between terminals.
    // wterm's own _onClickFocus handles click-to-focus; we just sync our state.
    const handleFocusIn = () => {
      if (!focused) {
        focused = true;
        dispatch("focus");
      }
    };
    const handleFocusOut = (event: FocusEvent) => {
      // Only blur if focus truly left this terminal (not just moved within it).
      if (!termEl.contains(event.relatedTarget as Node)) {
        if (focused) {
          focused = false;
          dispatch("blur");
        }
      }
    };
    termEl.addEventListener("focusin", handleFocusIn);
    termEl.addEventListener("focusout", handleFocusOut);
    _focusCleanup = () => {
      termEl.removeEventListener("focusin", handleFocusIn);
      termEl.removeEventListener("focusout", handleFocusOut);
    };

    loaded = true;
    for (const data of preloadBuffer) {
      console.log("[XTerm] Flushing preload buffer:", data);
      term.write(data);
    }
  });

  onDestroy(() => {
    _focusCleanup?.();
    term?.destroy();
  });
</script>

<svelte:window onkeydown={handleKeydown} />

<div
  class="term-container"
  class:focused
  class:dragging={isDragging}
  style:background={theme.background}
  on:mousedown={() => {
    if (!isDragging) dispatch("bringToFront");
  }}
  on:pointerdown={(event) => event.stopPropagation()}
>
  <div
    class="flex select-none"
    on:pointerdown={handleTitlePointerDown}
    on:pointermove={handleTitlePointerMove}
    on:pointerup={handleTitlePointerUp}
    on:pointercancel={handleTitlePointerUp}
  >
    <div class="flex-1 flex items-center px-3">
      <CircleButtons>
        <!--
          TODO: This should be on:click, but that is not working due to the
          containing element's on:pointerdown `stopPropagation()` call.
        -->
        <CircleButton
          kind="red"
          on:mousedown={(event) => event.button === 0 && dispatch("close")}
        />
        <CircleButton
          kind="yellow"
          on:mousedown={(event) => event.button === 0 && dispatch("shrink")}
        />
        <CircleButton
          kind="green"
          on:mousedown={(event) => event.button === 0 && dispatch("expand")}
        />
      </CircleButtons>
    </div>
    <div
      class="p-2 text-sm text-zinc-300 text-center font-medium overflow-hidden whitespace-nowrap text-ellipsis w-0 flex-grow-[4]"
    >
      {currentTitle}
    </div>
    <div class="flex-1" />
  </div>
  <div
    class="block transition-opacity duration-500"
    bind:this={termEl}
    style:opacity={loaded ? 1.0 : 0.0}
    on:wheel={handleWheel}
  />
</div>

<style>
  .term-container {
    display: inline-block;
    border-radius: 0.5rem;
    border: 1px solid rgb(63, 63, 70);
    opacity: 0.9;
    transition:
      transform 200ms,
      opacity 200ms;
  }

  .term-container:not(.focused) :global(.wterm) {
    cursor: default;
  }

  .term-container.focused {
    opacity: 1;
  }

  .term-container.dragging {
    opacity: 0.85;
    box-shadow: 0 8px 30px rgba(0, 0, 0, 0.4);
    transition: none;
  }
</style>
