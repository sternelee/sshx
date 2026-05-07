<!-- @component Interactive terminal rendered with wterm -->
<script lang="ts" module>
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
          makeToast({ kind: "error", message: "Could not load terminal font." });
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
  import { onDestroy, onMount } from "svelte";
  import { WTerm } from "@wterm/dom";

  import themes, { applyTheme } from "./themes";
  import CircleButton from "./CircleButton.svelte";
  import CircleButtons from "./CircleButtons.svelte";
  import { settings } from "$lib/settings";

  const isMac = browser && navigator.platform.startsWith("Mac");

  /**
   * Props — note: `write` and `termEl` are exposed via registration callbacks
   * rather than $bindable because Svelte 5 throws props_invalid_value when a
   * function is propagated back through a $bindable binding.
   */
  let {
    rows,
    cols,
    showTitleBar = true,
    visible = true,
    fillParent = false,
    /** Called once during init with a stable write function. */
    onregisterWrite,
    /** Called once after the wterm container div is mounted. */
    onregisterTermEl,
    ondata,
    onclose,
    onshrink,
    onexpand,
    onbringToFront,
    onstartMove,
    onfocus,
    onblur,
    oncellsize,
    ontitle,
  }: {
    rows: number;
    cols: number;
    showTitleBar?: boolean;
    visible?: boolean;
    /** When true the wterm container fills its CSS parent instead of using
     *  exact pixel dimensions. Use in split-pane mode where .term-container
     *  is already positioned to fill the pane via CSS. */
    fillParent?: boolean;
    onregisterWrite?: (fn: (data: string) => void) => void;
    onregisterTermEl?: (el: HTMLDivElement) => void;
    ondata?: (data: Uint8Array) => void;
    onclose?: () => void;
    onshrink?: () => void;
    onexpand?: () => void;
    onbringToFront?: () => void;
    onstartMove?: (e: PointerEvent) => void;
    onfocus?: () => void;
    onblur?: () => void;
    oncellsize?: (size: { charWidth: number; rowHeight: number }) => void;
    ontitle?: (title: string) => void;
  } = $props();

  let term: WTerm | null = null;
  // Local state for the wterm container element.
  let termEl = $state<HTMLDivElement>(null as any);
  let charWidth = $state(0);
  let rowHeight = $state(0);

  const theme = $derived(themes[$settings.theme]);

  $effect(() => {
    if (term && termEl) applyTheme(termEl, theme);
  });

  let loaded = $state(false);
  let focused = $state(false);
  let currentTitle = $state("Remote Terminal");
  let _focusCleanup: (() => void) | null = null;
  const utf8 = new TextEncoder();

  // Preload buffer: holds data arriving before the terminal is initialised.
  const preloadBuffer: string[] = [];

  // Register a stable write function with the parent immediately (synchronously).
  // Using a registration callback avoids Svelte 5's props_invalid_value error
  // that occurs when propagating a function through a $bindable prop.
  onregisterWrite?.((data: string) => {
    if (!term) preloadBuffer.push(data);
    else term.write(data);
  });

  // Expose the wterm container element to the parent after it's mounted.
  $effect(() => {
    if (termEl) onregisterTermEl?.(termEl);
  });

  function handleKeydown(event: KeyboardEvent) {
    if (!focused) return;
    const target = event.target as HTMLElement;
    if (target.tagName === "INPUT" || target.tagName === "TEXTAREA") {
      if (event.key === "Escape") event.preventDefault();
      return;
    }
    if (
      (isMac && event.metaKey && !event.ctrlKey && !event.altKey) ||
      (!isMac && !event.metaKey && event.ctrlKey && !event.altKey)
    ) {
      if (event.key === "ArrowLeft") {
        event.preventDefault();
        ondata?.(new Uint8Array([0x01]));
        return;
      } else if (event.key === "ArrowRight") {
        event.preventDefault();
        ondata?.(new Uint8Array([0x05]));
        return;
      } else if (event.key === "Backspace") {
        event.preventDefault();
        ondata?.(new Uint8Array([0x15]));
        return;
      }
    }
  }

  function handleWheel(event: WheelEvent) {
    if (focused) event.stopPropagation();
  }

  let isDragging = $state(false);

  function handleTitlePointerDown(event: PointerEvent) {
    if (event.button !== 0) return;
    isDragging = true;
    (event.currentTarget as HTMLElement).setPointerCapture(event.pointerId);
    onstartMove?.(event);
  }

  function handleTitlePointerMove(event: PointerEvent) {
    if (!isDragging) return;
    onstartMove?.(event);
  }

  function handleTitlePointerUp(event: PointerEvent) {
    if (!isDragging) return;
    isDragging = false;
    (event.currentTarget as HTMLElement).releasePointerCapture(event.pointerId);
    onstartMove?.(event);
  }

  function measureCharSize() {
    if (!termEl) return;
    const grid = termEl.querySelector(".term-grid") as HTMLElement | null;
    if (!grid) return;

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
    row.remove();

    if (rowRect.height >= 4 && rowRect.height <= 200) rowHeight = rowRect.height;
    else if (!rowHeight) rowHeight = 17;

    if (blockRect.width >= 1 && blockRect.width <= 100) charWidth = blockRect.width;
    else if (!charWidth) charWidth = 9;

    termEl.style.setProperty("--term-row-height", `${rowHeight}px`);
  }

  function updateSize(c: number, r: number) {
    if (!termEl || charWidth <= 0 || rowHeight <= 0) return;
    if (!Number.isFinite(c) || !Number.isFinite(r) || c < 1 || r < 1) return;
    termEl.style.boxSizing = "border-box";
    if (fillParent) {
      // Let CSS control dimensions (parent is position:absolute; inset:0).
      // wterm grid renders at top-left; extra space shows as terminal bg.
      termEl.style.width = "100%";
      termEl.style.height = "100%";
    } else {
      const padding = 12 * 2;
      termEl.style.width = `${Math.min(c * charWidth + padding, 3000)}px`;
      termEl.style.height = `${Math.min(r * rowHeight + padding, 4000)}px`;
    }
  }

  $effect(() => {
    if (term && charWidth > 0 && Number.isFinite(cols) && Number.isFinite(rows)) {
      term.resize(cols, rows);
      updateSize(cols, rows);
    }
  });

  onMount(async () => {
    await waitForFonts();

    term = new WTerm(termEl, {
      cols,
      rows,
      cursorBlink: false,
      autoResize: false,
      onData: (data: string) => { ondata?.(utf8.encode(data)); },
      onTitle: (title: string) => {
        currentTitle = title;
        ontitle?.(title);
      },
    });

    applyTheme(termEl, theme);

    try {
      await term.init();
    } catch (err) {
      console.error("[XTerm] wterm init failed:", err);
      return;
    }

    measureCharSize();
    updateSize(cols, rows);
    oncellsize?.({ charWidth, rowHeight });

    const handleFocusIn = () => {
      if (!focused) {
        focused = true;
        // Defer so we're not mutating external state while Svelte's effect
        // runner is actively updating the DOM (e.g. switching pane visibility
        // sets display:none which synchronously fires focusout, which would
        // throw state_unsafe_mutation if onblur modifies parent $state).
        queueMicrotask(() => onfocus?.());
      }
    };
    const handleFocusOut = (event: FocusEvent) => {
      // Capture relatedTarget synchronously – it may become null after a tick.
      const isInside = termEl.contains(event.relatedTarget as Node);
      if (!isInside && focused) {
        focused = false;
        queueMicrotask(() => onblur?.());
      }
    };
    termEl.addEventListener("focusin", handleFocusIn);
    termEl.addEventListener("focusout", handleFocusOut);
    _focusCleanup = () => {
      termEl.removeEventListener("focusin", handleFocusIn);
      termEl.removeEventListener("focusout", handleFocusOut);
    };

    loaded = true;
    for (const data of preloadBuffer) term.write(data);
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
  style:display={visible ? undefined : "none"}
  onmousedown={() => { if (!isDragging) onbringToFront?.(); }}
  onpointerdown={(event) => event.stopPropagation()}
  role="presentation"
>
  {#if showTitleBar}
    <div
      class="flex select-none"
      onpointerdown={handleTitlePointerDown}
      onpointermove={handleTitlePointerMove}
      onpointerup={handleTitlePointerUp}
      onpointercancel={handleTitlePointerUp}
      role="presentation"
    >
      <div class="flex-1 flex items-center px-3">
        <CircleButtons>
          <CircleButton kind="red"    onmousedown={(e) => e.button === 0 && onclose?.()}  />
          <CircleButton kind="yellow" onmousedown={(e) => e.button === 0 && onshrink?.()}  />
          <CircleButton kind="green"  onmousedown={(e) => e.button === 0 && onexpand?.()}  />
        </CircleButtons>
      </div>
      <div class="p-2 text-sm text-zinc-300 text-center font-medium overflow-hidden whitespace-nowrap text-ellipsis w-0 flex-grow-[4]">
        {currentTitle}
      </div>
      <div class="flex-1"></div>
    </div>
  {/if}
  <div
    class="block transition-opacity duration-500"
    bind:this={termEl}
    style:opacity={loaded ? 1.0 : 0.0}
    onwheel={handleWheel}
    onclick={() => term?.focus()}
    onmousedown={() => term?.focus()}
    role="presentation"
  ></div>
</div>

<style>
  .term-container {
    display: inline-block;
    border-radius: 0.5rem;
    border: 1px solid rgb(63, 63, 70);
    opacity: 0.9;
    transition: transform 200ms, opacity 200ms;
  }

  .term-container:not(.focused) :global(.wterm) { cursor: default; }
  .term-container.focused { opacity: 1; }
  .term-container.dragging {
    opacity: 0.85;
    box-shadow: 0 8px 30px rgba(0, 0, 0, 0.4);
    transition: none;
  }
</style>
