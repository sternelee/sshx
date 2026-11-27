<script lang="ts">
  import { fade, scale } from "svelte/transition";
  import { cubicOut } from "svelte/easing";
  import { XIcon } from "svelte-feather-icons";

  let {
    title,
    description,
    showCloseButton = false,
    maxWidth = 768, // screen-md
    open,
    onclose,
    children,
  }: {
    title: string;
    description: string;
    showCloseButton?: boolean;
    maxWidth?: number;
    open: boolean;
    onclose?: () => void;
    children: import("svelte").Snippet;
  } = $props();

  function handleKeydown(event: KeyboardEvent) {
    if (event.key === "Escape") onclose?.();
  }
</script>

<svelte:window onkeydown={handleKeydown} />

{#if open}
  <div
    class="fixed inset-0 z-50 grid place-items-center"
    role="presentation"
    transition:fade={{ duration: 100 }}
  >
    <button
      class="fixed inset-0 -z-10 bg-black/20 backdrop-blur-sm cursor-default"
      aria-label="Close {title}"
      tabindex="-1"
      onclick={() => onclose?.()}
    ></button>

    <div
      class="w-full sm:w-[calc(100%-32px)]"
      style="max-width: {maxWidth}px"
      role="dialog"
      aria-modal="true"
      aria-label={title}
      transition:scale={{ duration: 150, start: 0.95, easing: cubicOut }}
    >
      <div
        class="relative bg-[#111] sm:border border-zinc-800 px-6 py-10 sm:py-6
         h-screen sm:h-auto max-h-screen sm:rounded-lg overflow-y-auto"
      >
        {#if showCloseButton}
          <button
            class="absolute top-4 right-4 p-1 rounded hover:bg-zinc-700 active:bg-indigo-700 transition-colors"
            aria-label="Close {title}"
            onclick={() => onclose?.()}
          >
            <XIcon class="h-5 w-5" />
          </button>
        {/if}

        <div class="mb-8 text-center">
          <h2 class="text-xl font-medium mb-2">
            {title}
          </h2>
          <p class="text-zinc-400">
            {description}
          </p>
        </div>

        {@render children()}
      </div>
    </div>
  </div>
{/if}
