<script lang="ts">
  import { Dialog } from "bits-ui";
  import { XIcon } from "svelte-feather-icons";
  import { createEventDispatcher } from "svelte";
  import { fly, fade } from "svelte/transition";

  const dispatch = createEventDispatcher<{ close: void }>();

  export let title: string;
  export let description: string;
  export let showCloseButton = false;
  export let maxWidth: number = 768; // screen-md
  export let open: boolean = false;
</script>

<Dialog.Root bind:open>
  <Dialog.Portal>
    <Dialog.Overlay class="fixed inset-0 z-50 bg-black/20 backdrop-blur-sm" />
    <div class="fixed inset-0 z-50 grid place-items-center">
      <div
        class="w-full sm:w-[calc(100%-32px)]"
        style="max-width: {maxWidth}px"
        transition:fly="{{x: 0, y: -20, duration: 300}}"
      >
        <div
          class="relative bg-[#111] sm:border border-zinc-800 px-6 py-10 sm:py-6
           h-screen sm:h-auto max-h-screen sm:rounded-lg overflow-y-auto"
          transition:fade="{{duration: 300}}"
        >
          {#if showCloseButton}
            <button
              class="absolute top-4 right-4 p-1 rounded hover:bg-zinc-700 active:bg-indigo-700 transition-colors"
              aria-label="Close {title}"
              on:click={() => dispatch("close")}
            >
              <XIcon class="h-5 w-5" />
            </button>
          {/if}

          <div class="mb-8 text-center">
            <Dialog.Title class="text-xl font-medium mb-2">
              {title}
            </Dialog.Title>
            <Dialog.Description class="text-zinc-400">
              {description}
            </Dialog.Description>
          </div>

          <slot />
        </div>
      </div>
    </div>
  </Dialog.Portal>
</Dialog.Root>
