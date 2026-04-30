<script lang="ts">
  import type { Snippet } from "svelte";
  import Dialog from "$lib/ui-headless/Dialog.svelte";
  import DialogDescription from "$lib/ui-headless/DialogDescription.svelte";
  import DialogOverlay from "$lib/ui-headless/DialogOverlay.svelte";
  import DialogTitle from "$lib/ui-headless/DialogTitle.svelte";
  import Transition from "$lib/ui-headless/Transition.svelte";
  import TransitionChild from "$lib/ui-headless/TransitionChild.svelte";
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
    children?: Snippet;
  } = $props();
</script>

<Transition show={open}>
  <Dialog {onclose} class="fixed inset-0 z-50 grid place-items-center">
    <DialogOverlay class="fixed -z-10 inset-0 bg-black/20 backdrop-blur-sm" />

    <TransitionChild
      enter="duration-300 ease-out"
      enterFrom="scale-95 opacity-0"
      enterTo="scale-100 opacity-100"
      leave="duration-75 ease-out"
      leaveFrom="scale-200 opacity-100"
      leaveTo="scale-95 opacity-0"
      class="w-full sm:w-[calc(100%-32px)]"
      style="max-width: {maxWidth}px"
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
          <DialogTitle class="text-xl font-medium mb-2">
            {title}
          </DialogTitle>
          <DialogDescription class="text-zinc-400">
            {description}
          </DialogDescription>
        </div>

        {@render children?.()}
      </div>
    </TransitionChild>
  </Dialog>
</Transition>
