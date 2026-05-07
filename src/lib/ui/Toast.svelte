<script lang="ts">
  import {
    CheckCircleIcon,
    HelpCircleIcon,
    InfoIcon,
    XCircleIcon,
  } from "svelte-feather-icons";

  let {
    kind = "info",
    message,
    action = "",
    onaction,
  }: {
    /** The kind of toast to display. */
    kind?: "info" | "success" | "error";
    /** The message to display inside the toast. */
    message: string;
    /** An optional action to provide as a button on the toast. */
    action?: string;
    /** Invoked when the user clicks the action button. */
    onaction?: () => void;
  } = $props();
</script>

<div class="toast-box">
  {#if kind === "info"}
    <InfoIcon class="w-5 h-5 text-accent-lime flex-shrink-0" />
  {:else if kind === "success"}
    <CheckCircleIcon class="w-5 h-5 text-green-300 flex-shrink-0" />
  {:else if kind === "error"}
    <XCircleIcon class="w-5 h-5 text-red-300 flex-shrink-0" />
  {:else}
    <HelpCircleIcon class="w-5 h-5 text-accent-lime flex-shrink-0" />
  {/if}

  <p class="ml-3">
    {message}
  </p>

  {#if action}
    <div class="ml-auto">
      <button
        class="h-5 ml-3 px-2 flex items-center text-xs border rounded-md border-zinc-400 hover:border-zinc-200 hover:text-white transition-colors"
        onclick={() => onaction?.()}
      >
        {action}
      </button>
    </div>
  {/if}
</div>

<style>
  .toast-box {
    border: 1px solid rgb(63 63 70);
    background: rgba(24, 24, 27, 0.8);
    backdrop-filter: blur(4px);
    padding: 1rem;
    border-radius: 0.375rem;
    display: flex;
    align-items: flex-start;
    pointer-events: auto;
    font-size: 0.875rem;
  }
</style>
