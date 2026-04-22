<script lang="ts">
  import type { Snippet } from "svelte";

  let {
    show,
    children,
    enter,
    enterFrom,
    enterTo,
    leave,
    leaveFrom,
    leaveTo,
    class: className = "",
    style,
  }: {
    show: boolean;
    children?: Snippet;
    enter?: string;
    enterFrom?: string;
    enterTo?: string;
    leave?: string;
    leaveFrom?: string;
    leaveTo?: string;
    class?: string;
    style?: string;
  } = $props();
</script>

{#if show}
  <div class={className} {style}>
    {@render children?.()}
  </div>
{/if}
