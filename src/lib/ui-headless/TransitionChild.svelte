<script lang="ts">
  import type { Snippet } from "svelte";

  let {
    enter,
    enterFrom,
    enterTo,
    leave,
    leaveFrom,
    leaveTo,
    class: className = "",
    style,
    children,
  }: {
    enter?: string;
    enterFrom?: string;
    enterTo?: string;
    leave?: string;
    leaveFrom?: string;
    leaveTo?: string;
    class?: string;
    style?: string;
    children?: Snippet;
  } = $props();
</script>

<div class={className} {style}>
  {@render children?.()}
</div>
