<script lang="ts">
  import type { Snippet } from "svelte";

  let {
    onclose,
    class: className = "",
    children,
  }: {
    onclose?: () => void;
    class?: string;
    children?: Snippet;
  } = $props();

  function handleKeydown(e: KeyboardEvent) {
    if (e.key === "Escape" && onclose) {
      onclose();
    }
  }
</script>

<svelte:window onkeydown={handleKeydown} />
<div class={className}>
  {@render children?.()}
</div>
