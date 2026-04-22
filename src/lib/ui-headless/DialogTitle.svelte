<script lang="ts">
  import type { Snippet } from "svelte";
  let { class: className = "", children }: { class?: string; children?: Snippet } = $props();
</script>

<h2 class={className}>
  {@render children?.()}
</h2>
