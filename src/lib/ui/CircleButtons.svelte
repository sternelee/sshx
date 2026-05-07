<script lang="ts">
  import type { Snippet } from "svelte";

  let { children }: { children?: Snippet } = $props();
</script>

<div class="flex space-x-2 text-transparent hover:text-black/75">
  {@render children?.()}
</div>
