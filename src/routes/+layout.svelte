<script lang="ts">
  import "@fontsource-variable/inter";
  import "@wterm/dom/css";
  import "../app.css";

  import type { Snippet } from "svelte";
  import ToastContainer from "$lib/ui/ToastContainer.svelte";

  let { children }: { children?: Snippet } = $props();
</script>

<ToastContainer />

{@render children?.()}
