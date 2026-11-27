<script lang="ts">
  import "@fontsource-variable/inter";

  import "sshx-xterm/css/xterm.css";
  import "../app.css";

  import ToastContainer from "$lib/ui/ToastContainer.svelte";

  let { children } = $props();
</script>

<ToastContainer />

{@render children()}
