<script lang="ts">
  import { page } from "$app/stores";
  import P2PSession from "$lib/P2PSession.svelte";

  let title: string = "P2P Remote Terminal | sshx";
</script>

<svelte:head>
  <title>{title}</title>

  <style>
    body {
      overscroll-behavior: none;
    }
  </style>
</svelte:head>

<P2PSession
  id={$page.params.id || "p2p"}
  on:receiveName={({ detail: sessionName }) => {
    if (sessionName) {
      title = `${sessionName} | sshx`;
    }
  }}
/>
