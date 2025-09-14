<script lang="ts">
  import Session from "$lib/Session.svelte";

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

<Session
  id="p2p-main"
  on:receiveName={({ detail: sessionName }) => {
    if (sessionName) {
      title = `${sessionName} | sshx`;
    }
  }}
/>
