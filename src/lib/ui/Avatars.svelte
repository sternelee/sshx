<script lang="ts">
  import { fade } from "svelte/transition";

  import type { WsUser } from "$lib/protocol";
  import { nameToHue } from "./LiveCursor.svelte";

  let { users }: { users: [number, WsUser][] } = $props();

  function nameToInitials(name: string): string {
    const parts = name.split(/\s/).filter((s) => s);
    if (parts.length === 0) {
      return "-";
    } else if (parts.length === 1) {
      return parts[0][0].toLocaleUpperCase();
    } else {
      return (parts[0][0] + parts[1][0]).toLocaleUpperCase();
    }
  }
</script>

<div class="flex flex-row-reverse">
  {#each users as [id, user] (id)}
    <div
      class="avatar"
      style:background="hsla({nameToHue(user.name)}, 80%, 30%, 90%)"
      transition:fade|local={{ duration: 200 }}
    >
      {nameToInitials(user.name)}
    </div>
  {/each}
</div>

<style>
  .avatar {
    width: 1.75rem;
    height: 1.75rem;
    border-radius: 9999px;
    font-size: 0.75rem;
    font-weight: 500;
    display: flex;
    justify-content: center;
    align-items: center;
    margin-right: 0.25rem;
  }

  .avatar:first-child {
    margin-right: 0;
  }
</style>
