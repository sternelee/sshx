<script lang="ts">
  import {
    MessageSquareIcon,
    PlusCircleIcon,
    SettingsIcon,
    WifiIcon,
  } from "svelte-feather-icons";

  import logo from "$lib/assets/logo.svg";

  let {
    connected,
    hasWriteAccess,
    newMessages,
    layoutMode = "canvas",
    oncreate,
    onchat,
    onsettings,
    onnetworkInfo,
    onlayoutChange,
  }: {
    connected: boolean;
    hasWriteAccess: boolean | undefined;
    newMessages: boolean;
    layoutMode?: "canvas" | "tabs";
    oncreate?: () => void;
    onchat?: () => void;
    onsettings?: () => void;
    onnetworkInfo?: () => void;
    onlayoutChange?: (mode: "canvas" | "tabs") => void;
  } = $props();
</script>

<div class="panel inline-block px-3 py-2">
  <div class="flex items-center select-none">
    <a href="/" class="flex-shrink-0"
      ><img src={logo} alt="sshx logo" class="h-10" /></a
    >
    <p class="ml-1.5 mr-2 font-medium">sshx</p>

    <div class="v-divider"></div>

    <div class="flex space-x-1">
      <button
        class="icon-button"
        onclick={() => oncreate?.()}
        disabled={!connected || !hasWriteAccess}
        title={!connected
          ? "Not connected"
          : hasWriteAccess === false
            ? "No write access"
            : "Create new terminal"}
      >
        <PlusCircleIcon strokeWidth={1.5} class="p-0.5" />
      </button>
      <button class="icon-button" onclick={() => onchat?.()}>
        <MessageSquareIcon strokeWidth={1.5} class="p-0.5" />
        {#if newMessages}
          <div class="activity"></div>
        {/if}
      </button>
      <button class="icon-button" onclick={() => onsettings?.()}>
        <SettingsIcon strokeWidth={1.5} class="p-0.5" />
      </button>
    </div>

    <div class="v-divider"></div>

    <div class="flex space-x-1">
      <button class="icon-button" onclick={() => onnetworkInfo?.()}>
        <WifiIcon strokeWidth={1.5} class="p-0.5" />
      </button>
    </div>

    <div class="v-divider"></div>

    <div class="flex space-x-1" title="Layout mode">
      <button
        class="icon-button"
        class:active={layoutMode === "canvas"}
        title="Canvas mode — free floating terminals"
        onclick={() => onlayoutChange?.("canvas")}
      >
        <svg
          width="20"
          height="20"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          stroke-width="1.5"
          stroke-linecap="round"
          stroke-linejoin="round"
          class="p-0.5"
        >
          <rect x="3" y="3" width="7" height="7" /><rect
            x="14"
            y="3"
            width="7"
            height="7"
          /><rect x="3" y="14" width="7" height="7" /><rect
            x="14"
            y="14"
            width="7"
            height="7"
          />
        </svg>
      </button>
      <button
        class="icon-button"
        class:active={layoutMode === "tabs"}
        title="Tab mode — all terminals in one window"
        onclick={() => onlayoutChange?.("tabs")}
      >
        <svg
          width="20"
          height="20"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          stroke-width="1.5"
          stroke-linecap="round"
          stroke-linejoin="round"
          class="p-0.5"
        >
          <rect x="3" y="3" width="18" height="18" rx="2" />
          <path d="M3 9h18M9 9v12" />
        </svg>
      </button>
    </div>
  </div>
</div>

<style>
  .v-divider {
    height: 1.25rem;
    margin-left: 0.5rem;
    margin-right: 0.5rem;
    border-left: 4px solid rgb(31, 31, 31);
  }

  .icon-button {
    position: relative;
    border-radius: 0.375rem;
    padding: 0.25rem;
    transition: background-color 200ms;
  }

  .icon-button:hover {
    background-color: rgb(63, 63, 63);
  }

  .icon-button:active {
    background-color: rgb(55, 48, 194);
  }

  .icon-button.active {
    background-color: rgb(55, 48, 194);
  }

  .icon-button:disabled {
    opacity: 0.5;
    background-color: transparent;
  }

  .activity {
    position: absolute;
    top: 0.25rem;
    right: 0.125rem;
    font-size: 0.75rem;
    padding: 2px;
    background-color: rgb(239, 68, 68);
    border-radius: 9999px;
  }
</style>
