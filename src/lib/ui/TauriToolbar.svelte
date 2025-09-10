<script lang="ts">
  import { createEventDispatcher, onMount, onDestroy } from "svelte";
  import { 
    MinimizeIcon, 
    MaximizeIcon, 
    XIcon, 
    CopyIcon, 
    ShareIcon,
    SettingsIcon,
    InfoIcon
  } from "svelte-feather-icons";
  import { isTauri, getTauriApi } from "$lib/tauri-api";
  import { makeToast } from "$lib/toast";

  export let currentSessionId: string | null = null;
  export let sessionTicket: string = "";
  export let connected: boolean = false;

  const dispatch = createEventDispatcher<{
    settings: void;
    info: void;
    shareSession: string;
  }>();

  let tauriApi = getTauriApi();
  let appVersion = "unknown";
  let nodeId = "unknown";
  let isDesktop = false;

  onMount(async () => {
    isDesktop = isTauri();
    
    if (isDesktop) {
      try {
        appVersion = await tauriApi.getAppVersion();
        nodeId = await tauriApi.getNodeId();
      } catch (error) {
        console.error("Failed to get app info:", error);
      }

      // Set up window close handler
      tauriApi.onWindowCloseRequested(async () => {
        if (currentSessionId) {
          const shouldClose = confirm("You have an active session. Are you sure you want to close the app?");
          if (shouldClose) {
            try {
              await tauriApi.closeSession(currentSessionId);
            } catch (error) {
              console.error("Failed to close session on exit:", error);
            }
          }
          return shouldClose;
        }
        return true;
      });
    }
  });

  async function minimizeWindow() {
    if (isDesktop) {
      await tauriApi.minimizeWindow();
    }
  }

  async function maximizeWindow() {
    if (isDesktop) {
      await tauriApi.maximizeWindow();
    }
  }

  async function closeWindow() {
    if (isDesktop) {
      await tauriApi.closeWindow();
    }
  }

  async function copySessionTicket() {
    if (sessionTicket) {
      try {
        await tauriApi.copyToClipboard(sessionTicket);
        makeToast({
          kind: "success",
          message: "Session ticket copied to clipboard!"
        });
      } catch (error) {
        console.error("Failed to copy to clipboard:", error);
        makeToast({
          kind: "error",
          message: "Failed to copy session ticket"
        });
      }
    }
  }

  async function shareSession() {
    if (currentSessionId && sessionTicket) {
      dispatch("shareSession", sessionTicket);
    }
  }

  function showSettings() {
    dispatch("settings");
  }

  function showInfo() {
    dispatch("info");
  }
</script>

{#if isDesktop}
  <div class="tauri-toolbar">
    <!-- Left side - App info and controls -->
    <div class="toolbar-left">
      <div class="app-info">
        <span class="app-name">sshx</span>
        {#if connected && currentSessionId}
          <span class="session-indicator">
            • Session {currentSessionId.slice(0, 8)}...
          </span>
        {/if}
      </div>
    </div>

    <!-- Center - Session controls -->
    <div class="toolbar-center">
      {#if connected && sessionTicket}
        <button
          class="toolbar-btn session-btn"
          on:click={copySessionTicket}
          title="Copy session ticket"
        >
          <CopyIcon size="16" />
          <span>Copy Ticket</span>
        </button>
        
        <button
          class="toolbar-btn session-btn"
          on:click={shareSession}
          title="Share session"
        >
          <ShareIcon size="16" />
          <span>Share</span>
        </button>
      {/if}
    </div>

    <!-- Right side - Window controls -->
    <div class="toolbar-right">
      <button
        class="toolbar-btn"
        on:click={showInfo}
        title="App information"
      >
        <InfoIcon size="16" />
      </button>
      
      <button
        class="toolbar-btn"
        on:click={showSettings}
        title="Settings"
      >
        <SettingsIcon size="16" />
      </button>
      
      <div class="window-controls">
        <button
          class="window-control minimize"
          on:click={minimizeWindow}
          title="Minimize"
        >
          <MinimizeIcon size="14" />
        </button>
        
        <button
          class="window-control maximize"
          on:click={maximizeWindow}
          title="Maximize"
        >
          <MaximizeIcon size="14" />
        </button>
        
        <button
          class="window-control close"
          on:click={closeWindow}
          title="Close"
        >
          <XIcon size="14" />
        </button>
      </div>
    </div>
  </div>

  <!-- App Info Modal (placeholder for now) -->
  <div class="app-info-hidden">
    <span>Version: {appVersion}</span>
    <span>Node ID: {nodeId.slice(0, 12)}...</span>
  </div>
{/if}

<style>
  .tauri-toolbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    height: 40px;
    background: #27272a;
    border-bottom: 1px solid #3f3f46;
    padding: 0 12px;
    user-select: none;
    -webkit-app-region: drag;
  }

  .toolbar-left,
  .toolbar-center,
  .toolbar-right {
    display: flex;
    align-items: center;
    gap: 8px;
    -webkit-app-region: no-drag;
  }

  .toolbar-left {
    flex: 1;
  }

  .toolbar-center {
    flex: 0 0 auto;
  }

  .toolbar-right {
    flex: 1;
    justify-content: flex-end;
  }

  .app-info {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 13px;
    color: #a1a1aa;
  }

  .app-name {
    font-weight: 600;
    color: #f4f4f5;
  }

  .session-indicator {
    color: #22c55e;
    font-size: 12px;
  }

  .toolbar-btn {
    display: flex;
    align-items: center;
    gap: 4px;
    padding: 4px 8px;
    background: transparent;
    border: none;
    color: #a1a1aa;
    font-size: 12px;
    border-radius: 4px;
    cursor: pointer;
    transition: all 150ms ease;
  }

  .toolbar-btn:hover {
    background: #3f3f46;
    color: #f4f4f5;
  }

  .session-btn {
    background: #1e40af;
    color: #dbeafe;
  }

  .session-btn:hover {
    background: #1d4ed8;
    color: #ffffff;
  }

  .window-controls {
    display: flex;
    gap: 2px;
    margin-left: 8px;
  }

  .window-control {
    width: 28px;
    height: 28px;
    display: flex;
    align-items: center;
    justify-content: center;
    background: transparent;
    border: none;
    color: #a1a1aa;
    cursor: pointer;
    border-radius: 4px;
    transition: all 150ms ease;
  }

  .window-control:hover {
    background: #3f3f46;
    color: #f4f4f5;
  }

  .window-control.close:hover {
    background: #dc2626;
    color: #ffffff;
  }

  .app-info-hidden {
    display: none;
  }

  /* Responsive adjustments */
  @media (max-width: 768px) {
    .toolbar-center {
      display: none;
    }
    
    .app-info {
      font-size: 12px;
    }
    
    .session-indicator {
      display: none;
    }
  }
</style>