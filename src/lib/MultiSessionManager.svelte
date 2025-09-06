<script lang="ts">
  import { onMount, onDestroy, createEventDispatcher } from 'svelte';
  import { fade, slide } from 'svelte/transition';
  import type { MultiSessionSshxClient, SessionInfo } from '$lib/sshx-api';
  import { createMessageRouter, type RoutingConfig } from '$lib/message-router';

  export let id: string = 'multi-session';

  const dispatch = createEventDispatcher<{
    sessionCreated: string;
    sessionJoined: string;
    sessionSwitched: string;
    sessionClosed: string;
  }>();

  let multiSessionClient: MultiSessionSshxClient;
  let messageRouter: any;
  let sessions: SessionInfo[] = [];
  let activeSessionId: string | null = null;
  let showSessionManager = false;
  let newSessionLoading = false;
  let joinTicket = '';
  let joinLoading = false;
  let joinError = '';

  // Session UI state
  let minimizedSessions: string[] = [];
  let sessionLayout: 'grid' | 'tabs' = 'tabs';

  onMount(async () => {
    // Initialize multi-session client
    const { MultiSessionSshxClient } = await import('$lib/sshx-api');

    multiSessionClient = new MultiSessionSshxClient({
      onEvent: handleSessionEvent,
      onConnect: handleSessionConnect,
      onDisconnect: handleSessionDisconnect,
    });

    // Initialize message router with custom config
    const routingConfig: RoutingConfig = {
      enableBroadcast: true,
      enableCrossSessionRelay: false,
      maxMessageHistory: 500,
      enableMessageFiltering: true,
    };

    messageRouter = createMessageRouter(multiSessionClient, routingConfig);
    messageRouter.initialize();

    // Auto-create first session
    await createNewSession();
  });

  onDestroy(() => {
    multiSessionClient?.dispose();
    messageRouter?.dispose();
  });

  async function createNewSession() {
    try {
      newSessionLoading = true;
      const ticket = await multiSessionClient.createSession();
      await refreshSessions();

      // Switch to the new session
      const newSession = sessions.find(s => s.ticket === ticket);
      if (newSession) {
        await switchToSession(newSession.id);
      }

      dispatch('sessionCreated', ticket);
      newSessionLoading = false;
    } catch (error) {
      console.error('Failed to create session:', error);
      newSessionLoading = false;
    }
  }

  async function joinExistingSession() {
    try {
      joinLoading = true;
      joinError = '';

      const sessionId = await multiSessionClient.joinSession(joinTicket);
      await refreshSessions();

      // Switch to the joined session
      await switchToSession(sessionId);

      dispatch('sessionJoined', sessionId);
      joinLoading = false;
      joinTicket = '';
    } catch (error) {
      console.error('Failed to join session:', error);
      joinError = 'Failed to join session. Please check the ticket.';
      joinLoading = false;
    }
  }

  async function switchToSession(sessionId: string) {
    if (!multiSessionClient.isSessionActive(sessionId)) {
      console.error(`Session ${sessionId} is not active`);
      return;
    }

    try {
      messageRouter.setActiveSession(sessionId);
      activeSessionId = sessionId;
      dispatch('sessionSwitched', sessionId);
    } catch (error) {
      console.error('Failed to switch session:', error);
    }
  }

  async function closeSession(sessionId: string) {
    try {
      const success = await multiSessionClient.removeSession(sessionId);
      if (success) {
        await refreshSessions();

        // Switch to another session if we closed the active one
        if (sessionId === activeSessionId && sessions.length > 0) {
          await switchToSession(sessions[0].id);
        } else if (sessions.length === 0) {
          activeSessionId = null;
        }

        dispatch('sessionClosed', sessionId);
      }
    } catch (error) {
      console.error('Failed to close session:', error);
    }
  }

  async function refreshSessions() {
    try {
      sessions = multiSessionClient.getAllSessionInfo();
    } catch (error) {
      console.error('Failed to refresh sessions:', error);
    }
  }

  function toggleSessionMinimize(sessionId: string) {
    if (minimizedSessions.includes(sessionId)) {
      minimizedSessions = minimizedSessions.filter(id => id !== sessionId);
    } else {
      minimizedSessions = [...minimizedSessions, sessionId];
    }
  }

  function getSessionTitle(session: SessionInfo): string {
    const date = new Date(session.createdAt);
    return `Session ${date.toLocaleTimeString()}`;
  }

  function getSessionStatus(session: SessionInfo): string {
    return session.active ? 'Active' : 'Inactive';
  }

  // Event handlers
  function handleSessionEvent(event: any, sessionId?: string) {
    if (!sessionId) return;

    // Handle session-specific events here
    console.log(`Event from session ${sessionId}:`, event);
  }

  function handleSessionConnect(sessionId?: string) {
    if (!sessionId) return;
    console.log(`Session ${sessionId} connected`);
    refreshSessions();
  }

  function handleSessionDisconnect(sessionId?: string) {
    if (!sessionId) return;
    console.log(`Session ${sessionId} disconnected`);
    refreshSessions();
  }

  // Auto-refresh sessions periodically
  onMount(() => {
    const interval = setInterval(() => {
      if (sessions.length > 0) {
        refreshSessions();
      }
    }, 5000);

    return () => clearInterval(interval);
  });

  $: canCreateMore = sessions.length < 5; // Limit to 5 sessions
  $: activeSession = sessions.find(s => s.id === activeSessionId);

  // Keyboard shortcuts
  onMount(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.ctrlKey || event.metaKey) {
        switch (event.key) {
          case 'n':
            event.preventDefault();
            if (canCreateMore) createNewSession();
            break;
          case 't':
            event.preventDefault();
            showSessionManager = !showSessionManager;
            break;
          case 'Tab':
            event.preventDefault();
            if (sessions.length > 1) {
              const currentIndex = sessions.findIndex(s => s.id === activeSessionId);
              const nextIndex = (currentIndex + 1) % sessions.length;
              switchToSession(sessions[nextIndex].id);
            }
            break;
        }
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  });
</script>

<div class="multi-session-container">
  <!-- Session Manager Header -->
  <div class="session-manager-header">
    <div class="session-info">
      {#if activeSession}
        <span class="active-session-title">
          {getSessionTitle(activeSession)}
        </span>
        <span class="session-status active">
          {getSessionStatus(activeSession)}
        </span>
      {:else}
        <span class="no-session">No active session</span>
      {/if}
    </div>

    <div class="session-controls">
      <button
        class="btn btn-secondary"
        on:click={() => showSessionManager = !showSessionManager}
        title="Session Manager (Ctrl+T)"
      >
        Sessions ({sessions.length})
      </button>

      {#if canCreateMore}
        <button
          class="btn btn-primary"
          on:click={createNewSession}
          disabled={newSessionLoading}
          title="New Session (Ctrl+N)"
        >
          {#if newSessionLoading}
            Creating...
          {:else}
            New Session
          {/if}
        </button>
      {/if}
    </div>
  </div>

  <!-- Session Manager Panel -->
  {#if showSessionManager}
    <div class="session-manager-panel" transition:slide>
      <div class="panel-header">
        <h3>Session Manager</h3>
        <button class="close-btn" on:click={() => showSessionManager = false}>×</button>
      </div>

      <!-- Join Session Form -->
      <div class="join-session-form">
        <h4>Join Existing Session</h4>
        <div class="form-group">
          <input
            type="text"
            bind:value={joinTicket}
            placeholder="Enter session ticket"
            class:has-error={!!joinError}
          />
          {#if joinError}
            <div class="error-message">{joinError}</div>
          {/if}
        </div>
        <button
          class="btn btn-secondary"
          on:click={joinExistingSession}
          disabled={joinLoading || !joinTicket.trim()}
        >
          {#if joinLoading}
            Joining...
          {:else}
            Join Session
          {/if}
        </button>
      </div>

      <!-- Sessions List -->
      <div class="sessions-list">
        <h4>Active Sessions ({sessions.filter(s => s.active).length})</h4>
        {#each sessions as session (session.id)}
          <div
            class="session-item"
            class:active={session.id === activeSessionId}
            class:inactive={!session.active}
          >
            <div class="session-info">
              <div class="session-title">{getSessionTitle(session)}</div>
              <div class="session-meta">
                <span class="session-id">{session.id.slice(0, 8)}...</span>
                <span class="session-status">{getSessionStatus(session)}</span>
              </div>
            </div>

            <div class="session-actions">
              {#if session.active}
                {#if session.id !== activeSessionId}
                  <button
                    class="btn btn-sm btn-secondary"
                    on:click={() => switchToSession(session.id)}
                  >
                    Switch
                  </button>
                {/if}
                <button
                  class="btn btn-sm btn-danger"
                  on:click={() => closeSession(session.id)}
                >
                  Close
                </button>
              {:else}
                <button
                  class="btn btn-sm btn-secondary"
                  on:click={() => closeSession(session.id)}
                >
                  Remove
                </button>
              {/if}
            </div>
          </div>
        {/each}

        {#if sessions.length === 0}
          <div class="no-sessions">No sessions found</div>
        {/if}
      </div>
    </div>
  {/if}

  <!-- Session Content Area -->
  <div class="session-content">
    {#if activeSession}
      <div class="active-session-container">
        <!-- This would render the actual terminal/session content -->
        <div class="session-placeholder">
          <h3>Active Session: {getSessionTitle(activeSession)}</h3>
          <p>Session ID: {activeSession.id}</p>
          <p>Ticket: {activeSession.ticket}</p>
          <p>Terminal interface would be rendered here</p>
        </div>
      </div>
    {:else}
      <div class="no-session-placeholder">
        <h3>No Active Session</h3>
        <p>Create a new session or join an existing one to get started.</p>
      </div>
    {/if}
  </div>

  <!-- Quick Session Switcher (Keyboard Navigation) -->
  {#if sessions.length > 1}
    <div class="session-switcher-hint">
      <small>Press Ctrl+Tab to switch between sessions</small>
    </div>
  {/if}
</div>

<style>
  .multi-session-container {
    display: flex;
    flex-direction: column;
    height: 100vh;
    background: #1a1a1a;
    color: #fff;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  }

  .session-manager-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 1rem;
    background: #2d2d2d;
    border-bottom: 1px solid #404040;
  }

  .session-info {
    display: flex;
    align-items: center;
    gap: 1rem;
  }

  .active-session-title {
    font-weight: 600;
    color: #4CAF50;
  }

  .session-status {
    padding: 0.25rem 0.5rem;
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: 500;
  }

  .session-status.active {
    background: #4CAF50;
    color: white;
  }

  .session-status.inactive {
    background: #666;
    color: white;
  }

  .session-controls {
    display: flex;
    gap: 0.5rem;
  }

  .btn {
    padding: 0.5rem 1rem;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    font-size: 0.875rem;
    font-weight: 500;
    transition: all 0.2s;
  }

  .btn-primary {
    background: #4CAF50;
    color: white;
  }

  .btn-primary:hover:not(:disabled) {
    background: #45a049;
  }

  .btn-secondary {
    background: #555;
    color: white;
  }

  .btn-secondary:hover:not(:disabled) {
    background: #666;
  }

  .btn-danger {
    background: #f44336;
    color: white;
  }

  .btn-danger:hover:not(:disabled) {
    background: #da190b;
  }

  .btn-sm {
    padding: 0.25rem 0.5rem;
    font-size: 0.75rem;
  }

  .btn:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .session-manager-panel {
    position: absolute;
    top: 4rem;
    right: 1rem;
    width: 400px;
    max-height: 80vh;
    background: #2d2d2d;
    border: 1px solid #404040;
    border-radius: 8px;
    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
    z-index: 1000;
    overflow-y: auto;
  }

  .panel-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 1rem;
    border-bottom: 1px solid #404040;
  }

  .panel-header h3 {
    margin: 0;
    font-size: 1.125rem;
    font-weight: 600;
  }

  .close-btn {
    background: none;
    border: none;
    color: #999;
    font-size: 1.5rem;
    cursor: pointer;
    padding: 0;
    width: 1.5rem;
    height: 1.5rem;
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .close-btn:hover {
    color: #fff;
  }

  .join-session-form {
    padding: 1rem;
    border-bottom: 1px solid #404040;
  }

  .join-session-form h4 {
    margin: 0 0 0.75rem 0;
    font-size: 0.875rem;
    font-weight: 600;
    color: #ccc;
  }

  .form-group {
    margin-bottom: 0.75rem;
  }

  .form-group input {
    width: 100%;
    padding: 0.5rem;
    background: #1a1a1a;
    border: 1px solid #404040;
    border-radius: 4px;
    color: #fff;
    font-size: 0.875rem;
  }

  .form-group input.has-error {
    border-color: #f44336;
  }

  .error-message {
    color: #f44336;
    font-size: 0.75rem;
    margin-top: 0.25rem;
  }

  .sessions-list {
    padding: 1rem;
  }

  .sessions-list h4 {
    margin: 0 0 0.75rem 0;
    font-size: 0.875rem;
    font-weight: 600;
    color: #ccc;
  }

  .session-item {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 0.75rem;
    background: #1a1a1a;
    border: 1px solid #404040;
    border-radius: 4px;
    margin-bottom: 0.5rem;
  }

  .session-item.active {
    border-color: #4CAF50;
    background: #2d4a2d;
  }

  .session-item.inactive {
    opacity: 0.6;
  }

  .session-meta {
    display: flex;
    gap: 0.5rem;
    align-items: center;
    margin-top: 0.25rem;
  }

  .session-id {
    font-size: 0.75rem;
    color: #888;
    font-family: monospace;
  }

  .session-actions {
    display: flex;
    gap: 0.25rem;
  }

  .session-content {
    flex: 1;
    padding: 1rem;
    overflow: auto;
  }

  .session-placeholder,
  .no-session-placeholder {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    height: 100%;
    text-align: center;
    color: #ccc;
  }

  .session-placeholder h3,
  .no-session-placeholder h3 {
    margin-bottom: 1rem;
    color: #fff;
  }

  .no-sessions {
    text-align: center;
    color: #888;
    font-style: italic;
    padding: 2rem;
  }

  .session-switcher-hint {
    position: absolute;
    bottom: 1rem;
    right: 1rem;
    color: #666;
    font-size: 0.75rem;
  }

  .no-session {
    color: #888;
    font-style: italic;
  }
</style>
