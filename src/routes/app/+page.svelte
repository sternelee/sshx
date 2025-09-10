<script lang="ts">
  import { onMount } from "svelte";
  import { isTauri } from "$lib/tauri-api";
  import P2PSession from "$lib/P2PSession.svelte";
  import { goto } from "$app/navigation";
  import {
    DesktopIcon,
    ShareIcon,
    PlusIcon,
    LogInIcon,
    SettingsIcon,
  } from "svelte-feather-icons";

  let isDesktopApp = false;
  let showCreateSession = false;
  let showJoinSession = false;
  let sessionTicket = "";
  let sessionStarted = false;

  onMount(() => {
    isDesktopApp = isTauri();
  });

  function startNewSession() {
    sessionStarted = true;
  }

  function joinSessionWithTicket() {
    if (sessionTicket.trim()) {
      goto(`/p2p?ticket=${encodeURIComponent(sessionTicket)}`);
    }
  }

  function openP2PSession() {
    goto("/p2p");
  }
</script>

<svelte:head>
  <title
    >sshx - Secure Collaborative Terminal{isDesktopApp
      ? " (Desktop)"
      : ""}</title
  >
</svelte:head>

{#if sessionStarted}
  <P2PSession />
{:else}
  <main class="min-h-screen bg-zinc-900 text-zinc-100">
    <div class="max-w-4xl mx-auto px-4 py-8">
      <!-- Header -->
      <header class="text-center mb-12">
        <div class="flex items-center justify-center gap-3 mb-4">
          {#if isDesktopApp}
            <DesktopIcon size="32" class="text-blue-400" />
          {/if}
          <h1 class="text-4xl font-bold">sshx</h1>
        </div>
        <p class="text-zinc-400 text-lg">
          {isDesktopApp ? "Desktop App" : "Web App"} - Secure Collaborative Terminal
        </p>
        {#if isDesktopApp}
          <p class="text-sm text-blue-400 mt-2">
            Running in Tauri desktop environment with P2P networking
          </p>
        {/if}
      </header>

      <!-- Quick Actions -->
      <div class="grid md:grid-cols-2 gap-6 mb-12">
        <!-- Create New Session -->
        <div class="bg-zinc-800 rounded-lg border border-zinc-700 p-6">
          <div class="flex items-center gap-3 mb-4">
            <div class="p-2 bg-green-600 rounded-lg">
              <PlusIcon size="20" />
            </div>
            <h2 class="text-xl font-semibold">Start New Session</h2>
          </div>
          <p class="text-zinc-400 mb-4">
            Create a new collaborative terminal session and share it with
            others.
          </p>
          <button
            class="bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded-lg font-medium transition-colors w-full"
            on:click={openP2PSession}
          >
            Create Session
          </button>
        </div>

        <!-- Join Existing Session -->
        <div class="bg-zinc-800 rounded-lg border border-zinc-700 p-6">
          <div class="flex items-center gap-3 mb-4">
            <div class="p-2 bg-blue-600 rounded-lg">
              <LogInIcon size="20" />
            </div>
            <h2 class="text-xl font-semibold">Join Session</h2>
          </div>
          <p class="text-zinc-400 mb-4">
            Enter a session ticket to join an existing collaborative session.
          </p>
          <div class="space-y-3">
            <input
              type="text"
              placeholder="Paste session ticket here..."
              bind:value={sessionTicket}
              class="w-full px-3 py-2 bg-zinc-700 border border-zinc-600 rounded-lg text-zinc-100 placeholder-zinc-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
            <button
              class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg font-medium transition-colors w-full"
              disabled={!sessionTicket.trim()}
              on:click={joinSessionWithTicket}
            >
              Join Session
            </button>
          </div>
        </div>
      </div>

      <!-- Features Section -->
      <section class="mb-12">
        <h3 class="text-2xl font-semibold mb-6 text-center">Features</h3>
        <div class="grid md:grid-cols-3 gap-6">
          <div class="text-center">
            <div class="p-3 bg-purple-600 rounded-lg inline-block mb-3">
              <ShareIcon size="24" />
            </div>
            <h4 class="font-semibold mb-2">P2P Networking</h4>
            <p class="text-zinc-400 text-sm">
              Direct peer-to-peer connections for low-latency collaboration
            </p>
          </div>
          <div class="text-center">
            <div class="p-3 bg-pink-600 rounded-lg inline-block mb-3">
              <SettingsIcon size="24" />
            </div>
            <h4 class="font-semibold mb-2">End-to-End Encrypted</h4>
            <p class="text-zinc-400 text-sm">
              All communications are encrypted and secure
            </p>
          </div>
          <div class="text-center">
            <div class="p-3 bg-orange-600 rounded-lg inline-block mb-3">
              <DesktopIcon size="24" />
            </div>
            <h4 class="font-semibold mb-2">Cross-Platform</h4>
            <p class="text-zinc-400 text-sm">
              Available as web app and native desktop application
            </p>
          </div>
        </div>
      </section>

      <!-- Platform Info -->
      {#if isDesktopApp}
        <div
          class="bg-blue-900/20 border border-blue-700/50 rounded-lg p-4 mb-8"
        >
          <h4 class="font-semibold text-blue-400 mb-2">Desktop App Benefits</h4>
          <ul class="text-sm text-zinc-300 space-y-1">
            <li>• Native system integration and notifications</li>
            <li>• Better performance with native P2P networking</li>
            <li>• Offline-capable collaborative sessions</li>
            <li>• System tray integration (when available)</li>
          </ul>
        </div>
      {:else}
        <div
          class="bg-zinc-800 border border-zinc-700 rounded-lg p-4 mb-8 text-center"
        >
          <p class="text-zinc-400 mb-3">
            Want a better experience? Try our desktop app!
          </p>
          <a
            href="https://github.com/ekzhang/sshx/releases"
            target="_blank"
            class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg font-medium transition-colors inline-block"
          >
            Download Desktop App
          </a>
        </div>
      {/if}

      <!-- Footer -->
      <footer class="text-center text-zinc-500 text-sm">
        <p>
          sshx - Secure Collaborative Terminal
          {#if isDesktopApp}(Desktop){/if}
        </p>
        <p class="mt-1">
          <a
            href="https://github.com/ekzhang/sshx"
            target="_blank"
            class="hover:text-zinc-300"
          >
            Open Source on GitHub
          </a>
        </p>
      </footer>
    </div>
  </main>
{/if}

<style>
  :global(body) {
    margin: 0;
    padding: 0;
    background-color: #18181b;
  }
</style>
