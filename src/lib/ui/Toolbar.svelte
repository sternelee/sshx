<script lang="ts">
  import { createEventDispatcher } from "svelte";
  import {
    MessageSquareIcon,
    PlusCircleIcon,
    SettingsIcon,
    WifiIcon,
    ChevronDownIcon,
    HomeIcon,
    ExternalLinkIcon,
  } from "svelte-feather-icons";

  import logo from "$lib/assets/logo.svg";
  import { user, userSessions, authService } from "$lib/auth";
  import { onMount } from "svelte";

  export let connected: boolean;
  export let hasWriteAccess: boolean | undefined;
  export let newMessages: boolean;
  export let currentSessionId: string = '';

  let showSessionDropdown = false;
  let dropdownElement: HTMLDivElement;

  const dispatch = createEventDispatcher<{
    create: void;
    chat: void;
    settings: void;
    networkInfo: void;
    switchSession: { sessionId: string };
  }>();

  onMount(async () => {
    // 如果用户已登录，加载会话列表
    if ($user) {
      try {
        await authService.getUserSessions($user.token);
      } catch (error) {
        console.error('Failed to load user sessions:', error);
      }
    }

    // 点击外部关闭下拉菜单
    function handleClickOutside(event: MouseEvent) {
      if (dropdownElement && !dropdownElement.contains(event.target as Node)) {
        showSessionDropdown = false;
      }
    }

    document.addEventListener('click', handleClickOutside);
    return () => {
      document.removeEventListener('click', handleClickOutside);
    };
  });

  function switchToSession(sessionId: string) {
    dispatch('switchSession', { sessionId });
    showSessionDropdown = false;
  }

  function goToHome() {
    window.location.href = '/home';
  }

  function formatSessionName(name: string) {
    // 简化会话名称显示
    if (name.startsWith('user-')) {
      const parts = name.split('-');
      if (parts.length >= 3) {
        return `${parts[1].slice(0, 8)}...${parts[2]}`;
      }
    }
    return name.length > 20 ? name.slice(0, 20) + '...' : name;
  }

  function formatDate(timestamp: number) {
    const now = Date.now();
    const diff = now - timestamp;
    const minutes = Math.floor(diff / 60000);
    const hours = Math.floor(diff / 3600000);
    const days = Math.floor(diff / 86400000);

    if (minutes < 1) return '刚刚';
    if (minutes < 60) return `${minutes}分钟前`;
    if (hours < 24) return `${hours}小时前`;
    return `${days}天前`;
  }
</script>

<div class="panel inline-block px-3 py-2">
  <div class="flex items-center select-none">
    <a href="/" class="flex-shrink-0"
      ><img src={logo} alt="sshx logo" class="h-10" /></a
    >
    <p class="ml-1.5 mr-2 font-medium">sshx</p>

    <!-- 会话切换器（仅在用户登录时显示） -->
    {#if $user && $userSessions.length > 0}
      <div class="relative" bind:this={dropdownElement}>
        <button
          class="flex items-center space-x-2 px-3 py-1 rounded-md hover:bg-zinc-700 transition-colors"
          on:click={() => showSessionDropdown = !showSessionDropdown}
        >
          <span class="text-sm text-zinc-300">
            {currentSessionId ? formatSessionName(currentSessionId) : '选择会话'}
          </span>
          <ChevronDownIcon size="14" class="text-zinc-400" />
        </button>

        {#if showSessionDropdown}
          <div class="absolute top-full left-0 mt-1 w-80 bg-zinc-800 border border-zinc-600 rounded-md shadow-lg z-50 max-h-64 overflow-y-auto">
            <!-- 控制台链接 -->
            <button
              class="w-full flex items-center space-x-3 px-4 py-3 hover:bg-zinc-700 transition-colors border-b border-zinc-600"
              on:click={goToHome}
            >
              <HomeIcon size="16" class="text-zinc-400" />
              <div class="flex-1 text-left">
                <div class="text-sm font-medium text-zinc-200">返回控制台</div>
                <div class="text-xs text-zinc-400">管理 API Keys 和会话</div>
              </div>
            </button>

            <!-- 会话列表 -->
            {#each $userSessions as session (session.name)}
              <button
                class="w-full flex items-center space-x-3 px-4 py-3 hover:bg-zinc-700 transition-colors {currentSessionId === session.name ? 'bg-zinc-700' : ''}"
                on:click={() => switchToSession(session.name)}
              >
                <ExternalLinkIcon size="16" class="text-zinc-400" />
                <div class="flex-1 text-left">
                  <div class="text-sm font-medium text-zinc-200 font-mono">
                    {formatSessionName(session.name)}
                  </div>
                  <div class="text-xs text-zinc-400">
                    创建于 {formatDate(session.created_at)}
                  </div>
                </div>
                {#if currentSessionId === session.name}
                  <div class="w-2 h-2 bg-green-400 rounded-full"></div>
                {/if}
              </button>
            {/each}

            {#if $userSessions.length === 0}
              <div class="px-4 py-6 text-center text-zinc-400 text-sm">
                <ExternalLinkIcon size="24" class="mx-auto mb-2 opacity-50" />
                <p>暂无活跃会话</p>
                <p class="text-xs">使用 API Key 创建新会话</p>
              </div>
            {/if}
          </div>
        {/if}
      </div>
    {/if}

    <div class="v-divider" />

    <div class="flex space-x-1">
      <button
        class="icon-button"
        on:click={() => dispatch("create")}
        disabled={!connected || !hasWriteAccess}
        title={!connected
          ? "Not connected"
          : hasWriteAccess === false // Only show the "No write access" title after confirming read-only mode.
          ? "No write access"
          : "Create new terminal"}
      >
        <PlusCircleIcon strokeWidth={1.5} class="p-0.5" />
      </button>
      <button class="icon-button" on:click={() => dispatch("chat")}>
        <MessageSquareIcon strokeWidth={1.5} class="p-0.5" />
        {#if newMessages}
          <div class="activity" />
        {/if}
      </button>
      <button class="icon-button" on:click={() => dispatch("settings")}>
        <SettingsIcon strokeWidth={1.5} class="p-0.5" />
      </button>
    </div>

    <div class="v-divider" />

    <div class="flex space-x-1">
      <button class="icon-button" on:click={() => dispatch("networkInfo")}>
        <WifiIcon strokeWidth={1.5} class="p-0.5" />
      </button>
    </div>
  </div>
</div>

<style lang="postcss">
  .v-divider {
    @apply h-5 mx-2 border-l-4 border-zinc-800;
  }

  .icon-button {
    @apply relative rounded-md p-1 hover:bg-zinc-700 active:bg-indigo-700 transition-colors;
    @apply disabled:opacity-50 disabled:bg-transparent;
  }

  .activity {
    @apply absolute top-1 right-0.5 text-xs p-[4.5px] bg-red-500 rounded-full;
  }
</style>
