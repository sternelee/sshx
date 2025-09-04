<script lang="ts">
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import { user, apiKeys, userSessions, authService } from '$lib/auth';
  import Session from '$lib/Session.svelte';
  import { 
    PlusIcon, 
    KeyIcon, 
    TrashIcon, 
    ExternalLinkIcon,
    CopyIcon,
    RefreshCwIcon 
  } from 'svelte-feather-icons';

  let currentSessionId = '';
  let showApiKeyModal = false;
  let newApiKeyName = '';
  let loading = false;
  let error = '';
  let copySuccess = '';

  // 检查用户登录状态
  onMount(async () => {
    const currentUser = authService.restoreUser();
    if (!currentUser) {
      goto('/');
      return;
    }

    // 加载用户数据
    await loadUserData();
  });

  async function loadUserData() {
    if (!$user) return;

    try {
      loading = true;
      await Promise.all([
        authService.listApiKeys($user.token),
        authService.getUserSessions($user.token)
      ]);
    } catch (err: any) {
      error = '加载数据失败: ' + err.message;
    } finally {
      loading = false;
    }
  }

  async function createApiKey() {
    if (!$user || !newApiKeyName.trim()) return;

    try {
      loading = true;
      error = '';
      await authService.generateApiKey(newApiKeyName.trim(), $user.token);
      newApiKeyName = '';
      showApiKeyModal = false;
    } catch (err: any) {
      error = '创建 API Key 失败: ' + err.message;
    } finally {
      loading = false;
    }
  }

  async function deleteApiKey(apiKeyId: string) {
    if (!$user || !confirm('确定要删除这个 API Key 吗？')) return;

    try {
      loading = true;
      await authService.deleteApiKey(apiKeyId, $user.token);
    } catch (err: any) {
      error = '删除 API Key 失败: ' + err.message;
    } finally {
      loading = false;
    }
  }

  async function closeSession(sessionId: string) {
    if (!$user || !confirm('确定要关闭这个会话吗？')) return;

    try {
      loading = true;
      await authService.closeUserSession(sessionId, $user.token);
      // 刷新会话列表
      await authService.getUserSessions($user.token);
    } catch (err: any) {
      error = '关闭会话失败: ' + err.message;
    } finally {
      loading = false;
    }
  }

  function joinSession(sessionName: string) {
    currentSessionId = sessionName;
  }

  function copyToClipboard(text: string, type: string) {
    navigator.clipboard.writeText(text).then(() => {
      copySuccess = `${type} 已复制到剪贴板`;
      setTimeout(() => copySuccess = '', 2000);
    });
  }

  function formatDate(timestamp: number) {
    return new Date(timestamp).toLocaleString('zh-CN');
  }

  function handleLogout() {
    authService.logout();
    goto('/');
  }
</script>

<svelte:head>
  <title>sshx 控制台</title>
</svelte:head>

{#if currentSessionId}
  <!-- 会话视图 -->
  <Session 
    id={currentSessionId}
    on:receiveName={({ detail: sessionName }) => {
      if (sessionName) {
        document.title = `${sessionName} | sshx`;
      }
    }}
  />
{:else}
  <!-- 控制台视图 -->
  <div class="min-h-screen bg-zinc-950 text-zinc-100">
    <!-- 顶部导航 -->
    <nav class="border-b border-zinc-800 bg-zinc-900/50 backdrop-blur">
      <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div class="flex items-center justify-between h-16">
          <div class="flex items-center space-x-4">
            <h1 class="text-xl font-semibold">sshx 控制台</h1>
            {#if $user}
              <span class="text-zinc-400 text-sm">欢迎, {$user.email}</span>
            {/if}
          </div>
          
          <div class="flex items-center space-x-3">
            <button
              class="flex items-center space-x-2 text-zinc-400 hover:text-zinc-200 px-3 py-2 rounded-md transition-colors"
              on:click={loadUserData}
              disabled={loading}
            >
              <RefreshCwIcon size="16" class={loading ? 'animate-spin' : ''} />
              <span>刷新</span>
            </button>
            
            <button
              class="text-zinc-400 hover:text-zinc-200 px-3 py-2 rounded-md transition-colors"
              on:click={() => goto('/')}
            >
              返回首页
            </button>
            
            <button
              class="text-zinc-400 hover:text-zinc-200 px-3 py-2 rounded-md transition-colors"
              on:click={handleLogout}
            >
              退出登录
            </button>
          </div>
        </div>
      </div>
    </nav>

    <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <!-- 错误提示 -->
      {#if error}
        <div class="mb-6 bg-red-900/20 border border-red-800 text-red-400 px-4 py-3 rounded-md">
          {error}
        </div>
      {/if}

      <!-- 成功提示 -->
      {#if copySuccess}
        <div class="mb-6 bg-green-900/20 border border-green-800 text-green-400 px-4 py-3 rounded-md">
          {copySuccess}
        </div>
      {/if}

      <div class="grid lg:grid-cols-2 gap-8">
        <!-- API Keys 管理 -->
        <div class="bg-zinc-900 border border-zinc-800 rounded-lg p-6">
          <div class="flex items-center justify-between mb-6">
            <h2 class="text-lg font-semibold flex items-center space-x-2">
              <KeyIcon size="20" />
              <span>API Keys</span>
            </h2>
            <button
              class="flex items-center space-x-2 bg-pink-700 hover:bg-pink-600 text-white px-3 py-2 rounded-md transition-colors"
              on:click={() => showApiKeyModal = true}
              disabled={loading}
            >
              <PlusIcon size="16" />
              <span>新建</span>
            </button>
          </div>

          <div class="space-y-3">
            {#each $apiKeys as apiKey (apiKey.id)}
              <div class="bg-zinc-800 border border-zinc-700 rounded-md p-4">
                <div class="flex items-center justify-between mb-2">
                  <h3 class="font-medium">{apiKey.name}</h3>
                  <button
                    class="text-red-400 hover:text-red-300 p-1 rounded transition-colors"
                    on:click={() => deleteApiKey(apiKey.id)}
                    disabled={loading}
                    title="删除 API Key"
                  >
                    <TrashIcon size="16" />
                  </button>
                </div>
                
                <div class="text-sm text-zinc-400 space-y-1">
                  <p>创建时间: {formatDate(apiKey.created_at * 1000)}</p>
                  {#if apiKey.last_used}
                    <p>最后使用: {formatDate(apiKey.last_used * 1000)}</p>
                  {:else}
                    <p>从未使用</p>
                  {/if}
                  <p class="flex items-center space-x-2">
                    <span>状态:</span>
                    <span class={apiKey.is_active ? 'text-green-400' : 'text-red-400'}>
                      {apiKey.is_active ? '激活' : '停用'}
                    </span>
                  </p>
                </div>

                <div class="mt-3 pt-3 border-t border-zinc-700">
                  <p class="text-xs text-zinc-500 mb-2">使用此 API Key 运行 sshx:</p>
                  <div class="bg-zinc-950 border border-zinc-600 rounded p-2 text-xs font-mono">
                    <div class="flex items-center justify-between">
                      <code class="text-zinc-300">export SSHX_API_KEY="{apiKey.id}..."</code>
                      <button
                        class="text-zinc-400 hover:text-zinc-200 ml-2"
                        on:click={() => copyToClipboard(`export SSHX_API_KEY="${apiKey.id}"`, 'API Key')}
                        title="复制到剪贴板"
                      >
                        <CopyIcon size="14" />
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            {:else}
              <div class="text-center text-zinc-400 py-8">
                <KeyIcon size="48" class="mx-auto mb-4 opacity-50" />
                <p>还没有 API Key</p>
                <p class="text-sm">创建一个 API Key 来使用 sshx 客户端</p>
              </div>
            {/each}
          </div>
        </div>

        <!-- 用户会话 -->
        <div class="bg-zinc-900 border border-zinc-800 rounded-lg p-6">
          <h2 class="text-lg font-semibold mb-6 flex items-center space-x-2">
            <ExternalLinkIcon size="20" />
            <span>我的会话</span>
          </h2>

          <div class="space-y-3">
            {#each $userSessions as session (session.name)}
              <div class="bg-zinc-800 border border-zinc-700 rounded-md p-4">
                <div class="flex items-center justify-between mb-2">
                  <h3 class="font-medium font-mono text-sm">{session.name}</h3>
                  <div class="flex items-center space-x-2">
                    <button
                      class="flex items-center space-x-1 text-pink-400 hover:text-pink-300 text-sm transition-colors"
                      on:click={() => joinSession(session.name)}
                    >
                      <ExternalLinkIcon size="14" />
                      <span>进入</span>
                    </button>
                    {#if session.is_active}
                      <button
                        class="text-red-400 hover:text-red-300 p-1 rounded transition-colors"
                        on:click={() => closeSession(session.id)}
                        disabled={loading}
                        title="关闭会话"
                      >
                        <TrashIcon size="14" />
                      </button>
                    {/if}
                  </div>
                </div>
                
                <div class="text-sm text-zinc-400 space-y-1">
                  <p>创建时间: {formatDate(session.created_at)}</p>
                  <p>最后活动: {formatDate(session.last_activity)}</p>
                  <p class="flex items-center space-x-2">
                    <span>状态:</span>
                    <span class={session.is_active ? 'text-green-400' : 'text-zinc-500'}>
                      {session.is_active ? '活跃' : '已关闭'}
                    </span>
                  </p>
                  <div class="flex items-center space-x-2">
                    <span>会话链接:</span>
                    <button
                      class="text-zinc-300 hover:text-zinc-100 underline truncate max-w-xs"
                      on:click={() => copyToClipboard(session.url, '会话链接')}
                      title="点击复制链接"
                    >
                      {session.url}
                    </button>
                  </div>
                </div>
              </div>
            {:else}
              <div class="text-center text-zinc-400 py-8">
                <ExternalLinkIcon size="48" class="mx-auto mb-4 opacity-50" />
                <p>还没有活跃会话</p>
                <p class="text-sm">使用 API Key 运行 sshx 客户端来创建会话</p>
              </div>
            {/each}
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- API Key 创建模态框 -->
  {#if showApiKeyModal}
    <div class="fixed inset-0 bg-black/50 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div class="bg-zinc-900 border border-zinc-700 rounded-lg shadow-xl max-w-md w-full p-6">
        <h3 class="text-lg font-semibold mb-4">创建新的 API Key</h3>
        
        <form on:submit|preventDefault={createApiKey} class="space-y-4">
          <div>
            <label for="apiKeyName" class="block text-sm font-medium text-zinc-300 mb-2">
              API Key 名称
            </label>
            <input
              id="apiKeyName"
              type="text"
              bind:value={newApiKeyName}
              placeholder="例如: 开发环境密钥"
              class="w-full px-3 py-2 bg-zinc-800 border border-zinc-600 rounded-md text-zinc-100 placeholder-zinc-400 focus:outline-none focus:ring-2 focus:ring-pink-500 focus:border-transparent"
              required
            />
          </div>

          <div class="flex space-x-3">
            <button
              type="submit"
              disabled={loading || !newApiKeyName.trim()}
              class="flex-1 bg-pink-700 hover:bg-pink-600 disabled:bg-pink-800 disabled:opacity-50 text-white font-medium py-2 px-4 rounded-md transition-colors"
            >
              {loading ? '创建中...' : '创建'}
            </button>
            <button
              type="button"
              class="flex-1 bg-zinc-700 hover:bg-zinc-600 text-zinc-200 font-medium py-2 px-4 rounded-md transition-colors"
              on:click={() => {
                showApiKeyModal = false;
                newApiKeyName = '';
              }}
            >
              取消
            </button>
          </div>
        </form>
      </div>
    </div>
  {/if}
{/if}