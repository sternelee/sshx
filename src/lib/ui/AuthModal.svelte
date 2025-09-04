<script lang="ts">
  import { createEventDispatcher } from 'svelte';
  import { XIcon, UserIcon, MailIcon, LockIcon } from 'svelte-feather-icons';
  import { authService } from '$lib/auth';

  export let isOpen = false;

  const dispatch = createEventDispatcher<{
    close: void;
    success: { user: any };
  }>();

  let isLogin = true;
  let email = '';
  let password = '';
  let confirmPassword = '';
  let loading = false;
  let error = '';

  function toggleMode() {
    isLogin = !isLogin;
    error = '';
    password = '';
    confirmPassword = '';
  }

  function closeModal() {
    isOpen = false;
    dispatch('close');
    resetForm();
  }

  function resetForm() {
    email = '';
    password = '';
    confirmPassword = '';
    error = '';
    loading = false;
  }

  async function handleSubmit() {
    if (loading) return;

    error = '';

    // 基本验证
    if (!email || !password) {
      error = '请填写所有必填字段';
      return;
    }

    if (!isLogin && password !== confirmPassword) {
      error = '密码确认不匹配';
      return;
    }

    if (password.length < 6) {
      error = '密码至少需要6个字符';
      return;
    }

    loading = true;

    try {
      let user;
      if (isLogin) {
        user = await authService.login(email, password);
      } else {
        user = await authService.register(email, password);
      }

      dispatch('success', { user });
      closeModal();
    } catch (err: any) {
      error = err.message || (isLogin ? '登录失败' : '注册失败');
    } finally {
      loading = false;
    }
  }

  function handleKeydown(event: KeyboardEvent) {
    if (event.key === 'Escape') {
      closeModal();
    } else if (event.key === 'Enter') {
      handleSubmit();
    }
  }
</script>

{#if isOpen}
  <!-- 背景遮罩 -->
  <div 
    class="fixed inset-0 bg-black/50 backdrop-blur-sm z-50 flex items-center justify-center p-4"
    on:click={closeModal}
    on:keydown={handleKeydown}
    role="dialog"
    aria-modal="true"
  >
    <!-- 模态框内容 -->
    <div 
      class="bg-zinc-900 border border-zinc-700 rounded-lg shadow-xl max-w-md w-full p-6"
      on:click|stopPropagation
      on:keydown|stopPropagation
      role="dialog"
      tabindex="-1"
    >
      <!-- 头部 -->
      <div class="flex items-center justify-between mb-6">
        <div class="flex items-center space-x-2">
          <UserIcon size="20" class="text-zinc-400" />
          <h2 class="text-xl font-semibold text-zinc-100">
            {isLogin ? '登录' : '注册'} sshx
          </h2>
        </div>
        <button
          class="text-zinc-400 hover:text-zinc-200 transition-colors"
          on:click={closeModal}
        >
          <XIcon size="20" />
        </button>
      </div>

      <!-- 表单 -->
      <form on:submit|preventDefault={handleSubmit} class="space-y-4">
        <!-- 邮箱输入 -->
        <div>
          <label for="email" class="block text-sm font-medium text-zinc-300 mb-2">
            邮箱地址
          </label>
          <div class="relative">
            <MailIcon size="16" class="absolute left-3 top-1/2 transform -translate-y-1/2 text-zinc-400" />
            <input
              id="email"
              type="email"
              bind:value={email}
              placeholder="your@email.com"
              class="w-full pl-10 pr-4 py-2 bg-zinc-800 border border-zinc-600 rounded-md text-zinc-100 placeholder-zinc-400 focus:outline-none focus:ring-2 focus:ring-pink-500 focus:border-transparent"
              required
            />
          </div>
        </div>

        <!-- 密码输入 -->
        <div>
          <label for="password" class="block text-sm font-medium text-zinc-300 mb-2">
            密码
          </label>
          <div class="relative">
            <LockIcon size="16" class="absolute left-3 top-1/2 transform -translate-y-1/2 text-zinc-400" />
            <input
              id="password"
              type="password"
              bind:value={password}
              placeholder="至少6个字符"
              class="w-full pl-10 pr-4 py-2 bg-zinc-800 border border-zinc-600 rounded-md text-zinc-100 placeholder-zinc-400 focus:outline-none focus:ring-2 focus:ring-pink-500 focus:border-transparent"
              required
            />
          </div>
        </div>

        <!-- 确认密码输入（仅注册时显示） -->
        {#if !isLogin}
          <div>
            <label for="confirmPassword" class="block text-sm font-medium text-zinc-300 mb-2">
              确认密码
            </label>
            <div class="relative">
              <LockIcon size="16" class="absolute left-3 top-1/2 transform -translate-y-1/2 text-zinc-400" />
              <input
                id="confirmPassword"
                type="password"
                bind:value={confirmPassword}
                placeholder="再次输入密码"
                class="w-full pl-10 pr-4 py-2 bg-zinc-800 border border-zinc-600 rounded-md text-zinc-100 placeholder-zinc-400 focus:outline-none focus:ring-2 focus:ring-pink-500 focus:border-transparent"
                required
              />
            </div>
          </div>
        {/if}

        <!-- 错误信息 -->
        {#if error}
          <div class="text-red-400 text-sm bg-red-900/20 border border-red-800 rounded-md p-3">
            {error}
          </div>
        {/if}

        <!-- 提交按钮 -->
        <button
          type="submit"
          disabled={loading}
          class="w-full bg-pink-700 hover:bg-pink-600 disabled:bg-pink-800 disabled:opacity-50 text-white font-medium py-2 px-4 rounded-md transition-colors focus:outline-none focus:ring-2 focus:ring-pink-500 focus:ring-offset-2 focus:ring-offset-zinc-900"
        >
          {#if loading}
            <div class="flex items-center justify-center space-x-2">
              <div class="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin"></div>
              <span>{isLogin ? '登录中...' : '注册中...'}</span>
            </div>
          {:else}
            {isLogin ? '登录' : '注册'}
          {/if}
        </button>

        <!-- 切换模式 -->
        <div class="text-center text-sm text-zinc-400">
          {isLogin ? '还没有账户？' : '已有账户？'}
          <button
            type="button"
            class="text-pink-400 hover:text-pink-300 font-medium ml-1"
            on:click={toggleMode}
          >
            {isLogin ? '立即注册' : '立即登录'}
          </button>
        </div>
      </form>
    </div>
  </div>
{/if}

<style lang="postcss">
  /* 确保模态框在最顶层 */
  :global(body:has(.modal-open)) {
    overflow: hidden;
  }
</style>