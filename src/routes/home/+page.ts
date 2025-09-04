import { browser } from '$app/environment';
import { redirect } from '@sveltejs/kit';

export async function load() {
  // 在客户端检查用户登录状态
  if (browser) {
    const stored = localStorage.getItem('sshx_user');
    if (!stored) {
      throw redirect(302, '/');
    }
  }

  return {};
}