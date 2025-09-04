import { writable } from 'svelte/store';
import { browser } from '$app/environment';
import { makeGrpcCall } from './grpc-proxy';

export interface User {
  id: string;
  email: string;
  token: string;
}

export interface ApiKey {
  id: string;
  name: string;
  created_at: number;
  last_used?: number;
  is_active: boolean;
}

export interface UserSession {
  id: string;
  name: string;
  url: string;
  user_id: string;
  api_key_id?: string;
  created_at: number;
  last_activity: number;
  is_active: boolean;
  metadata?: string;
}

// 用户状态存储
export const user = writable<User | null>(null);
export const apiKeys = writable<ApiKey[]>([]);
export const userSessions = writable<UserSession[]>([]);

// API 基础 URL
const API_BASE_URL = import.meta.env.DEV
  ? 'http://localhost:3000/api'
  : '/api';

class AuthService {
  private async makeApiRequest(endpoint: string, data: any) {
    const response = await fetch(`${API_BASE_URL}${endpoint}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(data),
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({ error: 'Unknown error' }));
      throw new Error(errorData.error || `HTTP error! status: ${response.status}`);
    }

    const result = await response.json();
    return result.data; // Extract data from SuccessResponse wrapper
  }

  private async makeApiGetRequest(endpoint: string, authToken: string) {
    const response = await fetch(`${API_BASE_URL}${endpoint}`, {
      method: 'POST', // Using POST for auth token in body
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ auth_token: authToken }),
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({ error: 'Unknown error' }));
      throw new Error(errorData.error || `HTTP error! status: ${response.status}`);
    }

    const result = await response.json();
    return result.data;
  }

  private async makeApiDeleteRequest(endpoint: string, authToken: string) {
    const response = await fetch(`${API_BASE_URL}${endpoint}`, {
      method: 'DELETE',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ auth_token: authToken }),
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({ error: 'Unknown error' }));
      throw new Error(errorData.error || `HTTP error! status: ${response.status}`);
    }

    const result = await response.json();
    return result.data;
  }

  async register(email: string, password: string): Promise<User> {
    try {
      const response = await this.makeApiRequest('/auth/register', {
        email,
        password,
      });

      const userData: User = {
        id: response.user_id,
        email: response.email,
        token: response.token,
      };

      // 保存到本地存储
      if (browser) {
        localStorage.setItem('sshx_user', JSON.stringify(userData));
      }

      user.set(userData);
      return userData;
    } catch (error) {
      console.error('Registration failed:', error);
      throw error;
    }
  }

  async login(email: string, password: string): Promise<User> {
    try {
      const response = await this.makeApiRequest('/auth/login', {
        email,
        password,
      });

      const userData: User = {
        id: response.user_id,
        email: response.email,
        token: response.token,
      };

      // 保存到本地存储
      if (browser) {
        localStorage.setItem('sshx_user', JSON.stringify(userData));
      }

      user.set(userData);
      return userData;
    } catch (error) {
      console.error('Login failed:', error);
      throw error;
    }
  }

  async logout() {
    if (browser) {
      localStorage.removeItem('sshx_user');
    }
    user.set(null);
    apiKeys.set([]);
    userSessions.set([]);
  }

  async generateApiKey(name: string, authToken: string): Promise<ApiKey> {
    try {
      const response = await this.makeApiRequest('/auth/api-keys', {
        auth_token: authToken,
        name,
      });

      const newApiKey: ApiKey = {
        id: response.id,
        name: response.name,
        created_at: response.created_at,
        is_active: true,
      };

      // 更新 API keys 列表
      apiKeys.update(keys => [...keys, newApiKey]);

      return newApiKey;
    } catch (error) {
      console.error('API key generation failed:', error);
      throw error;
    }
  }

  async listApiKeys(authToken: string): Promise<ApiKey[]> {
    try {
      const response = await this.makeApiGetRequest('/auth/api-keys', authToken);

      const keys: ApiKey[] = response.api_keys || [];
      apiKeys.set(keys);
      return keys;
    } catch (error) {
      console.error('Failed to list API keys:', error);
      throw error;
    }
  }

  async deleteApiKey(apiKeyId: string, authToken: string): Promise<boolean> {
    try {
      const response = await this.makeApiDeleteRequest(`/auth/api-keys/${apiKeyId}`, authToken);

      if (response.success) {
        // 从列表中移除已删除的 API key
        apiKeys.update(keys => keys.filter(key => key.id !== apiKeyId));
      }

      return response.success;
    } catch (error) {
      console.error('Failed to delete API key:', error);
      throw error;
    }
  }

  // 从本地存储恢复用户状态
  restoreUser(): User | null {
    if (!browser) return null;

    try {
      const stored = localStorage.getItem('sshx_user');
      if (stored) {
        const userData = JSON.parse(stored);
        user.set(userData);
        return userData;
      }
    } catch (error) {
      console.error('Failed to restore user from localStorage:', error);
    }

    return null;
  }

  // 获取用户会话列表
  async getUserSessions(authToken: string): Promise<UserSession[]> {
    try {
      const response = await this.makeApiGetRequest('/auth/sessions', authToken);

      const sessions: UserSession[] = response.sessions.map((session: any) => ({
        id: session.id,
        name: session.name,
        url: session.url,
        user_id: session.user_id,
        api_key_id: session.api_key_id,
        created_at: session.created_at,
        last_activity: session.last_activity,
        is_active: session.is_active,
        metadata: session.metadata,
      }));

      userSessions.set(sessions);
      return sessions;
    } catch (error) {
      console.error('Failed to get user sessions:', error);
      // 返回空数组而不是抛出错误，以便 UI 可以正常显示
      userSessions.set([]);
      return [];
    }
  }

  // 关闭用户会话
  async closeUserSession(sessionId: string, authToken: string): Promise<boolean> {
    try {
      const response = await fetch(`${API_BASE_URL}/auth/sessions/${sessionId}/close`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ auth_token: authToken }),
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({ error: 'Unknown error' }));
        throw new Error(errorData.error || `HTTP error! status: ${response.status}`);
      }

      const result = await response.json();

      if (result.data.success) {
        // 从列表中移除已关闭的会话
        userSessions.update(sessions =>
          sessions.map(session =>
            session.id === sessionId
              ? { ...session, is_active: false }
              : session
          )
        );
      }

      return result.data.success;
    } catch (error) {
      console.error('Failed to close session:', error);
      throw error;
    }
  }
}

export const authService = new AuthService();