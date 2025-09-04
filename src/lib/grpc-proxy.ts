// 简单的 gRPC 代理服务，将 HTTP 请求转换为 gRPC 调用
// 这个文件应该在服务器端运行，或者你可以使用 grpc-web 代理

export interface GrpcRequest {
  method: string;
  data: any;
}

export interface GrpcResponse {
  success: boolean;
  data?: any;
  error?: string;
}

// 模拟的 gRPC 响应，实际应该连接到真实的 gRPC 服务
export async function makeGrpcCall(method: string, data: any): Promise<any> {
  // 这里应该实际调用 gRPC 服务
  // 目前返回模拟数据用于开发

  switch (method) {
    case 'sshx.SshxService/Register':
      // 模拟注册响应
      return {
        token: 'mock_jwt_token_' + Date.now(),
        user_id: 'user_' + Math.random().toString(36).substr(2, 9),
        email: data.email,
      };

    case 'sshx.SshxService/Login':
      // 模拟登录响应
      return {
        token: 'mock_jwt_token_' + Date.now(),
        user_id: 'user_' + Math.random().toString(36).substr(2, 9),
        email: data.email,
      };

    case 'sshx.SshxService/GenerateApiKey':
      // 模拟 API Key 生成响应
      return {
        id: 'api_key_' + Math.random().toString(36).substr(2, 9),
        name: data.name,
        token: 'ak_' + Math.random().toString(36).substr(2, 32),
        created_at: Math.floor(Date.now() / 1000),
        user_id: 'user_123',
      };

    case 'sshx.SshxService/ListApiKeys':
      // 模拟 API Keys 列表响应
      return {
        api_keys: [
          {
            id: 'api_key_1',
            name: '开发环境密钥',
            created_at: Math.floor(Date.now() / 1000) - 86400,
            last_used: Math.floor(Date.now() / 1000) - 3600,
            is_active: true,
          },
          {
            id: 'api_key_2',
            name: '生产环境密钥',
            created_at: Math.floor(Date.now() / 1000) - 172800,
            is_active: true,
          },
        ],
      };

    case 'sshx.SshxService/DeleteApiKey':
      // 模拟删除 API Key 响应
      return {
        success: true,
      };

    default:
      throw new Error(`Unknown method: ${method}`);
  }
}