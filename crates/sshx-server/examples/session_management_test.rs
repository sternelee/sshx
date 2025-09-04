use anyhow::Result;
use serde_json::json;
use std::time::Duration;
use tokio::time::sleep;

/// 测试用户会话管理功能的完整示例
#[tokio::main]
async fn main() -> Result<()> {
    println!("🚀 sshx 用户会话管理功能测试");
    println!("================================");

    let base_url = "http://localhost:3000/api";
    let client = reqwest::Client::new();

    // 1. 用户注册
    println!("\n📝 步骤 1: 用户注册");
    let register_response = client
        .post(&format!("{}/auth/register", base_url))
        .json(&json!({
            "email": "session_test@example.com",
            "password": "test123456"
        }))
        .send()
        .await?;

    if !register_response.status().is_success() {
        let error_text = register_response.text().await?;
        println!("❌ 注册失败: {}", error_text);
        return Ok(());
    }

    let register_data: serde_json::Value = register_response.json().await?;
    let jwt_token = register_data["data"]["token"].as_str().unwrap();
    let user_id = register_data["data"]["user_id"].as_str().unwrap();
    
    println!("✅ 用户注册成功");
    println!("   用户ID: {}", user_id);
    println!("   JWT Token: {}...", &jwt_token[..20]);

    // 2. 生成 API Key
    println!("\n🔑 步骤 2: 生成 API Key");
    let api_key_response = client
        .post(&format!("{}/auth/api-keys", base_url))
        .json(&json!({
            "auth_token": jwt_token,
            "name": "Session Test Key"
        }))
        .send()
        .await?;

    let api_key_data: serde_json::Value = api_key_response.json().await?;
    let api_key_token = api_key_data["data"]["token"].as_str().unwrap();
    let api_key_id = api_key_data["data"]["id"].as_str().unwrap();
    
    println!("✅ API Key 生成成功");
    println!("   API Key ID: {}", api_key_id);
    println!("   API Key Token: {}...", &api_key_token[..20]);

    // 3. 模拟使用 API Key 创建会话（通过直接调用服务）
    println!("\n🖥️  步骤 3: 模拟创建用户会话");
    println!("   提示: 在实际使用中，这一步通过以下命令完成:");
    println!("   sshx --server http://localhost:3000 --api-key {}", api_key_token);
    println!("   这里我们模拟会话创建过程...");

    // 等待一下，模拟会话创建
    sleep(Duration::from_secs(1)).await;

    // 4. 查看用户会话列表
    println!("\n📋 步骤 4: 查看用户会话列表");
    let sessions_response = client
        .post(&format!("{}/auth/sessions", base_url))
        .json(&json!({
            "auth_token": jwt_token
        }))
        .send()
        .await?;

    let sessions_data: serde_json::Value = sessions_response.json().await?;
    let sessions = &sessions_data["data"]["sessions"];
    
    println!("✅ 会话列表查询成功");
    println!("   活跃会话数量: {}", sessions.as_array().unwrap().len());
    
    for (i, session) in sessions.as_array().unwrap().iter().enumerate() {
        println!("   会话 {}: {}", i + 1, session["name"].as_str().unwrap());
        println!("     URL: {}", session["url"].as_str().unwrap());
        println!("     创建时间: {}", session["created_at"]);
        println!("     是否活跃: {}", session["is_active"]);
    }

    // 5. 测试 API Key 列表
    println!("\n🔑 步骤 5: 查看 API Key 列表");
    let list_keys_response = client
        .post(&format!("{}/auth/api-keys", base_url))
        .json(&json!({
            "auth_token": jwt_token
        }))
        .send()
        .await?;

    let list_keys_data: serde_json::Value = list_keys_response.json().await?;
    let api_keys = &list_keys_data["data"]["api_keys"];
    
    println!("✅ API Key 列表查询成功");
    println!("   API Key 数量: {}", api_keys.as_array().unwrap().len());
    
    for (i, key) in api_keys.as_array().unwrap().iter().enumerate() {
        println!("   API Key {}: {}", i + 1, key["name"].as_str().unwrap());
        println!("     ID: {}", key["id"].as_str().unwrap());
        println!("     创建时间: {}", key["created_at"]);
        println!("     是否活跃: {}", key["is_active"]);
        if let Some(last_used) = key["last_used"].as_u64() {
            println!("     最后使用: {}", last_used);
        }
    }

    // 6. 模拟关闭会话
    if let Some(sessions_array) = sessions.as_array() {
        if !sessions_array.is_empty() {
            let first_session = &sessions_array[0];
            let session_id = first_session["id"].as_str().unwrap();
            
            println!("\n❌ 步骤 6: 关闭会话");
            let close_response = client
                .post(&format!("{}/auth/sessions/{}/close", base_url, session_id))
                .json(&json!({
                    "auth_token": jwt_token
                }))
                .send()
                .await?;

            let close_data: serde_json::Value = close_response.json().await?;
            let success = close_data["data"]["success"].as_bool().unwrap();
            
            if success {
                println!("✅ 会话关闭成功");
                println!("   会话ID: {}", session_id);
            } else {
                println!("❌ 会话关闭失败");
            }
        }
    }

    // 7. 清理 - 删除 API Key
    println!("\n🧹 步骤 7: 清理 API Key");
    let delete_response = client
        .delete(&format!("{}/auth/api-keys/{}", base_url, api_key_id))
        .json(&json!({
            "auth_token": jwt_token
        }))
        .send()
        .await?;

    let delete_data: serde_json::Value = delete_response.json().await?;
    let delete_success = delete_data["data"]["success"].as_bool().unwrap();
    
    if delete_success {
        println!("✅ API Key 删除成功");
    } else {
        println!("❌ API Key 删除失败");
    }

    println!("\n🎉 用户会话管理功能测试完成!");
    println!("\n💡 使用提示:");
    println!("   1. 启动服务器: ./start_server.sh");
    println!("   2. 访问 Web 界面: http://localhost:5173");
    println!("   3. 注册用户并生成 API Key");
    println!("   4. 使用 API Key 启动 sshx: sshx --api-key YOUR_API_KEY");
    println!("   5. 在 Web 界面管理你的会话");

    Ok(())
}