use anyhow::Result;
use reqwest::Client;
use serde_json::json;

#[tokio::main]
async fn main() -> Result<()> {
    println!("🌐 SSHX HTTP API Test");
    println!("====================");

    let client = Client::new();
    let base_url = "http://127.0.0.1:3000/api";

    // Test user registration
    println!("\n📝 Testing user registration...");
    let register_response = client
        .post(&format!("{}/auth/register", base_url))
        .json(&json!({
            "email": "test@example.com",
            "password": "test123456"
        }))
        .send()
        .await;

    let auth_token = match register_response {
        Ok(response) => {
            if response.status().is_success() {
                let data: serde_json::Value = response.json().await?;
                println!("✅ Registration successful!");
                println!("   User ID: {}", data["data"]["user_id"]);
                println!("   Email: {}", data["data"]["email"]);
                data["data"]["token"].as_str().unwrap().to_string()
            } else {
                println!("⚠️  Registration failed, trying login...");
                
                // Try login instead
                let login_response = client
                    .post(&format!("{}/auth/login", base_url))
                    .json(&json!({
                        "email": "test@example.com",
                        "password": "test123456"
                    }))
                    .send()
                    .await?;

                if login_response.status().is_success() {
                    let data: serde_json::Value = login_response.json().await?;
                    println!("✅ Login successful!");
                    println!("   User ID: {}", data["data"]["user_id"]);
                    println!("   Email: {}", data["data"]["email"]);
                    data["data"]["token"].as_str().unwrap().to_string()
                } else {
                    let error_text = login_response.text().await?;
                    println!("❌ Login failed: {}", error_text);
                    return Ok(());
                }
            }
        }
        Err(err) => {
            println!("❌ Connection failed: {}", err);
            println!("   Make sure the sshx-server is running on port 3000");
            return Ok(());
        }
    };

    // Test API key generation
    println!("\n🔑 Testing API key generation...");
    let api_key_response = client
        .post(&format!("{}/auth/api-keys", base_url))
        .json(&json!({
            "auth_token": auth_token,
            "name": "Test API Key"
        }))
        .send()
        .await?;

    let api_key_id = if api_key_response.status().is_success() {
        let data: serde_json::Value = api_key_response.json().await?;
        println!("✅ API key generated successfully!");
        println!("   ID: {}", data["data"]["id"]);
        println!("   Name: {}", data["data"]["name"]);
        println!("   Token: {}...", &data["data"]["token"].as_str().unwrap()[..20]);
        data["data"]["id"].as_str().unwrap().to_string()
    } else {
        let error_text = api_key_response.text().await?;
        println!("❌ API key generation failed: {}", error_text);
        return Ok(());
    };

    // Test API key listing
    println!("\n📋 Testing API key listing...");
    let list_response = client
        .post(&format!("{}/auth/api-keys", base_url)) // Using POST for auth token
        .json(&json!({
            "auth_token": auth_token
        }))
        .send()
        .await?;

    if list_response.status().is_success() {
        let data: serde_json::Value = list_response.json().await?;
        println!("✅ API keys listed successfully!");
        if let Some(api_keys) = data["data"]["api_keys"].as_array() {
            println!("   Found {} API key(s)", api_keys.len());
            for (i, key) in api_keys.iter().enumerate() {
                println!("   {}. ID: {}", i + 1, key["id"]);
                println!("      Name: {}", key["name"]);
                println!("      Active: {}", key["is_active"]);
            }
        }
    } else {
        let error_text = list_response.text().await?;
        println!("❌ API key listing failed: {}", error_text);
    }

    // Test user sessions
    println!("\n📱 Testing user sessions...");
    let sessions_response = client
        .post(&format!("{}/auth/sessions", base_url))
        .json(&json!({
            "auth_token": auth_token
        }))
        .send()
        .await?;

    if sessions_response.status().is_success() {
        let data: serde_json::Value = sessions_response.json().await?;
        println!("✅ User sessions retrieved successfully!");
        if let Some(sessions) = data["data"]["sessions"].as_array() {
            println!("   Found {} session(s)", sessions.len());
            for (i, session) in sessions.iter().enumerate() {
                println!("   {}. Name: {}", i + 1, session["name"]);
                println!("      URL: {}", session["url"]);
                println!("      Created: {}", session["created_at"]);
            }
        }
    } else {
        let error_text = sessions_response.text().await?;
        println!("❌ User sessions failed: {}", error_text);
    }

    // Test API key deletion
    println!("\n🗑️  Testing API key deletion...");
    let delete_response = client
        .delete(&format!("{}/auth/api-keys/{}", base_url, api_key_id))
        .json(&json!({
            "auth_token": auth_token
        }))
        .send()
        .await?;

    if delete_response.status().is_success() {
        let data: serde_json::Value = delete_response.json().await?;
        println!("✅ API key deleted successfully!");
        println!("   Success: {}", data["data"]["success"]);
    } else {
        let error_text = delete_response.text().await?;
        println!("❌ API key deletion failed: {}", error_text);
    }

    println!("\n🎉 HTTP API test completed!");
    println!("\n💡 Usage Instructions:");
    println!("   1. Start the sshx-server: cargo run --bin sshx-server -- --redis-url redis://localhost:6379");
    println!("   2. Use the frontend: npm run dev (in the root directory)");
    println!("   3. Visit: http://localhost:5173");

    Ok(())
}