use anyhow::Result;
use sshx_core::proto::{
    sshx_service_client::SshxServiceClient, RegisterRequest, LoginRequest, 
    GenerateApiKeyRequest, ListApiKeysRequest, DeleteApiKeyRequest
};
use tonic::transport::Channel;

#[tokio::main]
async fn main() -> Result<()> {
    println!("🔑 SSHX API Key Management Test");
    println!("================================");

    // Connect to the server
    let mut client = SshxServiceClient::connect("http://127.0.0.1:3000").await?;
    println!("✅ Connected to sshx server");

    // Test user registration
    println!("\n📝 Testing user registration...");
    let register_req = RegisterRequest {
        email: "test@example.com".to_string(),
        password: "test123456".to_string(),
    };

    let auth_response = match client.register(register_req).await {
        Ok(response) => {
            let auth = response.into_inner();
            println!("✅ User registered successfully");
            println!("   User ID: {}", auth.user_id);
            println!("   Email: {}", auth.email);
            auth
        }
        Err(err) => {
            // If user already exists, try to login
            println!("⚠️  Registration failed (user might exist): {}", err);
            println!("\n🔐 Trying to login...");
            
            let login_req = LoginRequest {
                email: "test@example.com".to_string(),
                password: "test123456".to_string(),
            };
            
            let response = client.login(login_req).await?;
            let auth = response.into_inner();
            println!("✅ User logged in successfully");
            println!("   User ID: {}", auth.user_id);
            println!("   Email: {}", auth.email);
            auth
        }
    };

    // Test API key generation
    println!("\n🔑 Testing API key generation...");
    let api_key_req = GenerateApiKeyRequest {
        auth_token: auth_response.token.clone(),
        name: "My Test API Key".to_string(),
    };

    let api_key_response = client.generate_api_key(api_key_req).await?;
    let api_key = api_key_response.into_inner();
    println!("✅ API key generated successfully");
    println!("   ID: {}", api_key.id);
    println!("   Name: {}", api_key.name);
    println!("   Token: {}...", &api_key.token[..20]); // Show only first 20 chars for security
    println!("   Created: {}", api_key.created_at);

    // Test API key listing
    println!("\n📋 Testing API key listing...");
    let list_req = ListApiKeysRequest {
        auth_token: auth_response.token.clone(),
    };

    let list_response = client.list_api_keys(list_req).await?;
    let api_keys = list_response.into_inner().api_keys;
    println!("✅ Found {} API key(s)", api_keys.len());
    
    for (i, key) in api_keys.iter().enumerate() {
        println!("   {}. ID: {}", i + 1, key.id);
        println!("      Name: {}", key.name);
        println!("      Created: {}", key.created_at);
        println!("      Last used: {:?}", key.last_used);
        println!("      Active: {}", key.is_active);
    }

    // Generate another API key
    println!("\n🔑 Generating another API key...");
    let api_key_req2 = GenerateApiKeyRequest {
        auth_token: auth_response.token.clone(),
        name: "Development Key".to_string(),
    };

    let api_key_response2 = client.generate_api_key(api_key_req2).await?;
    let api_key2 = api_key_response2.into_inner();
    println!("✅ Second API key generated");
    println!("   ID: {}", api_key2.id);
    println!("   Name: {}", api_key2.name);

    // Test API key deletion
    println!("\n🗑️  Testing API key deletion...");
    let delete_req = DeleteApiKeyRequest {
        auth_token: auth_response.token.clone(),
        api_key_id: api_key2.id.clone(),
    };

    let delete_response = client.delete_api_key(delete_req).await?;
    let deleted = delete_response.into_inner().success;
    
    if deleted {
        println!("✅ API key '{}' deleted successfully", api_key2.name);
    } else {
        println!("❌ Failed to delete API key");
    }

    // List API keys again to verify deletion
    println!("\n📋 Listing API keys after deletion...");
    let list_req2 = ListApiKeysRequest {
        auth_token: auth_response.token.clone(),
    };

    let list_response2 = client.list_api_keys(list_req2).await?;
    let remaining_keys = list_response2.into_inner().api_keys;
    println!("✅ {} API key(s) remaining", remaining_keys.len());
    
    for (i, key) in remaining_keys.iter().enumerate() {
        println!("   {}. ID: {}", i + 1, key.id);
        println!("      Name: {}", key.name);
        println!("      Active: {}", key.is_active);
    }

    // Show usage instructions
    println!("\n🚀 Usage Instructions:");
    println!("======================");
    println!("To use the API key with sshx client:");
    println!("  export SSHX_API_KEY=\"{}\"", api_key.token);
    println!("  sshx");
    println!();
    println!("Or use the command line flag:");
    println!("  sshx --api-key \"{}\"", api_key.token);
    println!();
    println!("The session will be automatically associated with your user account!");

    Ok(())
}