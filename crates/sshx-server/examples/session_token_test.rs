use sshx_core::proto::{
    sshx_service_client::SshxServiceClient, GenerateSessionTokenRequest, LoginRequest,
    RegisterRequest,
};
use tonic::Request;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Connect to the gRPC server
    let mut client = SshxServiceClient::connect("http://127.0.0.1:8080").await?;

    // Test registration
    println!("Testing user registration...");
    let register_req = Request::new(RegisterRequest {
        email: "testuser@example.com".to_string(),
        password: "password123".to_string(),
    });

    let auth_token = match client.register(register_req).await {
        Ok(response) => {
            let auth_response = response.into_inner();
            println!("Registration successful!");
            println!("Auth Token: {}", auth_response.token);
            println!("User ID: {}", auth_response.user_id);
            auth_response.token
        }
        Err(e) => {
            println!("Registration failed: {}", e);

            // Try login instead
            println!("\nTrying login...");
            let login_req = Request::new(LoginRequest {
                email: "testuser@example.com".to_string(),
                password: "password123".to_string(),
            });

            let auth_response = client.login(login_req).await?.into_inner();
            println!("Login successful!");
            println!("Auth Token: {}", auth_response.token);
            auth_response.token
        }
    };

    // Test session token generation
    println!("\nTesting session token generation...");
    let session_req = Request::new(GenerateSessionTokenRequest {
        auth_token: auth_token.clone(),
        session_name: "my-test-session".to_string(),
    });

    match client.generate_session_token(session_req).await {
        Ok(response) => {
            let session_response = response.into_inner();
            println!("Session token generation successful!");
            println!("Session Token: {}", session_response.session_token);
            println!("Session Name: {}", session_response.session_name);
            println!("User ID: {}", session_response.user_id);

            // Show how to use with sshx client
            let user_token = format!(
                "{}:{}",
                session_response.session_name, session_response.session_token
            );
            println!("\nTo use with sshx client:");
            println!("sshx --user-token '{}'", user_token);
            println!("or");
            println!("SSHX_USER_TOKEN='{}' sshx", user_token);
        }
        Err(e) => {
            println!("Session token generation failed: {}", e);
        }
    }

    Ok(())
}
