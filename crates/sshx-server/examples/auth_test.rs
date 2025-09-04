use sshx_core::proto::{sshx_service_client::SshxServiceClient, LoginRequest, RegisterRequest};
use tonic::Request;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Connect to the gRPC server
    let mut client = SshxServiceClient::connect("http://127.0.0.1:8080").await?;

    // Test registration
    println!("Testing user registration...");
    let register_req = Request::new(RegisterRequest {
        email: "test@example.com".to_string(),
        password: "password123".to_string(),
    });

    match client.register(register_req).await {
        Ok(response) => {
            let auth_response = response.into_inner();
            println!("Registration successful!");
            println!("Token: {}", auth_response.token);
            println!("User ID: {}", auth_response.user_id);
            println!("Email: {}", auth_response.email);
        }
        Err(e) => {
            println!("Registration failed: {}", e);
        }
    }

    // Test login
    println!("\nTesting user login...");
    let login_req = Request::new(LoginRequest {
        email: "test@example.com".to_string(),
        password: "password123".to_string(),
    });

    match client.login(login_req).await {
        Ok(response) => {
            let auth_response = response.into_inner();
            println!("Login successful!");
            println!("Token: {}", auth_response.token);
            println!("User ID: {}", auth_response.user_id);
            println!("Email: {}", auth_response.email);
        }
        Err(e) => {
            println!("Login failed: {}", e);
        }
    }

    Ok(())
}
