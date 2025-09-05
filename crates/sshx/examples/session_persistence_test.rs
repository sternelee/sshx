use anyhow::Result;
use sshx::session_persistence::{SessionPersistence, SessionState};
use std::path::Path;

/// Test session persistence functionality
fn main() -> Result<()> {
    println!("🔄 sshx 会话持久化功能测试");
    println!("============================");

    // 1. 测试会话ID生成
    println!("\n📋 步骤 1: 测试会话ID生成");

    let api_key = Some("test-api-key-12345");
    let server = "http://localhost:3000";
    let work_dir = Some(Path::new("/tmp/test"));

    let session_id1 = SessionPersistence::generate_session_id(api_key, server, work_dir);
    let session_id2 = SessionPersistence::generate_session_id(api_key, server, work_dir);

    println!("✅ 相同参数生成相同ID: {}", session_id1 == session_id2);
    println!("   会话ID: {}", session_id1);

    // 测试不同参数生成不同ID
    let different_id =
        SessionPersistence::generate_session_id(Some("different-key"), server, work_dir);
    println!("✅ 不同API Key生成不同ID: {}", session_id1 != different_id);

    // 2. 测试会话状态保存和加载
    println!("\n💾 步骤 2: 测试会话状态保存和加载");

    let persistence = SessionPersistence::new()?;

    let test_state = SessionState {
        session_id: session_id1.clone(),
        encryption_key: "test-encryption-key-abcd1234".to_string(),
        write_password: Some("test-write-password".to_string()),
        session_name: "user-12345678-1640995200".to_string(),
        session_token: "test-session-token".to_string(),
        base_url: "http://localhost:3000/s/user-12345678-1640995200".to_string(),
        full_url: "http://localhost:3000/s/user-12345678-1640995200#test-encryption-key-abcd1234".to_string(),
        write_url: Some("http://localhost:3000/s/user-12345678-1640995200#test-encryption-key-abcd1234,test-write-password".to_string()),
        server_origin: server.to_string(),
        api_key: api_key.map(|s| s.to_string()),
        created_at: chrono::Utc::now().timestamp() as u64,
        last_accessed: chrono::Utc::now().timestamp() as u64,
    };

    // 保存会话状态
    persistence.save_session(&test_state)?;
    println!("✅ 会话状态保存成功");

    // 加载会话状态
    let loaded_state = persistence.load_session(&session_id1)?;
    match loaded_state {
        Some(state) => {
            println!("✅ 会话状态加载成功");
            println!("   会话名称: {}", state.session_name);
            println!("   加密密钥: {}...", &state.encryption_key[..10]);
            println!("   完整URL: {}", state.full_url);
            println!("   API Key: {:?}", state.api_key);
        }
        None => {
            println!("❌ 会话状态加载失败");
            return Ok(());
        }
    }

    // 3. 测试会话有效性检查
    println!("\n⏰ 步骤 3: 测试会话有效性检查");

    let loaded_state = loaded_state.unwrap();
    let is_valid = persistence.is_session_valid(&loaded_state, 24);
    println!(
        "✅ 会话有效性检查: {}",
        if is_valid { "有效" } else { "无效" }
    );

    // 4. 测试会话列表
    println!("\n📋 步骤 4: 测试会话列表");

    let sessions = persistence.list_sessions()?;
    println!("✅ 找到 {} 个保存的会话", sessions.len());

    for (i, session) in sessions.iter().enumerate() {
        println!("   会话 {}: {}", i + 1, session.session_name);
        println!("     ID: {}", session.session_id);
        println!(
            "     创建时间: {}",
            chrono::DateTime::from_timestamp(session.created_at as i64, 0)
                .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                .unwrap_or_else(|| "无效时间".to_string())
        );
    }

    // 5. 测试会话清理
    println!("\n🧹 步骤 5: 测试会话清理");

    // 创建一个旧会话用于测试清理
    let old_state = SessionState {
        session_id: "old-test-session".to_string(),
        encryption_key: "old-key".to_string(),
        write_password: None,
        session_name: "old-session".to_string(),
        session_token: "old-token".to_string(),
        base_url: "http://localhost:3000/s/old-session".to_string(),
        full_url: "http://localhost:3000/s/old-session#old-key".to_string(),
        write_url: None,
        server_origin: server.to_string(),
        api_key: None,
        created_at: (chrono::Utc::now().timestamp() - 30 * 24 * 60 * 60) as u64, // 30天前
        last_accessed: (chrono::Utc::now().timestamp() - 30 * 24 * 60 * 60) as u64,
    };

    persistence.save_session(&old_state)?;
    println!("✅ 创建旧会话用于测试");

    let removed_count = persistence.cleanup_old_sessions(7)?; // 清理7天前的会话
    println!("✅ 清理了 {} 个旧会话", removed_count);

    // 6. 清理测试数据
    println!("\n🧹 步骤 6: 清理测试数据");

    persistence.remove_session(&session_id1)?;
    println!("✅ 测试会话已清理");

    println!("\n🎉 会话持久化功能测试完成!");
    println!("\n💡 使用提示:");
    println!("   1. 持久会话: sshx --api-key YOUR_API_KEY");
    println!("   2. 临时会话: sshx (不提供 API Key)");
    println!("   3. 清理旧会话: sshx --cleanup-sessions 7");
    println!("   4. 会话文件位置: ~/.config/sshx/sessions/");

    Ok(())
}
