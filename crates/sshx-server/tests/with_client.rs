use anyhow::{Context, Result};
use sshx::{controller::Controller, encrypt::Encrypt, runner::Runner};
use sshx_core::{
    proto::{server_update::ServerMessage, NewShell, TerminalInput},
    Sid, Uid,
};
use sshx_server::web::protocol::{WsClient, WsWinsize};
use tokio::time::{self, Duration};

use crate::common::*;

pub mod common;

#[tokio::test]
async fn test_handshake() -> Result<()> {
    let server = TestServer::new().await;
    let controller = Controller::new(&server.endpoint(), "", Runner::Echo, false).await?;
    controller.close().await?;
    Ok(())
}

#[tokio::test]
async fn test_command() -> Result<()> {
    let server = TestServer::new().await;
    let runner = Runner::Shell("/bin/bash".into());
    let mut controller = Controller::new(&server.endpoint(), "", runner, false).await?;

    let session = server
        .state()
        .lookup(controller.name())
        .context("couldn't find session in server state")?;

    let updates = session.update_tx();
    let new_shell = NewShell { id: 1, x: 0, y: 0 };
    updates.send(ServerMessage::CreateShell(new_shell)).await?;

    let key = controller.encryption_key();
    let encrypt = Encrypt::new(key);
    let offset = 4242;
    let data = TerminalInput {
        id: 1,
        data: encrypt.segment(0x200000000, offset, b"ls\r\n").into(),
        offset,
    };
    updates.send(ServerMessage::Input(data)).await?;

    tokio::select! {
        _ = controller.run() => (),
        _ = time::sleep(Duration::from_millis(1000)) => (),
    };
    controller.close().await?;
    Ok(())
}

#[tokio::test]
async fn test_ws_missing() -> Result<()> {
    let server = TestServer::new().await;

    let bad_endpoint = format!("ws://{}/not/an/endpoint", server.local_addr());
    assert!(ClientSocket::connect(&bad_endpoint, "", None)
        .await
        .is_err());

    let mut s = ClientSocket::connect(&server.ws_endpoint("foobar"), "", None).await?;
    s.expect_close(4404).await;

    Ok(())
}

#[tokio::test]
async fn test_ws_basic() -> Result<()> {
    let server = TestServer::new().await;

    let mut controller = Controller::new(&server.endpoint(), "", Runner::Echo, false).await?;
    let name = controller.name().to_owned();
    let key = controller.encryption_key().to_owned();
    tokio::spawn(async move { controller.run().await });

    let mut s = ClientSocket::connect(&server.ws_endpoint(&name), &key, None).await?;
    s.flush().await;
    assert_eq!(s.user_id, Uid(1));

    s.send(WsClient::Create(0, 0)).await;
    s.flush().await;
    assert_eq!(s.shells.len(), 1);
    assert!(s.shells.contains_key(&Sid(1)));

    s.send(WsClient::Subscribe(Sid(1), 0)).await;
    assert_eq!(s.read(Sid(1)), "");

    s.send_input(Sid(1), b"hello!").await;
    s.flush().await;
    assert_eq!(s.read(Sid(1)), "hello!");

    s.send_input(Sid(1), b" 123").await;
    s.flush().await;
    assert_eq!(s.read(Sid(1)), "hello! 123");

    Ok(())
}

#[tokio::test]
async fn test_ws_resize() -> Result<()> {
    let server = TestServer::new().await;

    let mut controller = Controller::new(&server.endpoint(), "", Runner::Echo, false).await?;
    let name = controller.name().to_owned();
    let key = controller.encryption_key().to_owned();
    tokio::spawn(async move { controller.run().await });

    let mut s = ClientSocket::connect(&server.ws_endpoint(&name), &key, None).await?;

    s.send(WsClient::Move(Sid(1), None)).await; // error: does not exist yet!
    s.flush().await;
    assert_eq!(s.errors.len(), 1);

    s.send(WsClient::Create(0, 0)).await;
    s.flush().await;
    assert_eq!(s.shells.len(), 1);
    assert_eq!(*s.shells.get(&Sid(1)).unwrap(), WsWinsize::default());

    let new_size = WsWinsize {
        x: 42,
        y: 105,
        rows: 200,
        cols: 20,
    };
    s.send(WsClient::Move(Sid(1), Some(new_size))).await;
    s.send(WsClient::Move(Sid(2), Some(new_size))).await; // error: does not exist
    s.flush().await;
    assert_eq!(s.shells.len(), 1);
    assert_eq!(*s.shells.get(&Sid(1)).unwrap(), new_size);
    assert_eq!(s.errors.len(), 2);

    s.send(WsClient::Close(Sid(1))).await;
    s.flush().await;
    assert_eq!(s.shells.len(), 0);

    s.send(WsClient::Move(Sid(1), None)).await; // error: shell was closed
    s.flush().await;
    assert_eq!(s.errors.len(), 3);

    Ok(())
}

#[tokio::test]
async fn test_users_join() -> Result<()> {
    let server = TestServer::new().await;

    let mut controller = Controller::new(&server.endpoint(), "", Runner::Echo, false).await?;
    let name = controller.name().to_owned();
    let key = controller.encryption_key().to_owned();
    tokio::spawn(async move { controller.run().await });

    let endpoint = server.ws_endpoint(&name);
    let mut s1 = ClientSocket::connect(&endpoint, &key, None).await?;
    s1.flush().await;
    assert_eq!(s1.users.len(), 1);

    let mut s2 = ClientSocket::connect(&endpoint, &key, None).await?;
    s2.flush().await;
    assert_eq!(s2.users.len(), 2);

    drop(s2);
    let mut s3 = ClientSocket::connect(&endpoint, &key, None).await?;
    s3.flush().await;
    assert_eq!(s3.users.len(), 2);

    s1.flush().await;
    assert_eq!(s1.users.len(), 2);

    Ok(())
}

#[tokio::test]
async fn test_users_metadata() -> Result<()> {
    let server = TestServer::new().await;

    let mut controller = Controller::new(&server.endpoint(), "", Runner::Echo, false).await?;
    let name = controller.name().to_owned();
    let key = controller.encryption_key().to_owned();
    tokio::spawn(async move { controller.run().await });

    let endpoint = server.ws_endpoint(&name);
    let mut s = ClientSocket::connect(&endpoint, &key, None).await?;
    s.flush().await;
    assert_eq!(s.users.len(), 1);
    assert_eq!(s.users.get(&s.user_id).unwrap().cursor, None);

    s.send(WsClient::SetName("mr. foo".into())).await;
    s.send(WsClient::SetCursor(Some((40, 524)))).await;
    s.flush().await;
    let user = s.users.get(&s.user_id).unwrap();
    assert_eq!(user.name, "mr. foo");
    assert_eq!(user.cursor, Some((40, 524)));

    Ok(())
}

#[tokio::test]
async fn test_chat_messages() -> Result<()> {
    let server = TestServer::new().await;

    let mut controller = Controller::new(&server.endpoint(), "", Runner::Echo, false).await?;
    let name = controller.name().to_owned();
    let key = controller.encryption_key().to_owned();
    tokio::spawn(async move { controller.run().await });

    let endpoint = server.ws_endpoint(&name);
    let mut s1 = ClientSocket::connect(&endpoint, &key, None).await?;
    let mut s2 = ClientSocket::connect(&endpoint, &key, None).await?;

    s1.send(WsClient::SetName("billy".into())).await;
    s1.send(WsClient::Chat("hello there!".into())).await;
    s1.flush().await;

    s2.flush().await;
    assert_eq!(s2.messages.len(), 1);
    assert_eq!(
        s2.messages[0],
        (s1.user_id, "billy".into(), "hello there!".into())
    );

    let mut s3 = ClientSocket::connect(&endpoint, &key, None).await?;
    s3.flush().await;
    assert_eq!(s1.messages.len(), 1);
    assert_eq!(s3.messages.len(), 0);

    Ok(())
}

#[tokio::test]
async fn test_read_write_permissions() -> Result<()> {
    let server = TestServer::new().await;

    // create controller with read-only mode enabled
    let mut controller = Controller::new(&server.endpoint(), "", Runner::Echo, true).await?;
    let name = controller.name().to_owned();
    let key = controller.encryption_key().to_owned();
    let write_url = controller
        .write_url()
        .expect("Should have write URL when enable_readers is true")
        .to_string();

    tokio::spawn(async move { controller.run().await });

    let write_password = write_url
        .split(',')
        .nth(1)
        .expect("Write URL should contain password");

    // connect with write access
    let mut writer =
        ClientSocket::connect(&server.ws_endpoint(&name), &key, Some(write_password)).await?;
    writer.flush().await;

    // test write permissions
    writer.send(WsClient::Create(0, 0)).await;
    writer.flush().await;
    assert_eq!(
        writer.shells.len(),
        1,
        "Writer should be able to create a shell"
    );
    assert!(writer.errors.is_empty(), "Writer should not receive errors");

    // connect with read-only access
    let mut reader = ClientSocket::connect(&server.ws_endpoint(&name), &key, None).await?;
    reader.flush().await;

    // test read-only restrictions
    reader.send(WsClient::Create(0, 0)).await;
    reader.flush().await;
    assert!(
        !reader.errors.is_empty(),
        "Reader should receive an error when attempting to create shell"
    );
    assert_eq!(
        reader.shells.len(),
        1,
        "Reader should still see the existing shell"
    );

    Ok(())
}

#[tokio::test]
async fn test_grpc_active_counter_tracks_stream() -> Result<()> {
    let server = TestServer::new().await;
    let mut controller = Controller::new(&server.endpoint(), "", Runner::Echo, false).await?;

    // Spawn the run loop so the gRPC `Channel` stream is actually opened
    // (Controller::new only completes the Open RPC; the bidirectional
    // stream is established inside run()).
    let session = server
        .state()
        .lookup(controller.name())
        .context("couldn't find session in server state")?;
    let name = controller.name().to_string();

    let run_handle = tokio::spawn(async move {
        tokio::select! {
            _ = controller.run() => (),
            _ = time::sleep(Duration::from_secs(5)) => (),
        }
        controller.close().await.ok();
    });

    // Allow the Channel stream to register.
    time::sleep(Duration::from_millis(300)).await;

    assert!(
        session.has_active_grpc(),
        "expected active grpc after CLI connect ({name})"
    );

    // Drop run handle to terminate the controller; close_session below
    // forces the Channel stream to exit.
    server.state().close_session(&name).await?;
    run_handle.await.ok();

    // Allow the spawned task to drop and decrement the counter.
    time::sleep(Duration::from_millis(300)).await;

    assert!(
        !session.has_active_grpc(),
        "expected inactive grpc after CLI disconnect",
    );
    Ok(())
}

// ---------- cold-tier integration ----------
//
// These tests require a Redis instance reachable via SSHX_TEST_REDIS_URL.
// When the env var is unset they skip silently so `cargo test` works on
// machines without docker-compose up.

#[tokio::test]
async fn test_cold_evict_and_thaw_via_websocket() -> Result<()> {
    let Some(server) = TestServer::with_redis().await else {
        return Ok(());
    };

    // 1. CLI connects and registers a shell so the snapshot has content.
    let mut controller = Controller::new(&server.endpoint(), "", Runner::Echo, false).await?;
    let name = controller.name().to_string();
    let session = server
        .state()
        .lookup(&name)
        .context("hot session missing")?;

    // Drive the controller briefly so background_sync registers, then
    // shut down the controller's gRPC stream (Channel will exit).
    let run_handle = tokio::spawn(async move {
        tokio::select! {
            _ = controller.run() => (),
            _ = time::sleep(Duration::from_millis(300)) => (),
        }
        controller.close().await.ok();
    });
    time::sleep(Duration::from_millis(400)).await;

    // 2. Inline evict (skip the 60 s sweeper interval).
    server.state().evict_to_cold(&name, &session).await?;
    server.state().remove(&name);
    run_handle.await.ok();

    assert!(
        server.state().lookup(&name).is_none(),
        "hot map should be empty after evict + remove"
    );

    // 3. WebSocket-side reconnect must thaw from Redis.
    let result = server.state().frontend_connect(&name).await?;
    let restored = match result {
        Ok(s) => s,
        Err(other) => panic!("expected thaw, got redirect/none: {other:?}"),
    };

    // 4. Restored session has the original metadata (encrypted_zeros) and at least the original
    //    shell registered.
    assert_eq!(
        restored.metadata().encrypted_zeros,
        session.metadata().encrypted_zeros,
        "encrypted_zeros must round-trip"
    );
    Ok(())
}

#[tokio::test]
async fn test_cold_does_not_evict_with_active_grpc() -> Result<()> {
    let Some(server) = TestServer::with_redis().await else {
        return Ok(());
    };
    let mut controller = Controller::new(&server.endpoint(), "", Runner::Echo, false).await?;
    let name = controller.name().to_string();

    let run_handle = tokio::spawn(async move {
        tokio::select! {
            _ = controller.run() => (),
            _ = time::sleep(Duration::from_secs(2)) => (),
        }
        controller.close().await.ok();
    });
    time::sleep(Duration::from_millis(300)).await;

    let session = server.state().lookup(&name).context("hot")?;
    assert!(
        session.has_active_grpc(),
        "active gRPC stream means sweeper must skip eviction"
    );
    assert_eq!(
        session.user_count(),
        0,
        "viewer count starts at 0 (no WebSocket connected)"
    );
    server.state().close_session(&name).await?;
    run_handle.await.ok();
    Ok(())
}

#[tokio::test]
async fn test_cold_redirect_when_other_owner() -> Result<()> {
    let Some(server) = TestServer::with_redis().await else {
        return Ok(());
    };
    let mut controller = Controller::new(&server.endpoint(), "", Runner::Echo, false).await?;
    let name = controller.name().to_string();
    let session = server.state().lookup(&name).context("hot")?;

    let run_handle = tokio::spawn(async move {
        tokio::select! {
            _ = controller.run() => (),
            _ = time::sleep(Duration::from_millis(300)) => (),
        }
        controller.close().await.ok();
    });
    time::sleep(Duration::from_millis(400)).await;

    // Cold-evict, then overwrite owner to point elsewhere.
    server.state().evict_to_cold(&name, &session).await?;
    server.state().remove(&name);
    run_handle.await.ok();

    let state = server.state();
    let mesh = state.mesh().expect("mesh enabled with redis");
    mesh.debug_set_owner(&name, "other-host:1234").await?;

    let result = server.state().frontend_connect(&name).await?;
    match result {
        Err(Some(host)) => assert_eq!(host, "other-host:1234"),
        other => panic!("expected redirect to other-host, got {other:?}"),
    }
    Ok(())
}
