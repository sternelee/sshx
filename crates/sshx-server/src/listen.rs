use std::{fmt::Debug, future::Future, sync::Arc};

use anyhow::Result;
use axum::body::Body;
use axum::serve::Listener;
use http::{header::CONTENT_TYPE, Request};
use sshx_core::proto::{sshx_service_server::SshxServiceServer, FILE_DESCRIPTOR_SET};
use tonic::service::Routes as TonicRoutes;
use tower::{make::Shared, steer::Steer, ServiceExt};
use tower_http::trace::TraceLayer;

use crate::{grpc::GrpcServer, web, ServerState};

/// Bind and listen from the application, with a state and termination signal.
///
/// This internal method is responsible for multiplexing the HTTP and gRPC
/// servers onto a single, consolidated `hyper` service.
pub(crate) async fn start_server<L>(
    state: Arc<ServerState>,
    listener: L,
    signal: impl Future<Output = ()> + Send + 'static,
) -> Result<()>
where
    L: Listener,
    L::Addr: Debug,
{
    let http_service = web::app()
        .with_state(state.clone())
        .layer(TraceLayer::new_for_http())
        .into_service()
        .boxed_clone();

    let user_service = match state.user_service() {
        Some(service) => service,
        None => {
            // Create a dummy user service if Redis is not available
            // This will fail gracefully when authentication is attempted
            let dummy_pool = deadpool_redis::Config::from_url("redis://localhost:6379")
                .create_pool(Some(deadpool_redis::Runtime::Tokio1))
                .expect("Failed to create dummy Redis pool");
            Arc::new(crate::user_service::UserService::new(
                dummy_pool,
                "dummy_secret".to_string(),
            ))
        }
    };

    let grpc_service = TonicRoutes::default()
        .add_service(SshxServiceServer::new(GrpcServer::new(state, user_service)))
        .add_service(
            tonic_reflection::server::Builder::configure()
                .register_encoded_file_descriptor_set(FILE_DESCRIPTOR_SET)
                .build_v1()?,
        )
        .into_axum_router()
        .layer(TraceLayer::new_for_grpc())
        .into_service()
        // This type conversion is necessary because Tonic 0.12 uses Axum 0.7, so its `axum::Router`
        // and `axum::Body` are based on an older `axum_core` version.
        .map_response(|r| r.map(Body::new))
        .boxed_clone();

    let svc = Steer::new(
        [http_service, grpc_service],
        |req: &Request<Body>, _services: &[_]| {
            let headers = req.headers();
            match headers.get(CONTENT_TYPE) {
                Some(content) if content == "application/grpc" => 1,
                _ => 0,
            }
        },
    );
    let make_svc = Shared::new(svc);

    axum::serve(listener, make_svc)
        .with_graceful_shutdown(signal)
        .await?;

    Ok(())
}
