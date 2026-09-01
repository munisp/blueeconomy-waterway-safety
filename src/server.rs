#![forbid(unsafe_code)]

//! Axum HTTP service exposing the telemetry integrity validator.
//!
//! Endpoints:
//! - `GET /health` — liveness probe.
//! - `POST /v1/telemetry/validate` — validates a telemetry frame. When a
//!   device registry is configured (via `WATERWAY_DEVICE_REGISTRY_PATH`), the
//!   body must be a signed telemetry frame verified against that registry.
//!   Validation failures fail closed with HTTP 422 and never echo the
//!   submitted payload.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Serialize;

use crate::{
    load_device_registry, validate_json, validate_signed_json, DeviceRegistry, MAX_JSON_BYTES,
};

pub const DEFAULT_BIND_ADDR: &str = "0.0.0.0:8080";
pub const DEVICE_REGISTRY_ENV: &str = "WATERWAY_DEVICE_REGISTRY_PATH";

struct AppState {
    registry: Option<DeviceRegistry>,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
}

pub fn router(registry: Option<DeviceRegistry>) -> Router {
    let state = Arc::new(AppState { registry });
    Router::new()
        .route("/health", get(health))
        .route("/v1/telemetry/validate", post(validate_telemetry))
        .layer(DefaultBodyLimit::max(MAX_JSON_BYTES))
        .with_state(state)
}

/// Load the optional device registry from the environment and serve HTTP.
/// Fail-closed: a configured but unreadable/invalid registry aborts startup.
pub async fn serve(bind: SocketAddr) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let registry = load_registry_from_env()?;
    let listener = tokio::net::TcpListener::bind(bind).await?;
    axum::serve(listener, router(registry)).await?;
    Ok(())
}

fn load_registry_from_env()
    -> Result<Option<DeviceRegistry>, Box<dyn std::error::Error + Send + Sync>> {
    match std::env::var_os(DEVICE_REGISTRY_ENV) {
        Some(path) if !path.is_empty() => {
            let registry = load_device_registry(Path::new(&path))?;
            Ok(Some(registry))
        }
        _ => Ok(None),
    }
}

async fn health() -> impl IntoResponse {
    (StatusCode::OK, Json(serde_json::json!({ "status": "ok" })))
}

async fn validate_telemetry(State(state): State<Arc<AppState>>, body: Bytes) -> Response {
    let validated = match state.registry.as_ref() {
        Some(registry) => validate_signed_json(&body, registry)
            .and_then(|record| serde_json::to_value(record).map_err(json_encode_error)),
        None => validate_json(&body)
            .and_then(|record| serde_json::to_value(record).map_err(json_encode_error)),
    };
    match validated {
        Ok(record) => (StatusCode::OK, Json(record)).into_response(),
        Err(error) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(ErrorResponse {
                error: error.code.to_owned(),
            }),
        )
            .into_response(),
    }
}

fn json_encode_error(error: serde_json::Error) -> crate::ValidationError {
    crate::ValidationError {
        code: "encode_result_failed",
        message: error.to_string(),
    }
}
