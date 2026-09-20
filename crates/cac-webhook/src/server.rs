use crate::config::WebhookConfig;
use crate::handler::{spawn_pr_job, WebhookHandler};
use crate::payload::ProviderKind;
use crate::signature::{verify_gitea_signature, verify_github_signature};
use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde_json::json;
use std::sync::Arc;
use tower_http::trace::TraceLayer;
use tracing::warn;

#[derive(Clone)]
struct AppState {
    handler: Arc<WebhookHandler>,
    secret: String,
}

pub async fn run_server(config: WebhookConfig) -> Result<(), std::io::Error> {
    let bind = config.bind_addr.clone();
    let secret = config.webhook_secret.clone();
    let handler = Arc::new(WebhookHandler::new(config));

    let state = AppState { handler, secret };

    let app = Router::new()
        .route("/health", get(health))
        .route("/webhook", post(webhook))
        .route("/webhook/github", post(webhook_github))
        .route("/webhook/gitea", post(webhook_gitea))
        .with_state(state)
        .layer(TraceLayer::new_for_http());

    let listener = tokio::net::TcpListener::bind(&bind).await?;
    tracing::info!(%bind, "CAC webhook server listening");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health() -> impl IntoResponse {
    Json(json!({ "status": "ok", "service": "compliance-as-code-webhook" }))
}

async fn webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let provider = detect_provider(&headers);
    handle_webhook(state, provider, headers, body).await
}

async fn webhook_github(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    handle_webhook(state, ProviderKind::GitHub, headers, body).await
}

async fn webhook_gitea(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    handle_webhook(state, ProviderKind::Gitea, headers, body).await
}

async fn handle_webhook(
    state: AppState,
    provider: ProviderKind,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    if !verify_request(&state.secret, provider, &headers, &body) {
        warn!("webhook signature verification failed");
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "invalid signature" })),
        );
    }

    let event = event_name(provider, &headers);
    if event != "pull_request" {
        return (
            StatusCode::OK,
            Json(json!({ "status": "ignored", "event": event })),
        );
    }

    let ctx = match WebhookHandler::parse_event(provider, &body) {
        Ok(Some(ctx)) => ctx,
        Ok(None) => {
            return (
                StatusCode::OK,
                Json(json!({ "status": "ignored", "reason": "unsupported action" })),
            );
        }
        Err(err) => {
            warn!(error = %err, "failed to parse webhook payload");
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": err.to_string() })),
            );
        }
    };

    spawn_pr_job(state.handler.clone(), ctx);
    (
        StatusCode::ACCEPTED,
        Json(json!({ "status": "accepted", "message": "compliance scan queued" })),
    )
}

fn detect_provider(headers: &HeaderMap) -> ProviderKind {
    if headers.contains_key("x-github-event") {
        ProviderKind::GitHub
    } else {
        ProviderKind::Gitea
    }
}

fn event_name(provider: ProviderKind, headers: &HeaderMap) -> String {
    match provider {
        ProviderKind::GitHub => header_value(headers, "x-github-event"),
        ProviderKind::Gitea => {
            header_value(headers, "x-gitea-event").or(header_value(headers, "x-gitea-event-type"))
        }
    }
    .unwrap_or_else(|| "unknown".into())
}

fn verify_request(secret: &str, provider: ProviderKind, headers: &HeaderMap, body: &[u8]) -> bool {
    if secret.is_empty() || secret == "change-me" {
        return true;
    }
    match provider {
        ProviderKind::GitHub => headers
            .get("x-hub-signature-256")
            .and_then(|v| v.to_str().ok())
            .map(|sig| verify_github_signature(secret, body, sig))
            .unwrap_or(false),
        ProviderKind::Gitea => headers
            .get("x-gitea-signature")
            .and_then(|v| v.to_str().ok())
            .map(|sig| verify_gitea_signature(secret, body, sig))
            .unwrap_or(false),
    }
}

fn header_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}
