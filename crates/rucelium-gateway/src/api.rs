//! The HTTP API (ADR-265 §4): health, stats, observations, events, an OGC
//! SensorThings-style projection, the federation surface peers poll, and a
//! local admin endpoint.
//!
//! # SECURITY (v0.1)
//!
//! **The admin endpoints carry NO authentication.** `POST
//! /api/admin/revoke/{node_id}` revokes a device key immediately. Any
//! deployment beyond a workbench MUST bind the HTTP port to localhost or
//! firewall it; production authentication is deliberate follow-up work
//! (ADR-265 §6).

use crate::state::{now_ns, GatewayState};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use rucelium_core::EventKind;
use rucelium_federation::{project_sample, SensorThingsBundle};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::BTreeSet;

/// Default `limit` for observation/event listings.
const DEFAULT_LIST_LIMIT: usize = 50;
/// Default `limit` for SensorThings listings.
const DEFAULT_ST_LIMIT: usize = 100;
/// Default `window_s` for `/api/federation/summary`.
const DEFAULT_SUMMARY_WINDOW_S: u64 = 3600;

/// Handler error: status + plain-text reason.
type ApiError = (StatusCode, String);

/// Map an internal error to a 500 with its message.
fn internal<E: std::fmt::Display>(e: E) -> ApiError {
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

/// `?limit=N` query.
#[derive(Debug, Deserialize)]
struct LimitParam {
    /// Maximum number of entries to return.
    limit: Option<usize>,
}

/// `?window_s=N` query.
#[derive(Debug, Deserialize)]
struct WindowParam {
    /// Summary window length in seconds, ending now.
    window_s: Option<u64>,
}

/// Build the gateway's axum router (see module docs for the endpoint list
/// and the v0.1 admin-endpoint security posture).
pub fn router(state: GatewayState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/api/stats", get(stats))
        .route("/api/observations/recent", get(observations_recent))
        .route("/api/events", get(events_recent))
        .route("/api/sensorthings/Things", get(st_things))
        .route("/api/sensorthings/Datastreams", get(st_datastreams))
        .route("/api/sensorthings/Observations", get(st_observations))
        .route("/api/federation/pubkey", get(fed_pubkey))
        .route("/api/federation/summary", get(fed_summary))
        .route("/api/federation/revocations", get(fed_revocations))
        .route("/api/federation/peers", get(fed_peers))
        .route("/api/admin/revoke/:node_id", post(admin_revoke))
        .with_state(state)
}

/// `GET /health` — liveness.
async fn health(State(state): State<GatewayState>) -> Json<Value> {
    Json(json!({ "ok": true, "biome_id": state.biome_id }))
}

/// `GET /api/stats` — one JSON snapshot of every counter in the daemon.
async fn stats(State(state): State<GatewayState>) -> Json<Value> {
    let inner = state.inner.lock().await;
    Json(json!({
        "biome_id": state.biome_id,
        "uptime_s": state.started.elapsed().as_secs(),
        "ingest": inner.ingest.stats(),
        "datagrams": inner.datagrams,
        "observations": inner.obs.stats(),
        "events": {
            "records": inner.events.len(),
            "segments": inner.events.segments().len(),
        },
        "biome": {
            "accepted": inner.biome.accepted_count(),
            "duplicates": inner.biome.duplicate_count(),
        },
        "worldgraph": {
            "nodes": inner.graph.len(),
            "contradictions": inner.graph.contradiction_count(),
        },
        "alerts": inner.alerts,
        "calibration_errors": inner.calibration_errors,
        "quarantined_nodes": inner.drift.quarantined(),
        "applied_peer_revocations": inner.applied_peer_revocations,
        "peer_summaries": inner.peer_summaries.len(),
    }))
}

/// `GET /api/observations/recent?limit=50` — most recent stored samples in
/// append order.
async fn observations_recent(
    State(state): State<GatewayState>,
    Query(q): Query<LimitParam>,
) -> Result<Json<Value>, ApiError> {
    let inner = state.inner.lock().await;
    let samples = inner
        .obs
        .recent(q.limit.unwrap_or(DEFAULT_LIST_LIMIT))
        .map_err(internal)?;
    Ok(Json(json!(samples)))
}

/// `GET /api/events?limit=50` — most recent stored events in append order.
async fn events_recent(
    State(state): State<GatewayState>,
    Query(q): Query<LimitParam>,
) -> Result<Json<Value>, ApiError> {
    let inner = state.inner.lock().await;
    let events = inner
        .events
        .recent(q.limit.unwrap_or(DEFAULT_LIST_LIMIT))
        .map_err(internal)?;
    Ok(Json(json!(events)))
}

/// Project the most recent `limit` stored samples into SensorThings bundles.
async fn recent_bundles(
    state: &GatewayState,
    limit: usize,
) -> Result<Vec<SensorThingsBundle>, ApiError> {
    let inner = state.inner.lock().await;
    let samples = inner.obs.recent(limit).map_err(internal)?;
    Ok(samples.iter().map(project_sample).collect())
}

/// `GET /api/sensorthings/Things?limit=100` — Things over the recent
/// observations, deduplicated by `@iot.id`.
async fn st_things(
    State(state): State<GatewayState>,
    Query(q): Query<LimitParam>,
) -> Result<Json<Value>, ApiError> {
    let bundles = recent_bundles(&state, q.limit.unwrap_or(DEFAULT_ST_LIMIT)).await?;
    let mut seen = BTreeSet::new();
    let things: Vec<_> = bundles
        .into_iter()
        .map(|b| b.thing)
        .filter(|t| seen.insert(t.iot_id.clone()))
        .collect();
    Ok(Json(json!({ "value": things })))
}

/// `GET /api/sensorthings/Datastreams?limit=100` — Datastreams over the
/// recent observations, deduplicated by `@iot.id`.
async fn st_datastreams(
    State(state): State<GatewayState>,
    Query(q): Query<LimitParam>,
) -> Result<Json<Value>, ApiError> {
    let bundles = recent_bundles(&state, q.limit.unwrap_or(DEFAULT_ST_LIMIT)).await?;
    let mut seen = BTreeSet::new();
    let streams: Vec<_> = bundles
        .into_iter()
        .map(|b| b.datastream)
        .filter(|d| seen.insert(d.iot_id.clone()))
        .collect();
    Ok(Json(json!({ "value": streams })))
}

/// `GET /api/sensorthings/Observations?limit=100` — one Observation entity
/// per recent stored sample.
async fn st_observations(
    State(state): State<GatewayState>,
    Query(q): Query<LimitParam>,
) -> Result<Json<Value>, ApiError> {
    let bundles = recent_bundles(&state, q.limit.unwrap_or(DEFAULT_ST_LIMIT)).await?;
    let obs: Vec<_> = bundles.into_iter().map(|b| b.observation).collect();
    Ok(Json(json!({ "value": obs })))
}

/// `GET /api/federation/pubkey` — the biome's federated identity.
async fn fed_pubkey(State(state): State<GatewayState>) -> Json<Value> {
    let inner = state.inner.lock().await;
    Json(json!({
        "biome_id": state.biome_id,
        "pubkey_hex": inner.biome.public_key_hex(),
    }))
}

/// `GET /api/federation/summary?window_s=3600` — the signed regional summary
/// over `[now - window_s, now)`.
async fn fed_summary(
    State(state): State<GatewayState>,
    Query(q): Query<WindowParam>,
) -> Json<Value> {
    let window_ns = q
        .window_s
        .unwrap_or(DEFAULT_SUMMARY_WINDOW_S)
        .saturating_mul(1_000_000_000);
    let end = now_ns();
    let start = end.saturating_sub(window_ns);
    let inner = state.inner.lock().await;
    Json(json!(inner.biome.summarize(start, end)))
}

/// `GET /api/federation/revocations` — every biome-signed `DeviceRevoked`
/// event in the durable event store; peers verify and apply these.
async fn fed_revocations(State(state): State<GatewayState>) -> Result<Json<Value>, ApiError> {
    let inner = state.inner.lock().await;
    let revocations: Vec<_> = inner
        .events
        .iter()
        .map_err(internal)?
        .into_iter()
        .filter(|e| e.kind == EventKind::DeviceRevoked)
        .collect();
    Ok(Json(json!(revocations)))
}

/// `GET /api/federation/peers` — the latest verified summary per peer.
async fn fed_peers(State(state): State<GatewayState>) -> Json<Value> {
    let inner = state.inner.lock().await;
    Json(json!(inner.peer_summaries))
}

/// `POST /api/admin/revoke/{node_id}` — revoke a device locally: registry
/// revocation (immediate ingest rejection), biome revocation, and a
/// biome-signed `DeviceRevoked` event appended to the event store — the
/// record federation peers pick up.
///
/// **UNAUTHENTICATED in v0.1** — see the module-level SECURITY note.
async fn admin_revoke(
    State(state): State<GatewayState>,
    Path(node_id): Path<u64>,
) -> Result<Json<Value>, ApiError> {
    let mut inner = state.inner.lock().await;
    let registry_revoked = inner.ingest.registry_mut().revoke(node_id);
    let event = inner
        .biome
        .revoke_device(node_id, now_ns(), "admin revocation");
    inner.events.append(&event).map_err(internal)?;
    Ok(Json(json!({
        "node_id": node_id,
        "registry_revoked": registry_revoked,
        "event": event,
    })))
}
