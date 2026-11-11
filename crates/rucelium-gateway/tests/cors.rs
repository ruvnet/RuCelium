//! CORS + `/api/rf-context` contract guard for the read-only dashboard use
//! case (`api::dashboard_cors_layer` doc comment, `api::router`'s
//! `dashboard_origins` param).
//!
//! Addresses the two review rejections on the original split-PR shape
//! (RuView#1731 / RuCelium#3):
//! - the dashboard's `pollRuCelium()` contract (`upstream`, `stats`,
//!   `room_state_inferences`) is asserted directly against a live
//!   `/api/rf-context` response, not just unit-tested in `rf_bridge`;
//! - CORS is origin-gated and scoped to the two dashboard routes only — an
//!   unconfigured/unknown origin gets no `Access-Control-Allow-Origin` at
//!   all, a configured origin gets it on `/api/rf-context` and
//!   `/api/stats`, and `POST` is never allowed regardless of origin.

use rucelium_gateway::{spawn_gateway_with_state, GatewayConfig, GatewayState};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

const DASHBOARD_ORIGIN: &str = "http://127.0.0.1:8090";
const UNKNOWN_ORIGIN: &str = "http://evil.example";

fn temp_dir(tag: &str) -> PathBuf {
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("rucelium-gw-cors-{tag}-{}-{t}", std::process::id()))
}

async fn spawn_with_dashboard_origin() -> (rucelium_gateway::GatewayHandle, PathBuf) {
    let dir = temp_dir("dashboard");
    let cfg = GatewayConfig {
        udp_port: 0,
        http_port: 0,
        data_dir: dir.clone(),
        dashboard_origins: vec![DASHBOARD_ORIGIN.to_string()],
        ..GatewayConfig::default()
    };
    let state = GatewayState::open(&cfg).expect("open state");
    let handle = spawn_gateway_with_state(state, cfg)
        .await
        .expect("spawn gateway");
    (handle, dir)
}

#[tokio::test(flavor = "multi_thread")]
async fn rf_context_returns_the_schema_the_dashboard_s_polling_depends_on() {
    let (handle, dir) = spawn_with_dashboard_origin().await;
    let base = format!("http://127.0.0.1:{}", handle.http_port);

    let body: serde_json::Value = reqwest::get(format!("{base}/api/rf-context"))
        .await
        .expect("GET /api/rf-context")
        .json()
        .await
        .expect("valid JSON");

    // The exact contract `ui/pipeline.html`'s `pollRuCelium()` reads — an
    // idle bridge (no `--rf-upstream` configured here) still has to shape
    // this correctly, not just when there happens to be live traffic.
    assert!(body.get("upstream").is_some(), "missing `upstream`: {body}");
    assert!(body.get("stats").is_some(), "missing `stats`: {body}");
    assert!(
        body.get("room_state_inferences").is_some(),
        "missing `room_state_inferences`: {body}"
    );
    assert!(
        body["room_state_inferences"].is_array(),
        "`room_state_inferences` must be an array: {body}"
    );
    assert_eq!(
        body["upstream"],
        serde_json::Value::Null,
        "no --rf-upstream was configured, so it must be honestly null, not fabricated"
    );

    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_configured_dashboard_origin_gets_cors_on_both_dashboard_routes() {
    let (handle, dir) = spawn_with_dashboard_origin().await;
    let base = format!("http://127.0.0.1:{}", handle.http_port);
    let client = reqwest::Client::new();

    for path in ["/api/rf-context", "/api/stats"] {
        let resp = client
            .get(format!("{base}{path}"))
            .header("Origin", DASHBOARD_ORIGIN)
            .send()
            .await
            .unwrap_or_else(|e| panic!("GET {path}: {e}"));
        assert!(resp.status().is_success(), "GET {path} failed: {resp:?}");
        let allow_origin = resp
            .headers()
            .get("access-control-allow-origin")
            .unwrap_or_else(|| panic!("{path}: CORS header must be present for the configured origin"))
            .to_str()
            .unwrap();
        assert_eq!(
            allow_origin, DASHBOARD_ORIGIN,
            "{path}: must echo the configured origin, not a wildcard"
        );
    }

    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unconfigured_origin_gets_no_cors_header_on_dashboard_routes() {
    let (handle, dir) = spawn_with_dashboard_origin().await;
    let base = format!("http://127.0.0.1:{}", handle.http_port);
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{base}/api/rf-context"))
        .header("Origin", UNKNOWN_ORIGIN)
        .send()
        .await
        .expect("GET /api/rf-context");

    // The server still answers (this was never an auth control — see the
    // module docs), but the browser gets no ACAO for this origin, so the
    // browser's own same-origin policy still blocks the read.
    assert!(resp.status().is_success());
    assert!(
        resp.headers().get("access-control-allow-origin").is_none(),
        "an unconfigured origin must not receive an Access-Control-Allow-Origin header"
    );

    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test(flavor = "multi_thread")]
async fn no_dashboard_origin_configured_means_no_cors_header_at_all() {
    // The default posture (empty --dashboard-origin): CORS is fully
    // disabled, matching the gateway's pre-dashboard behavior exactly.
    let dir = temp_dir("no-origin");
    let cfg = GatewayConfig {
        udp_port: 0,
        http_port: 0,
        data_dir: dir.clone(),
        ..GatewayConfig::default()
    };
    let state = GatewayState::open(&cfg).expect("open state");
    let handle = spawn_gateway_with_state(state, cfg)
        .await
        .expect("spawn gateway");
    let base = format!("http://127.0.0.1:{}", handle.http_port);

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{base}/api/rf-context"))
        .header("Origin", DASHBOARD_ORIGIN)
        .send()
        .await
        .expect("GET /api/rf-context");

    assert!(resp.status().is_success());
    assert!(
        resp.headers().get("access-control-allow-origin").is_none(),
        "dashboard_origins defaults to empty, so CORS must be off by default"
    );

    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test(flavor = "multi_thread")]
async fn cors_never_applies_outside_the_two_dashboard_routes() {
    let (handle, dir) = spawn_with_dashboard_origin().await;
    let base = format!("http://127.0.0.1:{}", handle.http_port);
    let client = reqwest::Client::new();

    // Even the configured dashboard origin gets nothing on a route the
    // CORS layer was never applied to — the admin/federation/observation
    // surfaces stay same-origin-only in the browser no matter what.
    let resp = client
        .get(format!("{base}/api/observations/recent"))
        .header("Origin", DASHBOARD_ORIGIN)
        .send()
        .await
        .expect("GET /api/observations/recent");

    assert!(resp.status().is_success());
    assert!(
        resp.headers().get("access-control-allow-origin").is_none(),
        "CORS must be scoped to /api/rf-context and /api/stats only"
    );

    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test(flavor = "multi_thread")]
async fn preflight_for_a_write_route_does_not_allow_post() {
    let (handle, dir) = spawn_with_dashboard_origin().await;
    let base = format!("http://127.0.0.1:{}", handle.http_port);

    let client = reqwest::Client::new();
    // A browser preflight (OPTIONS) for a cross-origin POST to an admin
    // route must NOT come back allowing POST — the CORS policy is
    // deliberately GET-only (dashboard reads, not cross-origin writes),
    // and the admin route isn't even inside the CORS-scoped sub-router.
    let resp = client
        .request(reqwest::Method::OPTIONS, format!("{base}/api/admin/command"))
        .header("Origin", DASHBOARD_ORIGIN)
        .header("Access-Control-Request-Method", "POST")
        .send()
        .await
        .expect("OPTIONS preflight");

    let allow_methods = resp
        .headers()
        .get("access-control-allow-methods")
        .map(|v| v.to_str().unwrap_or("").to_string())
        .unwrap_or_default();
    assert!(
        !allow_methods.contains("POST"),
        "CORS policy must stay GET-only, got allow-methods={allow_methods:?}"
    );

    std::fs::remove_dir_all(&dir).ok();
}
