//! CORS regression guard for the read-only dashboard use case (`api::cors_layer`
//! doc comment): a same-machine dashboard on a different origin/port must be
//! able to read this gateway's JSON without a proxy, and the policy must stay
//! GET-only.

use rucelium_gateway::{spawn_gateway_with_state, GatewayConfig, GatewayState};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_dir(tag: &str) -> PathBuf {
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("rucelium-gw-cors-{tag}-{}-{t}", std::process::id()))
}

#[tokio::test(flavor = "multi_thread")]
async fn get_responses_carry_a_permissive_cors_header() {
    let dir = temp_dir("get");
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
        .get(format!("{base}/api/stats"))
        .header("Origin", "http://127.0.0.1:8080") // a plausible RuView `ui/` origin
        .send()
        .await
        .expect("GET /api/stats");

    assert!(resp.status().is_success());
    let allow_origin = resp
        .headers()
        .get("access-control-allow-origin")
        .expect("CORS header must be present on a GET response")
        .to_str()
        .unwrap();
    assert_eq!(
        allow_origin, "*",
        "any-origin GET access is the documented policy (api::cors_layer)"
    );

    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test(flavor = "multi_thread")]
async fn preflight_for_a_write_route_does_not_allow_post() {
    let dir = temp_dir("post");
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
    // A browser preflight (OPTIONS) for a cross-origin POST to an admin
    // route must NOT come back allowing POST — the CORS policy is
    // deliberately GET-only (dashboard reads, not cross-origin writes).
    let resp = client
        .request(reqwest::Method::OPTIONS, format!("{base}/api/admin/command"))
        .header("Origin", "http://127.0.0.1:8080")
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
