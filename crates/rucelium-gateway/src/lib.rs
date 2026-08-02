//! # rucelium-gateway
//!
//! The RuCelium rhizome gateway daemon (ADR-265 §4): one tokio/axum binary
//! composing the library crates into the ADR-264 Layer-2 rhizome.
//!
//! ```text
//! UDP :7464  ──► envelope detect (v1 CBOR / v2 compact / fragments)
//!            ──► reassemble ──► registry + signature + anti-replay (ingest)
//!            ──► calibration + drift quarantine
//!            ──► ObservationStore (disk) + WorldGraph + local alert rules
//!            ──► EventStore + biome-signed events
//! HTTP :7465 ──► /health /api/stats /api/observations/recent /api/events
//!            ──► /api/sensorthings/{Things,Datastreams,Observations}
//!            ──► /api/federation/{pubkey,summary,revocations,peers}
//! ```
//!
//! A background task federates with configured peers (verified signed
//! summaries and `DeviceRevoked` events only — ADR-264 §6), a retention
//! timer enforces the ADR-264 §10 lifespans, and `--simulate N` spawns a
//! clearly-labelled SYNTHETIC spore-node traffic generator.
//!
//! **SECURITY (v0.1)**: the HTTP admin endpoints are unauthenticated — bind
//! the HTTP port to localhost or firewall it (see [`api`]).

#![doc(html_root_url = "https://docs.rs/rucelium-gateway/0.1.0")]

pub mod api;
pub mod config;
pub mod federation;
pub mod net;
pub mod pipeline;
pub mod simulate;
pub mod state;

pub use config::GatewayConfig;
pub use pipeline::{process_datagram, ProcessOutcome};
pub use state::{GatewayState, Inner, PeerSummary};

use rucelium_core::DataClass;
use std::time::Duration;
use tokio::task::JoinHandle;

/// A running gateway: its shared state, the actual bound ports (useful when
/// the config asked for port `0`), and the spawned task handles.
pub struct GatewayHandle {
    /// Shared runtime state (also usable for test provisioning).
    pub state: GatewayState,
    /// Actual UDP ingest port.
    pub udp_port: u16,
    /// Actual HTTP API port.
    pub http_port: u16,
    /// Every background task spawned for this gateway. Aborting them (or
    /// dropping the runtime) stops the gateway.
    pub tasks: Vec<JoinHandle<()>>,
}

/// Open the gateway state and start the full stack (UDP loop, HTTP server,
/// retention timer, federation poller when peers are configured, simulator
/// when `--simulate N > 0`). Binds both ports before returning, so callers
/// can pass port `0` and read the real ports from the handle.
pub async fn spawn_gateway(config: GatewayConfig) -> Result<GatewayHandle, String> {
    let state = GatewayState::open(&config)?;
    spawn_gateway_with_state(state, config).await
}

/// Like [`spawn_gateway`], but over a pre-built [`GatewayState`] — lets
/// tests provision devices deterministically before any traffic or
/// federation poll can race them.
pub async fn spawn_gateway_with_state(
    state: GatewayState,
    config: GatewayConfig,
) -> Result<GatewayHandle, String> {
    let udp = tokio::net::UdpSocket::bind(("0.0.0.0", config.udp_port))
        .await
        .map_err(|e| format!("bind udp port {}: {e}", config.udp_port))?;
    let udp_port = udp
        .local_addr()
        .map_err(|e| format!("udp local_addr: {e}"))?
        .port();
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", config.http_port))
        .await
        .map_err(|e| format!("bind http port {}: {e}", config.http_port))?;
    let http_port = listener
        .local_addr()
        .map_err(|e| format!("http local_addr: {e}"))?
        .port();

    let mut tasks = Vec::new();
    tasks.push(tokio::spawn(net::run_udp(udp, state.clone())));

    let router = api::router(state.clone());
    tasks.push(tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, router).await {
            eprintln!("gateway: http server error: {e}");
        }
    }));

    tasks.push(tokio::spawn(run_retention(
        state.clone(),
        config.retention_check_secs,
    )));

    if !config.peers.is_empty() {
        tasks.push(tokio::spawn(federation::run_federation(
            state.clone(),
            config.peers.clone(),
            config.federation_poll_ms,
        )));
    }

    if config.simulate > 0 {
        tasks.push(tokio::spawn(simulate::run_simulator(
            state.clone(),
            config.simulate,
            config.seed,
            config.sim_interval_ms,
            udp_port,
        )));
    }

    Ok(GatewayHandle {
        state,
        udp_port,
        http_port,
        tasks,
    })
}

/// Retention timer: every `check_secs`, drop expired observation segments
/// (normalized samples are `DataClass::DerivedFeature`, ADR-264 §10 — raw
/// signal never reaches the store, and events keep their years-long
/// retention untouched in v0.1) and evict stale partial reassemblies.
async fn run_retention(state: GatewayState, check_secs: u64) {
    /// Partial messages older than this are abandoned (lost fragments).
    const FRAG_TIMEOUT_NS: u64 = 60_000_000_000;
    let retention_ns = DataClass::DerivedFeature.default_retention_ns();
    let mut tick = tokio::time::interval(Duration::from_secs(check_secs.max(1)));
    tick.tick().await; // consume the immediate first tick
    loop {
        tick.tick().await;
        let now = state::now_ns();
        let mut inner = state.inner.lock().await;
        match inner.obs.enforce_retention(now, retention_ns) {
            Ok(0) => {}
            Ok(n) => eprintln!("gateway: retention deleted {n} expired observations"),
            Err(e) => eprintln!("gateway: retention enforcement failed: {e}"),
        }
        inner
            .reassembler
            .evict_older_than(now.saturating_sub(FRAG_TIMEOUT_NS));
    }
}
