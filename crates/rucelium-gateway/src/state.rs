//! Shared gateway runtime state (ADR-265 §4).
//!
//! v0.1 concurrency model: **one big lock**. Every mutable component lives in
//! [`Inner`] behind a single `Arc<tokio::sync::Mutex<Inner>>`. The UDP loop,
//! HTTP handlers, federation poller, retention timer, and simulator all take
//! the same lock; per-datagram work is microseconds, so contention is
//! negligible at v0.1 scale and the simplicity buys obvious correctness.
//! Finer-grained locking is deliberate future work.

use crate::config::GatewayConfig;
use rucelium_calibration::{CalibrationStore, Calibrator, DriftDetector};
use rucelium_federation::{Biome, BiomeConfig, RegionalSummary};
use rucelium_ingest::IngestPipeline;
use rucelium_store::{EventStore, ObservationStore};
use rucelium_transport::Reassembler;
use rucelium_worldgraph::WorldGraph;
use serde::Serialize;
use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

/// Max records per observation segment file.
const OBS_SEGMENT_MAX_RECORDS: usize = 4096;
/// Max records per event segment file.
const EVT_SEGMENT_MAX_RECORDS: usize = 1024;
/// Max in-flight partially reassembled messages held by the gateway.
const REASSEMBLER_MAX_PENDING: usize = 256;

/// Nanoseconds since the Unix epoch, from the system clock. The library
/// crates are clock-free; the daemon is where wall time enters the system.
#[must_use]
pub fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// Datagram-level counters for the UDP front door (one bump per received
/// datagram, distinct from the envelope-level `IngestStats`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct DatagramStats {
    /// Datagrams that led to a fully accepted sample.
    pub accepted: u64,
    /// Datagrams rejected at any stage (transport, registry, ingest, store).
    pub rejected: u64,
    /// Fragment datagrams absorbed while awaiting the rest of their message.
    pub fragments: u64,
}

/// A verified regional summary fetched from a federation peer.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PeerSummary {
    /// Peer base URL the summary was fetched from.
    pub peer: String,
    /// The verified signed summary.
    pub summary: RegionalSummary,
    /// When this gateway fetched it (ns since Unix epoch).
    pub fetched_ns: u64,
}

/// Everything mutable in the gateway, guarded by one lock (module docs).
pub struct Inner {
    /// Wire ingest: registry, signatures, anti-replay (ADR-264 §5).
    pub ingest: IngestPipeline,
    /// Calibration records with anchor-rooted lineage.
    pub calibration: CalibrationStore,
    /// Applies calibration; never repairs (ADR-264 §12).
    pub calibrator: Calibrator,
    /// EWMA drift monitor with sticky quarantine.
    pub drift: DriftDetector,
    /// Environmental WorldGraph (ADR-264 §5.2).
    pub graph: WorldGraph,
    /// The sovereign biome aggregate + signing identity.
    pub biome: Biome,
    /// Durable observation log (disk).
    pub obs: ObservationStore,
    /// Durable event log (disk).
    pub events: EventStore,
    /// Fragment reassembly for MTU-constrained links.
    pub reassembler: Reassembler,
    /// Latest verified summary per federation peer.
    pub peer_summaries: Vec<PeerSummary>,
    /// `event_id`s of peer revocation events already applied locally.
    pub applied_revocation_ids: BTreeSet<String>,
    /// How many verified peer `DeviceRevoked` events were applied.
    pub applied_peer_revocations: u64,
    /// Local alert events raised (flood / anomaly rule).
    pub alerts: u64,
    /// Calibration application errors (sample kept raw, never repaired).
    pub calibration_errors: u64,
    /// Datagram-level UDP counters.
    pub datagrams: DatagramStats,
}

impl Inner {
    /// Build the full component stack, opening the durable stores under
    /// `config.data_dir` (`obs/` and `events/` subdirectories).
    pub fn open(config: &GatewayConfig) -> Result<Self, String> {
        let obs = ObservationStore::open(&config.data_dir.join("obs"), OBS_SEGMENT_MAX_RECORDS)
            .map_err(|e| format!("open observation store: {e}"))?;
        let events = EventStore::open(&config.data_dir.join("events"), EVT_SEGMENT_MAX_RECORDS)
            .map_err(|e| format!("open event store: {e}"))?;
        let seed = biome_seed(&config.biome_id, config.seed);
        Ok(Inner {
            ingest: IngestPipeline::default(),
            calibration: CalibrationStore::new(),
            calibrator: Calibrator::default(),
            drift: DriftDetector::default(),
            graph: WorldGraph::new(),
            biome: Biome::new(BiomeConfig::new(config.biome_id.clone()), &seed),
            obs,
            events,
            reassembler: Reassembler::new(REASSEMBLER_MAX_PENDING),
            peer_summaries: Vec::new(),
            applied_revocation_ids: BTreeSet::new(),
            applied_peer_revocations: 0,
            alerts: 0,
            calibration_errors: 0,
            datagrams: DatagramStats::default(),
        })
    }
}

/// Handle shared by every task and HTTP handler. Cheap to clone.
#[derive(Clone)]
pub struct GatewayState {
    /// Biome identity (mirrors the config; readable without the lock).
    pub biome_id: String,
    /// The single mutable state lock (module docs).
    pub inner: Arc<Mutex<Inner>>,
    /// Daemon start time, for `uptime_s`.
    pub started: Instant,
}

impl GatewayState {
    /// Open the durable stores and assemble the gateway state.
    pub fn open(config: &GatewayConfig) -> Result<Self, String> {
        Ok(GatewayState {
            biome_id: config.biome_id.clone(),
            inner: Arc::new(Mutex::new(Inner::open(config)?)),
            started: Instant::now(),
        })
    }
}

/// Derive the biome's 32-byte ed25519 signing seed from the biome id and the
/// numeric config seed: id bytes repeated/truncated, XORed with the seed
/// bytes and an index whitener.
///
/// **Deliberately not cryptographically strong** (v0.1): what matters is
/// that the same `(biome_id, seed)` always yields the same biome identity —
/// determinism, restart-stable keys, distinct keys for distinct biomes. A
/// production deployment provisions the biome key from a real ceremony.
#[must_use]
pub fn biome_seed(biome_id: &str, seed: u64) -> [u8; 32] {
    let id = biome_id.as_bytes();
    let sb = seed.to_le_bytes();
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        let idb = if id.is_empty() {
            0x7A
        } else {
            id[i % id.len()]
        };
        *b = idb ^ sb[i % 8] ^ (i as u8).wrapping_mul(0x9E);
    }
    out
}

#[cfg(test)]
pub(crate) mod testutil {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

    /// Unique per-test temp data dir (name uniqueness only, never store
    /// logic).
    pub(crate) fn temp_dir(tag: &str) -> PathBuf {
        let n = DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
        let t = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "rucelium-gateway-{tag}-{}-{n}-{t}",
            std::process::id()
        ))
    }

    /// A fresh [`Inner`] over a unique temp data dir.
    pub(crate) fn test_inner(tag: &str) -> Inner {
        let config = GatewayConfig {
            data_dir: temp_dir(tag),
            ..GatewayConfig::default()
        };
        Inner::open(&config).expect("test inner opens")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn biome_seed_is_deterministic_and_id_sensitive() {
        assert_eq!(biome_seed("biome/a", 1), biome_seed("biome/a", 1));
        assert_ne!(biome_seed("biome/a", 1), biome_seed("biome/b", 1));
        assert_ne!(biome_seed("biome/a", 1), biome_seed("biome/a", 2));
        // Empty id still yields a stable, non-degenerate seed.
        let empty = biome_seed("", 7);
        assert_eq!(empty, biome_seed("", 7));
        assert!(empty.iter().any(|&b| b != 0));
    }

    #[test]
    fn same_config_reproduces_the_biome_identity() {
        let config = GatewayConfig {
            data_dir: testutil::temp_dir("identity"),
            ..GatewayConfig::default()
        };
        let a = Inner::open(&config).unwrap();
        let b = Inner::open(&config).unwrap();
        assert_eq!(a.biome.public_key_hex(), b.biome.public_key_hex());
        std::fs::remove_dir_all(&config.data_dir).ok();
    }

    #[test]
    fn now_ns_is_monotonic_enough_and_after_2020() {
        let a = now_ns();
        let b = now_ns();
        assert!(b >= a);
        assert!(a > 1_577_836_800_000_000_000, "clock reads before 2020");
    }
}
