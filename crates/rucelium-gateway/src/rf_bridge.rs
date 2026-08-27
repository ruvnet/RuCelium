//! RuView RF-context ingest (ADR-264 §8) — two *different* kinds of "fusion",
//! only one of which this module does.
//!
//! Polls an external RuView `wifi-densepose-sensing-server`'s `GET
//! /api/field` (ADR-262 P3), verifies each event's provenance receipt, keeps
//! a bounded ring of the resulting [`RfContext`]s, and runs verified events
//! through [`rufield_fusion::RuFieldFusion`] to produce real room-state
//! inferences (`person_present`, `motion`, …) — all exposed at
//! `GET /api/rf-context`.
//!
//! ## Two fusions, not one
//!
//! * **`rufield_fusion::RuFieldFusion` (this module, real, wired in below)**
//!   — a temporal-window fusion *within* the RF domain: it combines this
//!   upstream's own `FieldEvent`s over a short window into inferences using
//!   RuField's own rule set. It needs nothing external — no environmental
//!   sample, no biome, no zone mapping — so there is nothing to fabricate.
//!   This is the same engine `rufield-viewer` already runs on the exact same
//!   event stream; wiring it here just makes the gateway able to answer
//!   "what does this RF upstream currently think is happening" on its own.
//! * **`rucelium_worldgraph::fuse_rf_context` (still NOT called here)** — a
//!   *cross-domain* fusion: pairing an `RfContext` against a *specific*
//!   existing environmental sample's WorldGraph node to compute a
//!   [`rucelium_worldgraph::Plausibility`] verdict (does the RF context
//!   support or contradict *that* biome sensor's reading). Nothing in this
//!   codebase yet defines which biome zone/sensor a given RuView device is
//!   supposed to corroborate, and inventing that pairing would be exactly
//!   the fabricated correlation ADR-264 §8 exists to prevent. That
//!   zone-pairing design is still deliberate follow-up work, not guessed at
//!   — this module does not touch the WorldGraph.
//!
//! ## Honesty
//!
//! Every event is receipt-checked via [`rufield_provenance::is_fusable`] and
//! tagged `verified: bool` in the stored ring — an unverified event is kept
//! visible (like a forged-data ✗ badge) but is excluded from the fusion
//! engine entirely (mirrors `rufield-viewer`'s own rule: forged data is never
//! rendered as trusted). `/api/rf-context` reports
//! `"fused_into_worldgraph": false` explicitly, so a consumer never has to
//! infer the WorldGraph boundary from absence.

use rucelium_worldgraph::RfContext;
use rufield_core::{FieldEvent, FusionEngine, InferenceQuery};
use rufield_fusion::RuFieldFusion;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::time::Duration;

use crate::state::{now_ns, GatewayState};

/// Bounded ring size for recently ingested RF context (mirrors
/// `wifi-densepose-sensing-server`'s own `FIELD_RING_CAPACITY` convention —
/// a live tap, not a store).
pub const RF_RECENT_CAPACITY: usize = 64;

/// Default poll interval for `GET <upstream>/api/field`, matching
/// `rufield-viewer`'s own default.
pub const DEFAULT_RF_POLL_MS: u64 = 500;

/// One ingested RF context plus its verification outcome and local receipt
/// time.
#[derive(Debug, Clone, Serialize)]
pub struct RfEntry {
    /// The distilled RF context (never ground truth — ADR-264 §8).
    pub context: RfContext,
    /// Whether the source `FieldEvent`'s provenance receipt verified
    /// (`rufield_provenance::is_fusable`). `false` means the bytes were
    /// reached but the signature/hash did not check out — stored so a forged
    /// or corrupted upstream is *visible*, never silently dropped.
    pub verified: bool,
    /// When this gateway received the event, ns since Unix epoch.
    pub received_ns: u64,
}

/// Ingest counters, exposed at `GET /api/rf-context`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct RfIngestStats {
    /// Successful polls of the upstream `/api/field` ring.
    pub polls: u64,
    /// Polls that failed (unreachable, non-2xx, or a malformed payload).
    pub poll_failures: u64,
    /// Total `FieldEvent`s received across all polls.
    pub events_received: u64,
    /// Received events whose provenance receipt verified.
    pub events_verified: u64,
    /// Received events whose provenance receipt did NOT verify (stored,
    /// flagged, never trusted).
    pub events_unverified: u64,
    /// Received events that were not `Modality::WifiCsi` and so are not RF
    /// context this bridge understands (`RfContext::from_field_event`
    /// returns `None`). Not an error — RuView's ring may carry other
    /// modalities over time.
    pub events_other_modality: u64,
}

/// Shape of RuView's `GET /api/field` response that this bridge actually
/// needs. Deliberately declares **only** `events`: the response also carries
/// `signer_pubkey_hex` and `dev_signing_key`, but their exact shape is
/// RuView's to evolve (see `ruvnet/RuCelium#1`, where a *different* consumer
/// of this same endpoint broke because it over-specified those two
/// informational fields). Serde drops unknown fields by default — no
/// `deny_unknown_fields` — so this struct is inert to that class of drift.
#[derive(Debug, Deserialize)]
struct ApiFieldPayload {
    events: Vec<FieldEvent>,
}

/// Pure ingest step (no I/O — unit-testable): fold one batch of freshly
/// polled `FieldEvent`s into the bounded ring, the counters, and the
/// within-RF-domain fusion engine (module docs: this is the fusion that
/// needs no external pairing, so it runs unconditionally on every verified
/// event).
pub fn ingest_events(
    recent: &mut VecDeque<RfEntry>,
    stats: &mut RfIngestStats,
    fusion: &mut RuFieldFusion,
    events: &[FieldEvent],
    received_ns: u64,
) {
    stats.polls += 1;
    for ev in events {
        stats.events_received += 1;
        let verified = rufield_provenance::is_fusable(ev);
        if verified {
            stats.events_verified += 1;
            // Mirrors rufield-viewer's own rule: only verified events reach
            // the fusion engine. `ingest` itself re-checks §11 fusability
            // (belt-and-suspenders), so forged data cannot reach it either way.
            let _ = fusion.ingest(ev.clone());
        } else {
            stats.events_unverified += 1;
        }
        match RfContext::from_field_event(ev) {
            Some(context) => {
                if recent.len() == RF_RECENT_CAPACITY {
                    recent.pop_front();
                }
                recent.push_back(RfEntry {
                    context,
                    verified,
                    received_ns,
                });
            }
            None => stats.events_other_modality += 1,
        }
    }
}

/// Record a failed poll attempt (unreachable upstream, non-2xx, or a
/// malformed payload). Never fatal — the next tick tries again.
pub fn record_poll_failure(stats: &mut RfIngestStats) {
    stats.poll_failures += 1;
}

/// Current room-state inferences from the within-RF-domain fusion engine
/// (module docs: the fusion that needs no external pairing). Empty on a
/// query error — `infer` errors only on the engine's own internal
/// consistency checks, not on caller input, so this stays a best-effort read
/// rather than a `Result` the HTTP handler has to plumb through.
#[must_use]
pub fn current_inferences(fusion: &RuFieldFusion) -> Vec<rufield_core::FieldInference> {
    fusion.infer(&InferenceQuery::all()).unwrap_or_default()
}

/// Fetch and decode one `GET <upstream>/api/field` response. The only I/O in
/// this module — everything else is pure and covered by unit tests.
async fn poll_once(client: &reqwest::Client, url: &str) -> Result<Vec<FieldEvent>, String> {
    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("http {}", resp.status()));
    }
    let body = resp
        .text()
        .await
        .map_err(|e| format!("read body: {e}"))?;
    let payload: ApiFieldPayload =
        serde_json::from_str(&body).map_err(|e| format!("decode /api/field: {e}"))?;
    Ok(payload.events)
}

/// Run the RF ingest task forever: poll `<upstream>/api/field` every
/// `poll_ms`, verify each event, and fold accepted RF context into
/// [`crate::state::Inner::rf_recent`]. Never fatal — an unreachable upstream
/// or a malformed payload just counts a failure and retries on the next
/// tick.
pub async fn run_rf_ingest(state: GatewayState, upstream: String, poll_ms: u64) {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(_) => return,
    };
    let url = format!("{}/api/field", upstream.trim_end_matches('/'));
    let mut tick = tokio::time::interval(Duration::from_millis(poll_ms.max(50)));
    loop {
        tick.tick().await;
        match poll_once(&client, &url).await {
            Ok(events) => {
                let received_ns = now_ns();
                let mut guard = state.inner.lock().await;
                let inner = &mut *guard;
                ingest_events(
                    &mut inner.rf_recent,
                    &mut inner.rf_stats,
                    &mut inner.rf_fusion,
                    &events,
                    received_ns,
                );
            }
            Err(e) => {
                eprintln!("gateway: rf-context poll of {url} failed: {e}");
                let mut inner = state.inner.lock().await;
                record_poll_failure(&mut inner.rf_stats);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rufield_core::{
        FieldAxis, FieldTensor, Modality, Observation, PrivacyClass, ProvenanceRef,
        SensorDescriptor,
    };
    use rufield_provenance::Signer;

    fn wifi_csi_event(device_id: &str, signed: bool) -> FieldEvent {
        let tensor = FieldTensor::new(
            1_000,
            Modality::WifiCsi,
            vec![FieldAxis::Frequency],
            vec![2],
            vec![0.1, 0.2],
            0.9,
            0.01,
            Some("cal".into()),
            PrivacyClass::P2,
        )
        .unwrap();
        let mut observation = Observation::occupancy(0.8, PrivacyClass::P2);
        observation
            .features
            .insert("motion_energy".to_string(), 0.7);
        // "presence" is what `rufield-fusion`'s default `person_present` rule
        // (rules/room_state.toml) actually keys on — without it the fusion
        // regression tests below would pass trivially (no rule ever fires).
        observation.features.insert("presence".to_string(), 0.8);
        let mut ev = FieldEvent::new(
            format!("ev-{device_id}"),
            1_000,
            SensorDescriptor {
                modality: "wifi_csi".into(),
                vendor: "simulated".into(),
                device_id: device_id.to_string(),
                placement: "unknown".into(),
                clock_domain: "local".into(),
            },
            tensor,
            observation,
            ProvenanceRef {
                raw_hash: "sha256:raw".into(),
                firmware_hash: "sha256:fw".into(),
                model_id: "m".into(),
                calibration_id: "cal".into(),
                // Deliberately non-synthetic: `is_fusable` short-circuits to
                // `true` for synthetic events regardless of signature, which
                // would make the "unsigned → unverified" test meaningless.
                // Real verification only actually runs when this is `false`.
                synthetic: false,
                signature_hex: None,
                signer_pubkey_hex: None,
            },
        );
        if signed {
            Signer::from_seed(b"rf-bridge-test-seed-32-bytes-ok!")
                .sign_event(&mut ev)
                .expect("test event signs");
        }
        ev
    }

    fn other_modality_event() -> FieldEvent {
        let tensor = FieldTensor::new(
            1_000,
            Modality::MmwaveRadar,
            vec![FieldAxis::Frequency],
            vec![1],
            vec![0.5],
            0.5,
            0.01,
            None,
            PrivacyClass::P2,
        )
        .unwrap();
        FieldEvent::new(
            "ev-radar",
            1_000,
            SensorDescriptor {
                modality: "mmwave_radar".into(),
                vendor: "sim".into(),
                device_id: "radar-1".into(),
                placement: "unknown".into(),
                clock_domain: "local".into(),
            },
            tensor,
            Observation::occupancy(0.5, PrivacyClass::P2),
            ProvenanceRef {
                raw_hash: "sha256:raw".into(),
                firmware_hash: "sha256:fw".into(),
                model_id: "m".into(),
                calibration_id: "cal".into(),
                synthetic: true,
                signature_hex: None,
                signer_pubkey_hex: None,
            },
        )
    }

    #[test]
    fn verified_wifi_csi_event_is_stored_and_counted() {
        let mut recent = VecDeque::new();
        let mut stats = RfIngestStats::default();
        let mut fusion = RuFieldFusion::new();
        let ev = wifi_csi_event("node-1", true);

        ingest_events(&mut recent, &mut stats, &mut fusion, std::slice::from_ref(&ev), 5_000);

        assert_eq!(recent.len(), 1);
        assert!(recent[0].verified);
        assert_eq!(recent[0].context.device_id, "node-1");
        assert_eq!(recent[0].received_ns, 5_000);
        assert_eq!(stats.polls, 1);
        assert_eq!(stats.events_received, 1);
        assert_eq!(stats.events_verified, 1);
        assert_eq!(stats.events_unverified, 0);
        assert_eq!(stats.events_other_modality, 0);
    }

    #[test]
    fn unsigned_event_is_stored_but_flagged_unverified() {
        let mut recent = VecDeque::new();
        let mut stats = RfIngestStats::default();
        let mut fusion = RuFieldFusion::new();
        let ev = wifi_csi_event("node-2", false);

        ingest_events(&mut recent, &mut stats, &mut fusion, std::slice::from_ref(&ev), 1);

        assert_eq!(recent.len(), 1, "unverified events are still visible, not dropped");
        assert!(!recent[0].verified);
        assert_eq!(stats.events_unverified, 1);
        assert_eq!(stats.events_verified, 0);
    }

    #[test]
    fn non_wifi_csi_event_is_not_stored_as_rf_context() {
        let mut recent = VecDeque::new();
        let mut stats = RfIngestStats::default();
        let mut fusion = RuFieldFusion::new();
        let ev = other_modality_event();

        ingest_events(&mut recent, &mut stats, &mut fusion, std::slice::from_ref(&ev), 1);

        assert!(recent.is_empty());
        assert_eq!(stats.events_other_modality, 1);
        assert_eq!(stats.events_received, 1, "still counted as received");
    }

    #[test]
    fn ring_is_bounded_and_drops_oldest() {
        let mut recent = VecDeque::new();
        let mut stats = RfIngestStats::default();
        let mut fusion = RuFieldFusion::new();
        for i in 0..(RF_RECENT_CAPACITY + 10) {
            let ev = wifi_csi_event(&format!("node-{i}"), true);
            ingest_events(&mut recent, &mut stats, &mut fusion, std::slice::from_ref(&ev), i as u64);
        }
        assert_eq!(recent.len(), RF_RECENT_CAPACITY);
        // Oldest entries evicted first: the front should be from late in the
        // sequence, not node-0.
        assert_ne!(recent.front().unwrap().context.device_id, "node-0");
        assert_eq!(
            recent.back().unwrap().context.device_id,
            format!("node-{}", RF_RECENT_CAPACITY + 9)
        );
    }

    #[test]
    fn verified_events_actually_reach_the_fusion_engine() {
        let mut recent = VecDeque::new();
        let mut stats = RfIngestStats::default();
        let mut fusion = RuFieldFusion::new();
        let ev = wifi_csi_event("node-fused", true);

        ingest_events(&mut recent, &mut stats, &mut fusion, std::slice::from_ref(&ev), 1);

        let inferences = current_inferences(&fusion);
        assert!(
            inferences.iter().any(|i| i.label == "person_present"),
            "a verified presence-bearing event should produce a person_present \
             inference from RuField's own default room-state rules, got: {inferences:?}"
        );
    }

    #[test]
    fn unverified_events_never_reach_the_fusion_engine() {
        let mut recent = VecDeque::new();
        let mut stats = RfIngestStats::default();
        let mut fusion = RuFieldFusion::new();
        let ev = wifi_csi_event("node-forged", false);

        ingest_events(&mut recent, &mut stats, &mut fusion, std::slice::from_ref(&ev), 1);

        let inferences = current_inferences(&fusion);
        assert!(
            inferences.is_empty(),
            "an unverified event must never influence a fused inference, got: {inferences:?}"
        );
    }

    #[test]
    fn poll_failure_is_counted_and_never_touches_the_ring() {
        let recent: VecDeque<RfEntry> = VecDeque::new();
        let mut stats = RfIngestStats::default();
        record_poll_failure(&mut stats);
        record_poll_failure(&mut stats);
        assert_eq!(stats.poll_failures, 2);
        assert!(recent.is_empty());
    }
}
