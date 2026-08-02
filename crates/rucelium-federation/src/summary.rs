//! Signed regional summaries and the minimal federation exchange
//! (ADR-264 §6): biomes federate **signed events and statistical
//! summaries**, never raw measurements.

use crate::biome::{verify_event, Biome};
use crate::sig;
use ed25519_dalek::{Signature, Signer as _};
use rucelium_core::EnvironmentalEvent;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Per-modality aggregate statistics over one summary window.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ModalityStats {
    /// Number of contributing observations.
    pub count: u64,
    /// Arithmetic mean of the calibrated values.
    pub mean: f64,
    /// Minimum value in the window.
    pub min: f64,
    /// Maximum value in the window.
    pub max: f64,
    /// Mean quality score of the contributing observations.
    pub mean_quality: f64,
}

/// A signed statistical summary of one biome over one time window — the
/// `DataClass::FederatedEvent`-class aggregate that leaves the biome instead
/// of raw data (ADR-264 §6, §10).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RegionalSummary {
    /// Wire spec version.
    pub spec_version: String,
    /// Producing biome.
    pub biome_id: String,
    /// Window start (inclusive), ns since Unix epoch.
    pub window_start_ns: u64,
    /// Window end (exclusive), ns since Unix epoch.
    pub window_end_ns: u64,
    /// Per-modality statistics, keyed by `SensorModality::as_str()` (BTreeMap
    /// for deterministic canonical bytes).
    pub stats: BTreeMap<String, ModalityStats>,
    /// Hex ed25519 signature by the biome key, if signed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_hex: Option<String>,
    /// Hex signer public key, if signed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_pubkey_hex: Option<String>,
}

/// Canonical bytes signed for a summary: the summary with its signature
/// fields cleared, as compact JSON.
fn canonical_summary_bytes(summary: &RegionalSummary) -> Vec<u8> {
    let mut s = summary.clone();
    s.signature_hex = None;
    s.signer_pubkey_hex = None;
    serde_json::to_vec(&s).expect("RegionalSummary JSON serialization cannot fail")
}

/// Verify the biome signature on a summary. `true` only when both signature
/// fields are present and verify over the canonical bytes — any field tamper
/// breaks it.
#[must_use]
pub fn verify_summary(summary: &RegionalSummary) -> bool {
    let (Some(sig_hex), Some(pk_hex)) = (&summary.signature_hex, &summary.signer_pubkey_hex) else {
        return false;
    };
    sig::verify_detached(pk_hex, sig_hex, &canonical_summary_bytes(summary))
}

impl Biome {
    /// Aggregate accepted observations with `measured_ns` in
    /// `[window_start_ns, window_end_ns)` into a per-modality summary, signed
    /// with the biome key. Deterministic: plain sum/count means over the
    /// arrival-ordered observation log.
    #[must_use]
    pub fn summarize(&self, window_start_ns: u64, window_end_ns: u64) -> RegionalSummary {
        struct Acc {
            count: u64,
            sum: f64,
            min: f64,
            max: f64,
            quality_sum: f64,
        }
        let mut acc: BTreeMap<String, Acc> = BTreeMap::new();
        for s in self.observations() {
            if s.measured_ns < window_start_ns || s.measured_ns >= window_end_ns {
                continue;
            }
            let e = acc.entry(s.modality.as_str().to_string()).or_insert(Acc {
                count: 0,
                sum: 0.0,
                min: f64::INFINITY,
                max: f64::NEG_INFINITY,
                quality_sum: 0.0,
            });
            e.count += 1;
            e.sum += s.value;
            e.min = e.min.min(s.value);
            e.max = e.max.max(s.value);
            e.quality_sum += f64::from(s.quality);
        }

        let stats = acc
            .into_iter()
            .map(|(k, a)| {
                let n = a.count as f64;
                (
                    k,
                    ModalityStats {
                        count: a.count,
                        mean: a.sum / n,
                        min: a.min,
                        max: a.max,
                        mean_quality: a.quality_sum / n,
                    },
                )
            })
            .collect();

        let mut summary = RegionalSummary {
            spec_version: rucelium_core::SPEC_VERSION.into(),
            biome_id: self.config().biome_id.clone(),
            window_start_ns,
            window_end_ns,
            stats,
            signature_hex: None,
            signer_pubkey_hex: None,
        };
        self.sign_summary(&mut summary);
        summary
    }

    /// Sign a summary in place with the biome key (canonical bytes with the
    /// signature fields cleared, same pattern as event signing).
    pub fn sign_summary(&self, summary: &mut RegionalSummary) {
        let bytes = canonical_summary_bytes(summary);
        let signature: Signature = self.signing_key().sign(&bytes);
        summary.signature_hex = Some(sig::hex_encode(&signature.to_bytes()));
        summary.signer_pubkey_hex = Some(self.public_key_hex());
    }
}

/// Errors raised by [`FederationBus`] registration and publication, and by
/// [`crate::OutageBuffer`] envelope handling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FederationError {
    /// The payload carried no signature / signer key.
    Unsigned,
    /// The signature did not verify over the canonical bytes.
    BadSignature,
    /// The payload's `biome_id` is not a registered biome.
    UnknownBiome(String),
    /// The payload's signer key is not the key registered for its claimed
    /// `biome_id` — a registered key may not publish under another biome's
    /// identity.
    IdentityMismatch {
        /// The biome identity the payload claimed.
        biome_id: String,
    },
    /// Re-registration attempted with a key epoch at or below the current
    /// one while changing the key — rotation requires a strictly higher
    /// epoch.
    StaleKeyEpoch {
        /// The biome being (re-)registered.
        biome_id: String,
        /// The rejected epoch.
        epoch: u32,
    },
    /// A summary for this `(biome_id, window_start_ns, window_end_ns)` was
    /// already accepted — replayed summaries are rejected.
    DuplicateSummary,
    /// An event with this `event_id` was already accepted — replayed events
    /// are rejected.
    DuplicateEvent,
    /// Bytes did not structurally decode as a signed wire envelope.
    BadEnvelope(String),
}

impl std::fmt::Display for FederationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FederationError::Unsigned => write!(f, "payload is unsigned"),
            FederationError::BadSignature => write!(f, "signature verification failed"),
            FederationError::UnknownBiome(id) => {
                write!(f, "not a registered biome: {id}")
            }
            FederationError::IdentityMismatch { biome_id } => {
                write!(f, "signer key is not the registered key for {biome_id}")
            }
            FederationError::StaleKeyEpoch { biome_id, epoch } => {
                write!(f, "stale key epoch {epoch} for {biome_id}")
            }
            FederationError::DuplicateSummary => {
                write!(f, "summary for this biome and window already accepted")
            }
            FederationError::DuplicateEvent => {
                write!(f, "event with this event_id already accepted")
            }
            FederationError::BadEnvelope(m) => write!(f, "envelope decode failed: {m}"),
        }
    }
}

impl std::error::Error for FederationError {}

/// A biome's registered federation identity: its current public key and the
/// key epoch it was registered under (rotation counter).
#[derive(Debug, Clone, PartialEq, Eq)]
struct BiomeKey {
    /// Hex ed25519 public key currently bound to the biome id.
    pubkey_hex: String,
    /// Monotonic rotation epoch; re-registration must strictly increase it
    /// to change the key.
    key_epoch: u32,
}

/// Minimal in-memory federation exchange (ADR-264 §7): registered biomes
/// publish signed summaries and events. Publication binds federation
/// identity to biome identity — the payload's `biome_id` must be registered
/// and its signer key must be the key registered *for that id* — and is
/// replay-protected: a summary window or event id is accepted at most once.
#[derive(Debug, Clone, Default)]
pub struct FederationBus {
    /// Registered biome identities and their current keys.
    biomes: BTreeMap<String, BiomeKey>,
    /// Accepted summaries, in publication order.
    summaries: Vec<RegionalSummary>,
    /// Accepted events, in publication order.
    events: Vec<EnvironmentalEvent>,
    /// Replay guard: every accepted `(biome_id, window_start_ns,
    /// window_end_ns)` summary window.
    seen_windows: BTreeSet<(String, u64, u64)>,
    /// Replay guard: every accepted `event_id`.
    seen_events: BTreeSet<String>,
}

impl FederationBus {
    /// Create an empty bus.
    #[must_use]
    pub fn new() -> Self {
        FederationBus::default()
    }

    /// Register a biome identity with its hex public key at `key_epoch`.
    /// Only registered biomes may publish, and only under their own
    /// `biome_id`.
    ///
    /// Re-registering the same `biome_id` with a **strictly higher** epoch
    /// replaces the key (rotation); summaries signed by the old key are
    /// rejected from then on. Re-registering with the same key is an
    /// idempotent no-op. A lower-or-equal epoch with a *different* key is
    /// rejected as [`FederationError::StaleKeyEpoch`] — a stolen old
    /// registration cannot roll the identity back.
    pub fn register_biome(
        &mut self,
        biome_id: impl Into<String>,
        pubkey_hex: impl Into<String>,
        key_epoch: u32,
    ) -> Result<(), FederationError> {
        let biome_id = biome_id.into();
        let pubkey_hex = pubkey_hex.into();
        if let Some(current) = self.biomes.get(&biome_id) {
            if key_epoch <= current.key_epoch && pubkey_hex != current.pubkey_hex {
                return Err(FederationError::StaleKeyEpoch {
                    biome_id,
                    epoch: key_epoch,
                });
            }
            if key_epoch <= current.key_epoch {
                return Ok(()); // idempotent re-registration of the same key
            }
        }
        self.biomes.insert(
            biome_id,
            BiomeKey {
                pubkey_hex,
                key_epoch,
            },
        );
        Ok(())
    }

    /// Look up the registered key for a claimed biome id and enforce
    /// identity binding against the payload's signer key.
    fn check_identity(
        &self,
        biome_id: &str,
        signer_pubkey_hex: &str,
    ) -> Result<(), FederationError> {
        let Some(registered) = self.biomes.get(biome_id) else {
            return Err(FederationError::UnknownBiome(biome_id.to_string()));
        };
        if registered.pubkey_hex != signer_pubkey_hex {
            return Err(FederationError::IdentityMismatch {
                biome_id: biome_id.to_string(),
            });
        }
        Ok(())
    }

    /// Publish a signed regional summary. Checks, in order: signature fields
    /// present ([`FederationError::Unsigned`]); `summary.biome_id` registered
    /// ([`FederationError::UnknownBiome`]); signer key is the key registered
    /// for that id ([`FederationError::IdentityMismatch`] — a registered key
    /// claiming another biome's id is rejected); signature verifies
    /// ([`FederationError::BadSignature`]); and the `(biome_id,
    /// window_start_ns, window_end_ns)` window was never accepted before
    /// ([`FederationError::DuplicateSummary`] — replay protection).
    pub fn publish(&mut self, summary: RegionalSummary) -> Result<(), FederationError> {
        let (Some(_), Some(pk)) = (&summary.signature_hex, &summary.signer_pubkey_hex) else {
            return Err(FederationError::Unsigned);
        };
        self.check_identity(&summary.biome_id, pk)?;
        if !verify_summary(&summary) {
            return Err(FederationError::BadSignature);
        }
        let window = (
            summary.biome_id.clone(),
            summary.window_start_ns,
            summary.window_end_ns,
        );
        if !self.seen_windows.insert(window) {
            return Err(FederationError::DuplicateSummary);
        }
        self.summaries.push(summary);
        Ok(())
    }

    /// Publish a signed environmental event with the same identity binding
    /// (via `event.biome_id`) and signature checks as [`Self::publish`],
    /// plus dedup by `event_id` ([`FederationError::DuplicateEvent`]).
    pub fn publish_event(&mut self, event: EnvironmentalEvent) -> Result<(), FederationError> {
        let (Some(_), Some(pk)) = (&event.signature_hex, &event.signer_pubkey_hex) else {
            return Err(FederationError::Unsigned);
        };
        self.check_identity(&event.biome_id, pk)?;
        if !verify_event(&event) {
            return Err(FederationError::BadSignature);
        }
        if !self.seen_events.insert(event.event_id.clone()) {
            return Err(FederationError::DuplicateEvent);
        }
        self.events.push(event);
        Ok(())
    }

    /// Accepted summaries, in publication order.
    #[must_use]
    pub fn summaries(&self) -> &[RegionalSummary] {
        &self.summaries
    }

    /// Accepted events, in publication order.
    #[must_use]
    pub fn events(&self) -> &[EnvironmentalEvent] {
        &self.events
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::biome::BiomeConfig;
    use crate::testutil::{pipeline, verified_sample, SEED};

    const BIOME_ID: &str = "biome/test-forest";

    /// A biome populated through the sealed ingest path — `summarize` runs
    /// over observations that all arrived via `Biome::accept`.
    fn biome_with_data() -> Biome {
        let mut p = pipeline(&[1, 2]);
        let mut b = Biome::new(BiomeConfig::new(BIOME_ID), SEED);
        b.accept(verified_sample(&mut p, 1, 1, 1_000, 10.0));
        b.accept(verified_sample(&mut p, 1, 2, 2_000, 20.0));
        b.accept(verified_sample(&mut p, 2, 1, 3_000, 30.0));
        b.accept(verified_sample(&mut p, 2, 2, 9_000, 99.0)); // outside [0, 5000) window
        b
    }

    /// A registered bus for `biome_with_data`'s biome at epoch 1.
    fn registered_bus(b: &Biome) -> FederationBus {
        let mut bus = FederationBus::new();
        bus.register_biome(BIOME_ID, b.public_key_hex(), 1).unwrap();
        bus
    }

    #[test]
    fn summarize_produces_exact_stats_over_sealed_observations() {
        let b = biome_with_data();
        assert_eq!(b.accepted_count(), 4);
        let s = b.summarize(0, 5_000);
        assert_eq!(s.spec_version, rucelium_core::SPEC_VERSION);
        assert_eq!(s.biome_id, BIOME_ID);
        let w = &s.stats["weather"];
        assert_eq!(w.count, 3);
        assert!((w.mean - 20.0).abs() < 1e-12);
        assert!((w.min - 10.0).abs() < f64::EPSILON);
        assert!((w.max - 30.0).abs() < f64::EPSILON);
        // 0x7000 / 0x8000 in Q0.15 = 0.875 exactly.
        assert!((w.mean_quality - 0.875).abs() < 1e-12);
        // Window is half-open: measured_ns = 9_000 excluded.
        assert_eq!(s.stats.len(), 1);
    }

    #[test]
    fn summary_sign_verify_round_trip_and_tamper() {
        let b = biome_with_data();
        let s = b.summarize(0, 5_000);
        assert!(verify_summary(&s));

        // Serde round trip preserves the signature.
        let json = serde_json::to_string(&s).unwrap();
        let back: RegionalSummary = serde_json::from_str(&json).unwrap();
        assert!(verify_summary(&back));

        // Tampered mean fails.
        let mut t = s.clone();
        t.stats.get_mut("weather").unwrap().mean = 21.0;
        assert!(!verify_summary(&t));

        // Tampered window fails.
        let mut t = s.clone();
        t.window_end_ns += 1;
        assert!(!verify_summary(&t));

        // Unsigned fails.
        let mut t = s.clone();
        t.signature_hex = None;
        assert!(!verify_summary(&t));
    }

    #[test]
    fn bus_rejects_unknown_tampered_and_unsigned_accepts_good() {
        let b = biome_with_data();
        let s = b.summarize(0, 5_000);
        let mut bus = FederationBus::new();

        // Unregistered biome id.
        assert_eq!(
            bus.publish(s.clone()),
            Err(FederationError::UnknownBiome(BIOME_ID.into()))
        );

        bus.register_biome(BIOME_ID, b.public_key_hex(), 1).unwrap();

        // Unsigned.
        let mut unsigned = s.clone();
        unsigned.signature_hex = None;
        unsigned.signer_pubkey_hex = None;
        assert_eq!(bus.publish(unsigned), Err(FederationError::Unsigned));

        // Tampered.
        let mut tampered = s.clone();
        tampered.stats.get_mut("weather").unwrap().count = 999;
        assert_eq!(bus.publish(tampered), Err(FederationError::BadSignature));

        // Good.
        bus.publish(s).unwrap();
        assert_eq!(bus.summaries().len(), 1);
    }

    #[test]
    fn registered_key_claiming_another_biome_id_is_rejected() {
        let b = biome_with_data();
        let mut bus = registered_bus(&b);
        // A second, honestly registered biome with a different key.
        let other = Biome::new(
            BiomeConfig::new("biome/other"),
            b"rucelium-other-seed-32-bytes-ok!",
        );
        bus.register_biome("biome/other", other.public_key_hex(), 1)
            .unwrap();

        // Attack: our registered key signs a summary claiming biome/other's
        // identity. The signature verifies and the key IS registered — but
        // not for that biome_id.
        let mut cross = b.summarize(0, 5_000);
        cross.biome_id = "biome/other".into();
        b.sign_summary(&mut cross);
        assert!(verify_summary(&cross));
        assert_eq!(
            bus.publish(cross),
            Err(FederationError::IdentityMismatch {
                biome_id: "biome/other".into()
            })
        );
        assert!(bus.summaries().is_empty());
    }

    #[test]
    fn duplicate_summary_window_is_rejected() {
        let b = biome_with_data();
        let mut bus = registered_bus(&b);
        let s = b.summarize(0, 5_000);
        bus.publish(s.clone()).unwrap();
        // Exact replay.
        assert_eq!(bus.publish(s), Err(FederationError::DuplicateSummary));
        // Same window, freshly re-signed: still a duplicate.
        let mut again = b.summarize(0, 5_000);
        b.sign_summary(&mut again);
        assert_eq!(bus.publish(again), Err(FederationError::DuplicateSummary));
        // A different window is fine.
        bus.publish(b.summarize(5_000, 10_000)).unwrap();
        assert_eq!(bus.summaries().len(), 2);
    }

    #[test]
    fn key_rotation_replaces_key_and_rejects_stale_epochs() {
        let b = biome_with_data();
        let mut bus = registered_bus(&b);
        let old_key_summary = b.summarize(0, 5_000);

        // Rotate: a new biome key at a strictly higher epoch.
        let rotated = Biome::new(
            BiomeConfig::new(BIOME_ID),
            b"rucelium-rotated-seed-32-bytes-!",
        );
        bus.register_biome(BIOME_ID, rotated.public_key_hex(), 2)
            .unwrap();

        // The old key's summary is now an identity mismatch.
        assert_eq!(
            bus.publish(old_key_summary),
            Err(FederationError::IdentityMismatch {
                biome_id: BIOME_ID.into()
            })
        );
        // The rotated key publishes fine.
        bus.publish(rotated.summarize(0, 5_000)).unwrap();

        // Rolling back to the old key at a lower or equal epoch fails.
        assert_eq!(
            bus.register_biome(BIOME_ID, b.public_key_hex(), 1),
            Err(FederationError::StaleKeyEpoch {
                biome_id: BIOME_ID.into(),
                epoch: 1
            })
        );
        assert_eq!(
            bus.register_biome(BIOME_ID, b.public_key_hex(), 2),
            Err(FederationError::StaleKeyEpoch {
                biome_id: BIOME_ID.into(),
                epoch: 2
            })
        );
        // Idempotent re-registration of the current key is a no-op.
        bus.register_biome(BIOME_ID, rotated.public_key_hex(), 2)
            .unwrap();
    }

    #[test]
    fn bus_publishes_events_with_identity_binding_and_event_dedup() {
        let mut b = biome_with_data();
        let event = b.revoke_device(1, 10_000, "compromised");
        let mut bus = FederationBus::new();

        assert_eq!(
            bus.publish_event(event.clone()),
            Err(FederationError::UnknownBiome(BIOME_ID.into()))
        );

        bus.register_biome(BIOME_ID, b.public_key_hex(), 1).unwrap();

        let mut tampered = event.clone();
        tampered.message.push('!');
        assert_eq!(
            bus.publish_event(tampered),
            Err(FederationError::BadSignature)
        );

        let mut unsigned = event.clone();
        unsigned.signature_hex = None;
        assert_eq!(bus.publish_event(unsigned), Err(FederationError::Unsigned));

        // Identity binding: the same registered key claiming another
        // registered biome's id is rejected.
        let other = Biome::new(
            BiomeConfig::new("biome/other"),
            b"rucelium-other-seed-32-bytes-ok!",
        );
        bus.register_biome("biome/other", other.public_key_hex(), 1)
            .unwrap();
        let mut cross = event.clone();
        cross.biome_id = "biome/other".into();
        b.sign_event(&mut cross);
        assert_eq!(
            bus.publish_event(cross),
            Err(FederationError::IdentityMismatch {
                biome_id: "biome/other".into()
            })
        );

        bus.publish_event(event.clone()).unwrap();
        assert_eq!(bus.events().len(), 1);

        // Replay by event_id is rejected.
        assert_eq!(
            bus.publish_event(event),
            Err(FederationError::DuplicateEvent)
        );
        assert_eq!(bus.events().len(), 1);
    }

    #[test]
    fn federation_error_displays() {
        assert_eq!(FederationError::Unsigned.to_string(), "payload is unsigned");
        assert!(FederationError::UnknownBiome("biome/x".into())
            .to_string()
            .contains("biome/x"));
        assert!(!FederationError::BadSignature.to_string().is_empty());
        assert!(FederationError::IdentityMismatch {
            biome_id: "biome/x".into()
        }
        .to_string()
        .contains("biome/x"));
        assert!(FederationError::StaleKeyEpoch {
            biome_id: "biome/x".into(),
            epoch: 3
        }
        .to_string()
        .contains('3'));
        assert!(!FederationError::DuplicateSummary.to_string().is_empty());
        assert!(!FederationError::DuplicateEvent.to_string().is_empty());
        assert!(FederationError::BadEnvelope("boom".into())
            .to_string()
            .contains("boom"));
    }
}
