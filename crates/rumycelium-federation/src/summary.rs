//! Signed regional summaries and the minimal federation exchange
//! (ADR-264 §6): biomes federate **signed events and statistical
//! summaries**, never raw measurements.

use crate::biome::{verify_event, Biome};
use crate::sig;
use ed25519_dalek::{Signature, Signer as _};
use rumycelium_core::EnvironmentalEvent;
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
            spec_version: rumycelium_core::SPEC_VERSION.into(),
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

/// Errors raised by [`FederationBus`] publication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FederationError {
    /// The payload carried no signature / signer key.
    Unsigned,
    /// The signature did not verify over the canonical bytes.
    BadSignature,
    /// The signer public key is not a registered biome (hex key attached).
    UnknownBiome(String),
}

impl std::fmt::Display for FederationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FederationError::Unsigned => write!(f, "payload is unsigned"),
            FederationError::BadSignature => write!(f, "signature verification failed"),
            FederationError::UnknownBiome(pk) => {
                write!(f, "signer is not a registered biome: {pk}")
            }
        }
    }
}

impl std::error::Error for FederationError {}

/// Minimal in-memory federation exchange (ADR-264 §7): registered biomes
/// publish signed summaries and events; everything unsigned, unverifiable, or
/// from an unregistered key is rejected.
#[derive(Debug, Clone, Default)]
pub struct FederationBus {
    /// Registered biome public keys (hex).
    biomes: BTreeSet<String>,
    /// Accepted summaries, in publication order.
    summaries: Vec<RegionalSummary>,
    /// Accepted events, in publication order.
    events: Vec<EnvironmentalEvent>,
}

impl FederationBus {
    /// Create an empty bus.
    #[must_use]
    pub fn new() -> Self {
        FederationBus::default()
    }

    /// Register a biome by its hex public key. Only registered biomes may
    /// publish.
    pub fn register_biome(&mut self, pubkey_hex: impl Into<String>) {
        self.biomes.insert(pubkey_hex.into());
    }

    /// Publish a signed regional summary. Rejects unsigned payloads,
    /// unregistered signers, and anything whose signature fails to verify.
    pub fn publish(&mut self, summary: RegionalSummary) -> Result<(), FederationError> {
        let (Some(_), Some(pk)) = (&summary.signature_hex, &summary.signer_pubkey_hex) else {
            return Err(FederationError::Unsigned);
        };
        if !self.biomes.contains(pk) {
            return Err(FederationError::UnknownBiome(pk.clone()));
        }
        if !verify_summary(&summary) {
            return Err(FederationError::BadSignature);
        }
        self.summaries.push(summary);
        Ok(())
    }

    /// Publish a signed environmental event with the same checks, via
    /// [`verify_event`].
    pub fn publish_event(&mut self, event: EnvironmentalEvent) -> Result<(), FederationError> {
        let (Some(_), Some(pk)) = (&event.signature_hex, &event.signer_pubkey_hex) else {
            return Err(FederationError::Unsigned);
        };
        if !self.biomes.contains(pk) {
            return Err(FederationError::UnknownBiome(pk.clone()));
        }
        if !verify_event(&event) {
            return Err(FederationError::BadSignature);
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
    use crate::testutil::{sample, SEED};

    fn biome_with_data() -> Biome {
        let mut b = Biome::new(BiomeConfig::new("biome/test-forest"), SEED);
        b.accept(sample(1, 1, 1_000, 10.0));
        b.accept(sample(1, 2, 2_000, 20.0));
        b.accept(sample(2, 1, 3_000, 30.0));
        b.accept(sample(2, 2, 9_000, 99.0)); // outside [0, 5000) window
        b
    }

    #[test]
    fn summarize_produces_exact_stats() {
        let b = biome_with_data();
        let s = b.summarize(0, 5_000);
        assert_eq!(s.spec_version, rumycelium_core::SPEC_VERSION);
        assert_eq!(s.biome_id, "biome/test-forest");
        let w = &s.stats["weather"];
        assert_eq!(w.count, 3);
        assert!((w.mean - 20.0).abs() < 1e-12);
        assert!((w.min - 10.0).abs() < f64::EPSILON);
        assert!((w.max - 30.0).abs() < f64::EPSILON);
        assert!((w.mean_quality - f64::from(0.9_f32)).abs() < 1e-12);
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

        // Unregistered biome.
        assert_eq!(
            bus.publish(s.clone()),
            Err(FederationError::UnknownBiome(b.public_key_hex()))
        );

        bus.register_biome(b.public_key_hex());

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
    fn bus_publishes_events_with_same_checks() {
        let mut b = biome_with_data();
        let event = b.revoke_device(1, 10_000, "compromised");
        let mut bus = FederationBus::new();

        assert!(matches!(
            bus.publish_event(event.clone()),
            Err(FederationError::UnknownBiome(_))
        ));

        bus.register_biome(b.public_key_hex());

        let mut tampered = event.clone();
        tampered.message.push('!');
        assert_eq!(
            bus.publish_event(tampered),
            Err(FederationError::BadSignature)
        );

        let mut unsigned = event.clone();
        unsigned.signature_hex = None;
        assert_eq!(bus.publish_event(unsigned), Err(FederationError::Unsigned));

        bus.publish_event(event).unwrap();
        assert_eq!(bus.events().len(), 1);
    }

    #[test]
    fn federation_error_displays() {
        assert_eq!(FederationError::Unsigned.to_string(), "payload is unsigned");
        assert!(FederationError::UnknownBiome("ab".into())
            .to_string()
            .contains("ab"));
        assert!(!FederationError::BadSignature.to_string().is_empty());
    }
}
