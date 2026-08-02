//! # rumycelium-federation
//!
//! Biome sovereignty for the RuMycelium fabric (ADR-264 §6, §7, §10, §12):
//!
//! - [`OutageBuffer`] — gateway store-and-forward log with duplicate-free
//!   replay across restarts (§14 criteria 2–3),
//! - [`Biome`] — the sovereign regional aggregate: verified-only ingest,
//!   global dedup spanning live ingest and buffer replay, device revocation
//!   as signed events, and delayed / coarsened disclosure,
//! - [`RegionalSummary`] + [`FederationBus`] — signed statistical summaries
//!   are what federate between biomes instead of raw data (§6),
//! - [`sensorthings`] — OGC SensorThings API 1.1 entity projection so every
//!   accepted observation is externally interoperable (§7, §14 criterion 6).
//!
//! Everything is deterministic: ed25519 signing is RFC 8032 deterministic,
//! keys derive from caller-supplied 32-byte seeds, and all timestamps are
//! passed in — no clocks, no RNG.

#![doc(html_root_url = "https://docs.rs/rumycelium-federation/0.1.0")]

pub mod biome;
pub mod buffer;
pub mod sensorthings;
pub mod summary;

pub use biome::{verify_event, AcceptOutcome, Biome, BiomeConfig, DisclosurePolicy};
pub use buffer::OutageBuffer;
pub use sensorthings::{
    project_sample, rfc3339_from_ns, Datastream, FeatureOfInterest, GeoJsonPoint, Location,
    Observation, ObservedProperty, Sensor, SensorThingsBundle, Thing, UnitOfMeasurement,
};
pub use summary::{verify_summary, FederationBus, FederationError, ModalityStats, RegionalSummary};

/// Shared hex + detached-signature helpers (same house style as
/// `rufield-provenance`).
pub(crate) mod sig {
    use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};

    /// Lowercase hex encoding.
    pub(crate) fn hex_encode(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    /// Hex decoding; `None` on odd length or non-hex characters.
    pub(crate) fn hex_decode(s: &str) -> Option<Vec<u8>> {
        if !s.len().is_multiple_of(2) {
            return None;
        }
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
            .collect()
    }

    /// Verify a detached hex ed25519 signature over `msg` with a hex public
    /// key. Any malformed input simply fails verification.
    pub(crate) fn verify_detached(pubkey_hex: &str, sig_hex: &str, msg: &[u8]) -> bool {
        let Some(pk_bytes) = hex_decode(pubkey_hex) else {
            return false;
        };
        let Ok(pk_arr) = <[u8; 32]>::try_from(pk_bytes) else {
            return false;
        };
        let Ok(vk) = VerifyingKey::from_bytes(&pk_arr) else {
            return false;
        };
        let Some(sig_bytes) = hex_decode(sig_hex) else {
            return false;
        };
        let Ok(sig_arr) = <[u8; 64]>::try_from(sig_bytes) else {
            return false;
        };
        let sig = Signature::from_bytes(&sig_arr);
        vk.verify(msg, &sig).is_ok()
    }
}

#[cfg(test)]
pub(crate) mod testutil {
    use rumycelium_core::{EnvSample, GeoPoint, SampleProvenance, SensorModality, Uncertainty};

    /// A valid, verified test sample.
    pub(crate) fn sample(node_id: u64, sequence: u32, measured_ns: u64, value: f64) -> EnvSample {
        EnvSample {
            node_id,
            sequence,
            measured_ns,
            received_ns: measured_ns + 1_000_000,
            geo: GeoPoint::new(514_778_216, -14_767, 46_000).unwrap(),
            modality: SensorModality::Weather,
            observed_property: "air_temperature".into(),
            unit: "Cel".into(),
            value,
            quality: 0.9,
            uncertainty: Uncertainty::symmetric(value, 0.5),
            calibration_id: 1,
            flags: 0,
            battery_mv: 3300,
            provenance: SampleProvenance {
                firmware_hash: "sha256:fw-test".into(),
                signer_pubkey_hex: "aa".into(),
                verified: true,
                lineage: vec!["cal:1".into()],
            },
        }
    }

    /// A deterministic 32-byte signer seed for tests.
    pub(crate) const SEED: &[u8; 32] = b"rumycelium-test-seed-32-bytes-ok";
}
