//! `EnvironmentalEvent` — the signed, federable event class
//! (ADR-264 §6 / §10).

use crate::error::EnvError;
use crate::geo::GeoPoint;
use crate::modality::{DataClass, SensorModality};
use serde::{Deserialize, Serialize};

/// Event severity ladder. RF-only evidence may never exceed `Advisory`
/// (ADR-264 §8) — enforced by `rumycelium-worldgraph`.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Informational; may rest on contextual (RF-only) evidence.
    Advisory,
    /// Elevated attention.
    Watch,
    /// Action recommended.
    Warning,
    /// Immediate action; local safety path (< 250 ms target).
    Critical,
}

/// What kind of event this is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    /// A local anomaly threshold fired.
    ThresholdExceeded,
    /// Statistical anomaly relative to expected behaviour.
    Anomaly,
    /// Physical tampering or displacement suspected.
    SensorTampered,
    /// A sensor was quarantined for drift (never silently corrected).
    SensorQuarantined,
    /// A device key was revoked.
    DeviceRevoked,
    /// Calibration drift detected against an anchor.
    CalibrationDrift,
    /// Flood risk assessment.
    FloodRisk,
    /// Wildfire risk assessment.
    WildfireRisk,
    /// A cross-boundary alert federated from / to a neighbouring biome.
    CrossBoundaryAlert,
}

/// Reference to a contributing observation (dedup key of an accepted
/// `EnvSample`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EvidenceRef {
    /// Producing device.
    pub node_id: u64,
    /// Sample sequence number on that device.
    pub sequence: u32,
}

/// A biome-scoped environmental event. Events are `DataClass::FederatedEvent`
/// — the only class that leaves the biome (ADR-264 §10).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EnvironmentalEvent {
    /// Wire spec version.
    pub spec_version: String,
    /// Unique event id (deterministic in the simulator).
    pub event_id: String,
    /// Owning biome.
    pub biome_id: String,
    /// Event kind.
    pub kind: EventKind,
    /// Severity.
    pub severity: Severity,
    /// Primary modality that produced the evidence.
    pub modality: SensorModality,
    /// Location (possibly coarsened per the biome's disclosure policy).
    pub geo: GeoPoint,
    /// Evidence window start, ns since Unix epoch.
    pub window_start_ns: u64,
    /// Evidence window end, ns since Unix epoch.
    pub window_end_ns: u64,
    /// Detection time, ns since Unix epoch.
    pub detected_ns: u64,
    /// Contributing observations.
    pub evidence: Vec<EvidenceRef>,
    /// Detection confidence `0.0..=1.0`.
    pub confidence: f32,
    /// Human-readable summary.
    pub message: String,
    /// Hex-encoded ed25519 signature by the biome/gateway key, if signed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_hex: Option<String>,
    /// Hex-encoded signer public key, if signed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_pubkey_hex: Option<String>,
}

impl EnvironmentalEvent {
    /// The data class of every environmental event.
    #[must_use]
    pub fn data_class(&self) -> DataClass {
        DataClass::FederatedEvent
    }

    /// Structural validation.
    pub fn validate(&self) -> Result<(), EnvError> {
        self.geo.validate()?;
        if self.event_id.is_empty() {
            return Err(EnvError::MissingField("event_id"));
        }
        if self.biome_id.is_empty() {
            return Err(EnvError::MissingField("biome_id"));
        }
        if !(0.0..=1.0).contains(&self.confidence) || !self.confidence.is_finite() {
            return Err(EnvError::QualityOutOfRange(self.confidence));
        }
        if self.window_end_ns < self.window_start_ns {
            return Err(EnvError::TimeInverted {
                measured_ns: self.window_start_ns,
                received_ns: self.window_end_ns,
            });
        }
        if self.evidence.is_empty() {
            return Err(EnvError::MissingField("evidence"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event() -> EnvironmentalEvent {
        EnvironmentalEvent {
            spec_version: crate::SPEC_VERSION.into(),
            event_id: "evt-0001".into(),
            biome_id: "biome/thames-estuary".into(),
            kind: EventKind::FloodRisk,
            severity: Severity::Warning,
            modality: SensorModality::WaterQuality,
            geo: GeoPoint::new(514_000_000, 500_000, 0).unwrap(),
            window_start_ns: 1_000,
            window_end_ns: 5_000,
            detected_ns: 5_100,
            evidence: vec![EvidenceRef {
                node_id: 7,
                sequence: 42,
            }],
            confidence: 0.9,
            message: "water level rising across 3 nodes".into(),
            signature_hex: None,
            signer_pubkey_hex: None,
        }
    }

    #[test]
    fn valid_event_round_trips() {
        let e = event();
        e.validate().unwrap();
        assert_eq!(e.data_class(), DataClass::FederatedEvent);
        let j = serde_json::to_string(&e).unwrap();
        let back: EnvironmentalEvent = serde_json::from_str(&j).unwrap();
        assert_eq!(e, back);
    }

    #[test]
    fn severity_orders() {
        assert!(Severity::Advisory < Severity::Watch);
        assert!(Severity::Watch < Severity::Warning);
        assert!(Severity::Warning < Severity::Critical);
    }

    #[test]
    fn empty_evidence_rejected() {
        let mut e = event();
        e.evidence.clear();
        assert!(matches!(e.validate(), Err(EnvError::MissingField("evidence"))));
    }
}
