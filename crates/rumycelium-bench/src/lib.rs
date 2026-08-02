//! # rumycelium-bench
//!
//! Deterministic **SYNTHETIC** biome benchmark for RuMycelium (ADR-264 §14).

pub mod report;
pub mod sim;

pub use report::{BiomeReport, Criterion};
pub use sim::{BiomeSim, Emission, EmissionKind, SimConfig, DEFAULT_SEED};

/// Run the full ADR-264 §14 acceptance benchmark. (Runner lands with the
/// mid-layer crates.)
#[must_use]
pub fn run(_config: SimConfig) -> BiomeReport {
    unimplemented!("runner lands after the mid-layer crates")
}
