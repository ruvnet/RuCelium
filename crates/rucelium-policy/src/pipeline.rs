//! The governed control path itself (ADR-264 §9), stage by stage:
//!
//! ```text
//! AgentProposal → PolicyEngine::evaluate      → EvaluatedProposal
//!               → SafetySimulator::simulate   → SimulatedProposal
//!               → AuthorityRegistry::authorize → AuthorizedProposal
//!               → CommandSigner::sign         → SignedCommand
//!               → GatewayValidator::validate_and_execute → ExecutionReceipt
//! ```
//!
//! [`EvaluatedProposal`], [`SimulatedProposal`], and [`AuthorizedProposal`]
//! have private fields and **no public constructor** — the only way to obtain
//! one is to pass the previous gate, so skipping a stage is a compile error.
//! [`SignedCommand`] crosses the network, so at that hop the gate is
//! cryptography (an ed25519 signature by a key the gateway trusts), not type
//! privacy.

use crate::audit::AuditTrail;
use crate::proposal::{AgentProposal, ProposalKind};
use crate::ControlError;
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

// ---------------------------------------------------------------------------
// hex / hash helpers (house style, matching rufield-provenance)
// ---------------------------------------------------------------------------

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn hex_decode(s: &str) -> Result<Vec<u8>, ControlError> {
    if !s.len().is_multiple_of(2) {
        return Err(ControlError::BadEncoding("odd hex length".into()));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|e| ControlError::BadEncoding(e.to_string()))
        })
        .collect()
}

/// `sha256:<hex>` digest over arbitrary bytes.
fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    let mut s = String::from("sha256:");
    for b in h.finalize() {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

// ---------------------------------------------------------------------------
// Stage 1 — deterministic policy evaluation
// ---------------------------------------------------------------------------

/// Deterministic policy rules for [`PolicyEngine`].
#[derive(Debug, Clone, PartialEq)]
pub struct PolicyConfig {
    /// Minimum allowed sampling interval, seconds (default 10).
    pub min_sampling_interval_s: u32,
    /// Maximum allowed sampling interval, seconds (default 86 400 = 1 day).
    pub max_sampling_interval_s: u32,
    /// Maximum absolute actuator magnitude policy will ever accept
    /// (default 1.0). The safety envelope may be tighter — that is a
    /// separate gate.
    pub max_actuator_magnitude: f64,
    /// Actuators agents may target at all. Empty by default: no actuator
    /// command passes policy until the biome owner lists its actuators.
    pub allowed_actuators: BTreeSet<String>,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        PolicyConfig {
            min_sampling_interval_s: 10,
            max_sampling_interval_s: 86_400,
            max_actuator_magnitude: 1.0,
            allowed_actuators: BTreeSet::new(),
        }
    }
}

/// Stage 1: deterministic policy evaluation. The only entry point into the
/// governed control path — it is the sole producer of [`EvaluatedProposal`].
#[derive(Debug, Default, Clone)]
pub struct PolicyEngine {
    config: PolicyConfig,
}

/// Witness that a proposal passed deterministic policy evaluation.
/// Private fields, no public constructor: the only producer is
/// [`PolicyEngine::evaluate`], and the only consumer is
/// [`SafetySimulator::simulate`].
#[derive(Debug, Clone, PartialEq)]
pub struct EvaluatedProposal {
    proposal: AgentProposal,
    evaluated_ns: u64,
}

impl EvaluatedProposal {
    /// The underlying proposal (read-only).
    #[must_use]
    pub fn proposal(&self) -> &AgentProposal {
        &self.proposal
    }

    /// When policy evaluation ran, ns since Unix epoch.
    #[must_use]
    pub fn evaluated_ns(&self) -> u64 {
        self.evaluated_ns
    }
}

impl PolicyEngine {
    /// Engine with the given rules.
    #[must_use]
    pub fn new(config: PolicyConfig) -> Self {
        PolicyEngine { config }
    }

    /// Evaluate a raw agent proposal against deterministic policy rules.
    ///
    /// Records the `"proposed"` audit entry on entry and a
    /// `"policy_evaluated"` entry with the verdict (accepted or rejected).
    pub fn evaluate(
        &self,
        proposal: AgentProposal,
        now_ns: u64,
        audit: &mut AuditTrail,
    ) -> Result<EvaluatedProposal, ControlError> {
        audit.record(
            "proposed",
            &proposal.proposal_id,
            now_ns,
            format!(
                "agent {} proposes in biome {}",
                proposal.agent_id, proposal.biome_id
            ),
        );
        match self.check(&proposal) {
            Ok(()) => {
                audit.record(
                    "policy_evaluated",
                    &proposal.proposal_id,
                    now_ns,
                    "accepted",
                );
                Ok(EvaluatedProposal {
                    proposal,
                    evaluated_ns: now_ns,
                })
            }
            Err(e) => {
                audit.record(
                    "policy_evaluated",
                    &proposal.proposal_id,
                    now_ns,
                    format!("rejected: {e}"),
                );
                Err(e)
            }
        }
    }

    fn check(&self, p: &AgentProposal) -> Result<(), ControlError> {
        for (name, value) in [
            ("proposal_id", &p.proposal_id),
            ("agent_id", &p.agent_id),
            ("biome_id", &p.biome_id),
            ("justification", &p.justification),
        ] {
            if value.is_empty() {
                return Err(ControlError::PolicyViolation(format!("empty {name}")));
            }
        }
        match &p.kind {
            ProposalKind::SetSamplingRate { interval_s, .. } => {
                if *interval_s < self.config.min_sampling_interval_s
                    || *interval_s > self.config.max_sampling_interval_s
                {
                    return Err(ControlError::PolicyViolation(format!(
                        "sampling interval {interval_s}s outside [{}, {}]s",
                        self.config.min_sampling_interval_s, self.config.max_sampling_interval_s
                    )));
                }
            }
            ProposalKind::DeployModel {
                model_id,
                target_gateway,
            } => {
                if model_id.is_empty() {
                    return Err(ControlError::PolicyViolation("empty model_id".into()));
                }
                if target_gateway.is_empty() {
                    return Err(ControlError::PolicyViolation("empty target_gateway".into()));
                }
            }
            ProposalKind::RepositionSensor { to, .. } => {
                to.validate().map_err(|e| {
                    ControlError::PolicyViolation(format!("invalid target geo: {e}"))
                })?;
            }
            ProposalKind::ActuatorCommand {
                actuator_id,
                magnitude,
                ..
            } => {
                if !self.config.allowed_actuators.contains(actuator_id) {
                    return Err(ControlError::PolicyViolation(format!(
                        "actuator {actuator_id} is not in the allowed set"
                    )));
                }
                if !magnitude.is_finite() || magnitude.abs() > self.config.max_actuator_magnitude {
                    return Err(ControlError::PolicyViolation(format!(
                        "actuator magnitude {magnitude} exceeds policy maximum {}",
                        self.config.max_actuator_magnitude
                    )));
                }
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Stage 2 — safety simulation
// ---------------------------------------------------------------------------

/// Safety envelope for [`SafetySimulator`]. Deliberately tighter than policy:
/// something policy allows can still be unsafe.
#[derive(Debug, Clone, PartialEq)]
pub struct SafetyConfig {
    /// Maximum absolute actuator magnitude the simulator considers safe
    /// (default 0.8 — tighter than the policy default of 1.0).
    pub safe_magnitude: f64,
    /// Maximum number of commands the simulator will pass per actuator
    /// (default 10) — a deterministic stand-in for rate limiting.
    pub max_commands_per_actuator: u32,
}

impl Default for SafetyConfig {
    fn default() -> Self {
        SafetyConfig {
            safe_magnitude: 0.8,
            max_commands_per_actuator: 10,
        }
    }
}

/// Witness that a proposal passed the safety simulation. Private fields, no
/// public constructor: produced only by [`SafetySimulator::simulate`],
/// consumed only by [`AuthorityRegistry::authorize`].
#[derive(Debug, Clone, PartialEq)]
pub struct SimulatedProposal {
    proposal: AgentProposal,
    simulated_ns: u64,
}

impl SimulatedProposal {
    /// The underlying proposal (read-only).
    #[must_use]
    pub fn proposal(&self) -> &AgentProposal {
        &self.proposal
    }

    /// When the safety simulation ran, ns since Unix epoch.
    #[must_use]
    pub fn simulated_ns(&self) -> u64 {
        self.simulated_ns
    }
}

/// Stage 2: deterministic safety simulation. Takes `&mut self` because it
/// tracks how many commands each actuator has been issued.
#[derive(Debug, Default, Clone)]
pub struct SafetySimulator {
    config: SafetyConfig,
    issued: BTreeMap<String, u32>,
}

impl SafetySimulator {
    /// Simulator with the given safety envelope.
    #[must_use]
    pub fn new(config: SafetyConfig) -> Self {
        SafetySimulator {
            config,
            issued: BTreeMap::new(),
        }
    }

    /// Run the safety simulation over a policy-evaluated proposal.
    ///
    /// An actuator magnitude beyond [`SafetyConfig::safe_magnitude`] fails
    /// [`ControlError::Unsafe`] even when policy allowed it — policy and
    /// safety are distinct gates. Records a `"safety_simulated"` audit entry
    /// either way.
    pub fn simulate(
        &mut self,
        p: EvaluatedProposal,
        now_ns: u64,
        audit: &mut AuditTrail,
    ) -> Result<SimulatedProposal, ControlError> {
        let proposal_id = p.proposal.proposal_id.clone();
        if let ProposalKind::ActuatorCommand {
            actuator_id,
            magnitude,
            ..
        } = &p.proposal.kind
        {
            if magnitude.abs() > self.config.safe_magnitude {
                let e = ControlError::Unsafe(format!(
                    "magnitude {magnitude} exceeds safety envelope {}",
                    self.config.safe_magnitude
                ));
                audit.record(
                    "safety_simulated",
                    &proposal_id,
                    now_ns,
                    format!("rejected: {e}"),
                );
                return Err(e);
            }
            let count = self.issued.entry(actuator_id.clone()).or_insert(0);
            if *count >= self.config.max_commands_per_actuator {
                let e = ControlError::Unsafe(format!(
                    "actuator {actuator_id} command budget exhausted ({} max)",
                    self.config.max_commands_per_actuator
                ));
                audit.record(
                    "safety_simulated",
                    &proposal_id,
                    now_ns,
                    format!("rejected: {e}"),
                );
                return Err(e);
            }
            *count += 1;
        }
        audit.record(
            "safety_simulated",
            &proposal_id,
            now_ns,
            "within safety envelope",
        );
        Ok(SimulatedProposal {
            proposal: p.proposal,
            simulated_ns: now_ns,
        })
    }
}

// ---------------------------------------------------------------------------
// Stage 3 — authority check
// ---------------------------------------------------------------------------

/// Witness that a proposal is authorized for its biome. Private fields, no
/// public constructor: produced only by [`AuthorityRegistry::authorize`],
/// consumed only by [`CommandSigner::sign`].
#[derive(Debug, Clone, PartialEq)]
pub struct AuthorizedProposal {
    proposal: AgentProposal,
    authorized_ns: u64,
}

impl AuthorizedProposal {
    /// The underlying proposal (read-only).
    #[must_use]
    pub fn proposal(&self) -> &AgentProposal {
        &self.proposal
    }

    /// When authorization was checked, ns since Unix epoch.
    #[must_use]
    pub fn authorized_ns(&self) -> u64 {
        self.authorized_ns
    }
}

/// Stage 3: per-biome authority. Actuator authority never leaves the biome
/// owner (ADR-264 §6): an [`ProposalKind::ActuatorCommand`] requires an exact
/// `(biome, agent, actuator)` grant; all non-actuator kinds are
/// auto-authorized for the proposing biome.
#[derive(Debug, Default, Clone)]
pub struct AuthorityRegistry {
    grants: BTreeSet<(String, String, String)>,
}

impl AuthorityRegistry {
    /// Empty registry: no actuator grants at all.
    #[must_use]
    pub fn new() -> Self {
        AuthorityRegistry::default()
    }

    /// Biome-owner grant: allow `agent_id` to command `actuator_id` inside
    /// `biome_id`.
    pub fn grant(&mut self, biome_id: &str, agent_id: &str, actuator_id: &str) {
        self.grants.insert((
            biome_id.to_string(),
            agent_id.to_string(),
            actuator_id.to_string(),
        ));
    }

    /// Check authority for a safety-simulated proposal. Records an
    /// `"authorized"` audit entry with the verdict.
    pub fn authorize(
        &self,
        p: SimulatedProposal,
        now_ns: u64,
        audit: &mut AuditTrail,
    ) -> Result<AuthorizedProposal, ControlError> {
        let proposal_id = p.proposal.proposal_id.clone();
        if let ProposalKind::ActuatorCommand { actuator_id, .. } = &p.proposal.kind {
            let key = (
                p.proposal.biome_id.clone(),
                p.proposal.agent_id.clone(),
                actuator_id.clone(),
            );
            if !self.grants.contains(&key) {
                let e = ControlError::NotAuthorized {
                    biome_id: p.proposal.biome_id.clone(),
                    agent_id: p.proposal.agent_id.clone(),
                    actuator_id: actuator_id.clone(),
                };
                audit.record("authorized", &proposal_id, now_ns, format!("rejected: {e}"));
                return Err(e);
            }
        }
        audit.record("authorized", &proposal_id, now_ns, "granted");
        Ok(AuthorizedProposal {
            proposal: p.proposal,
            authorized_ns: now_ns,
        })
    }
}

// ---------------------------------------------------------------------------
// Stage 4 — signed command
// ---------------------------------------------------------------------------

/// The exact material an ed25519 command signature covers, with a fixed,
/// derive-defined field order so `serde_json::to_vec` is canonical and
/// deterministic.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CommandPayload {
    /// Command id, `"cmd-{proposal_id}"`.
    pub command_id: String,
    /// Biome the command targets.
    pub biome_id: String,
    /// Agent that proposed it.
    pub agent_id: String,
    /// What to do.
    pub kind: ProposalKind,
    /// When the command was issued, ns since Unix epoch.
    pub issued_ns: u64,
    /// When the command expires, ns since Unix epoch.
    pub expires_ns: u64,
}

/// A signed, time-limited command — the only artifact a gateway will execute.
///
/// Unlike the in-process stage witnesses, a `SignedCommand` crosses the
/// network, so it is `Serialize`/`Deserialize` with public fields. **Type
/// privacy is not the gate at this hop — cryptography is.** Anyone can
/// deserialize or hand-forge one of these, but [`GatewayValidator`] rejects
/// it unless the ed25519 signature verifies over the canonical payload bytes
/// under a key the gateway explicitly trusts.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignedCommand {
    /// The signed material (canonical bytes are `serde_json::to_vec` of this).
    pub payload: CommandPayload,
    /// Hex-encoded ed25519 signature over [`SignedCommand::canonical_bytes`].
    pub signature_hex: String,
    /// Hex-encoded ed25519 public key of the signer.
    pub signer_pubkey_hex: String,
}

impl SignedCommand {
    /// Command id (`"cmd-{proposal_id}"`).
    #[must_use]
    pub fn command_id(&self) -> &str {
        &self.payload.command_id
    }

    /// Issue time, ns since Unix epoch.
    #[must_use]
    pub fn issued_ns(&self) -> u64 {
        self.payload.issued_ns
    }

    /// Expiry time, ns since Unix epoch.
    #[must_use]
    pub fn expires_ns(&self) -> u64 {
        self.payload.expires_ns
    }

    /// Canonical JSON bytes of the payload — exactly what the signature
    /// covers. Deterministic: derived `Serialize` emits fields in declaration
    /// order.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        canonical_bytes(&self.payload)
    }
}

fn canonical_bytes(payload: &CommandPayload) -> Vec<u8> {
    // Infallible for this struct: string keys only, and any non-finite
    // magnitude was already rejected by the policy gate.
    serde_json::to_vec(payload).expect("CommandPayload serialization cannot fail")
}

/// Stage 4: deterministic ed25519 command signer, key derived from a 32-byte
/// seed (same house style as `rufield-provenance::Signer`). Same seed ⇒ same
/// key ⇒ same signatures — no RNG anywhere.
pub struct CommandSigner {
    key: SigningKey,
}

impl CommandSigner {
    /// Signer from a fixed 32-byte seed.
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        CommandSigner {
            key: SigningKey::from_bytes(seed),
        }
    }

    /// Hex-encoded public key — hand this to [`GatewayValidator::new`].
    #[must_use]
    pub fn public_hex(&self) -> String {
        hex_encode(self.key.verifying_key().as_bytes())
    }

    /// Sign an authorized proposal into a time-limited [`SignedCommand`]
    /// (`expires_ns = issued_ns + ttl_ns`, saturating). Records a `"signed"`
    /// audit entry.
    #[must_use]
    pub fn sign(
        &self,
        p: AuthorizedProposal,
        issued_ns: u64,
        ttl_ns: u64,
        audit: &mut AuditTrail,
    ) -> SignedCommand {
        let expires_ns = issued_ns.saturating_add(ttl_ns);
        let payload = CommandPayload {
            command_id: format!("cmd-{}", p.proposal.proposal_id),
            biome_id: p.proposal.biome_id.clone(),
            agent_id: p.proposal.agent_id.clone(),
            kind: p.proposal.kind.clone(),
            issued_ns,
            expires_ns,
        };
        let sig: Signature = self.key.sign(&canonical_bytes(&payload));
        audit.record(
            "signed",
            &p.proposal.proposal_id,
            issued_ns,
            format!(
                "command {} signed, expires_ns={expires_ns}",
                payload.command_id
            ),
        );
        SignedCommand {
            payload,
            signature_hex: hex_encode(&sig.to_bytes()),
            signer_pubkey_hex: self.public_hex(),
        }
    }
}

// ---------------------------------------------------------------------------
// Stages 5 + 6 — gateway validation and local execution
// ---------------------------------------------------------------------------

/// Read-only view of the command kind handed to the execution closure.
pub type ProposalKindView = ProposalKind;

/// Terminal artifact of the governed control path: proof that a command was
/// validated and executed exactly once.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExecutionReceipt {
    /// Executed command.
    pub command_id: String,
    /// Execution time, ns since Unix epoch (caller-supplied).
    pub executed_ns: u64,
    /// Outcome string returned by the local execution closure.
    pub outcome: String,
    /// `sha256:` over `"{command_id}|{executed_ns}|{outcome}"` — deterministic
    /// for identical runs.
    pub gateway_receipt_hash: String,
}

/// Stages 5 and 6: gateway-side validation and local execution.
///
/// Checks, in order: the signer key is trusted
/// ([`ControlError::UntrustedKey`]), the signature verifies over the
/// canonical bytes ([`ControlError::BadSignature`]), the command has not
/// expired ([`ControlError::Expired`]), and the command id has not already
/// executed ([`ControlError::DuplicateCommand`] — replay protection). Only
/// then does the execution closure run, exactly once per command id.
#[derive(Debug, Clone)]
pub struct GatewayValidator {
    trusted: BTreeSet<String>,
    executed: BTreeSet<String>,
}

impl GatewayValidator {
    /// Validator trusting the given hex-encoded ed25519 public keys.
    #[must_use]
    pub fn new(trusted_keys: Vec<String>) -> Self {
        GatewayValidator {
            trusted: trusted_keys.into_iter().collect(),
            executed: BTreeSet::new(),
        }
    }

    /// Validate a signed command and, on success, run `execute` (the local
    /// execution) and return the [`ExecutionReceipt`]. Records
    /// `"gateway_validated"` (with the verdict, pass or fail) and, on
    /// success, `"executed"` audit entries.
    pub fn validate_and_execute<F: FnOnce(&ProposalKindView) -> String>(
        &mut self,
        cmd: &SignedCommand,
        now_ns: u64,
        execute: F,
        audit: &mut AuditTrail,
    ) -> Result<ExecutionReceipt, ControlError> {
        // Audit under the originating proposal id so the trail lines up.
        let proposal_id = cmd
            .payload
            .command_id
            .strip_prefix("cmd-")
            .unwrap_or(&cmd.payload.command_id)
            .to_string();
        if let Err(e) = self.check(cmd, now_ns) {
            audit.record(
                "gateway_validated",
                &proposal_id,
                now_ns,
                format!("rejected: {e}"),
            );
            return Err(e);
        }
        audit.record(
            "gateway_validated",
            &proposal_id,
            now_ns,
            "signature and freshness ok",
        );
        self.executed.insert(cmd.payload.command_id.clone());
        let outcome = execute(&cmd.payload.kind);
        let gateway_receipt_hash =
            sha256_hex(format!("{}|{now_ns}|{outcome}", cmd.payload.command_id).as_bytes());
        audit.record(
            "executed",
            &proposal_id,
            now_ns,
            format!("outcome: {outcome}"),
        );
        Ok(ExecutionReceipt {
            command_id: cmd.payload.command_id.clone(),
            executed_ns: now_ns,
            outcome,
            gateway_receipt_hash,
        })
    }

    fn check(&self, cmd: &SignedCommand, now_ns: u64) -> Result<(), ControlError> {
        if !self.trusted.contains(&cmd.signer_pubkey_hex) {
            return Err(ControlError::UntrustedKey(cmd.signer_pubkey_hex.clone()));
        }
        let pk_bytes = hex_decode(&cmd.signer_pubkey_hex)?;
        let pk_arr: [u8; 32] = pk_bytes
            .try_into()
            .map_err(|_| ControlError::BadEncoding("pubkey not 32 bytes".into()))?;
        let vk = VerifyingKey::from_bytes(&pk_arr)
            .map_err(|e| ControlError::BadEncoding(e.to_string()))?;
        let sig_bytes = hex_decode(&cmd.signature_hex)?;
        let sig_arr: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| ControlError::BadEncoding("signature not 64 bytes".into()))?;
        let sig = Signature::from_bytes(&sig_arr);
        vk.verify(&cmd.canonical_bytes(), &sig)
            .map_err(|_| ControlError::BadSignature)?;
        if now_ns >= cmd.payload.expires_ns {
            return Err(ControlError::Expired {
                expires_ns: cmd.payload.expires_ns,
                now_ns,
            });
        }
        if self.executed.contains(&cmd.payload.command_id) {
            return Err(ControlError::DuplicateCommand(
                cmd.payload.command_id.clone(),
            ));
        }
        Ok(())
    }
}
