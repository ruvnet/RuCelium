//! Network federation sync (ADR-265 §4): a background task polls each
//! configured peer's `/api/federation/{pubkey,summary,revocations}`,
//! verifies every ed25519 signature against the peer's **published** biome
//! key, stores verified summaries, and applies verified `DeviceRevoked`
//! events to the local registry. Unverifiable data is skipped and logged —
//! never applied, never repaired (ADR-264 §12). Only signed summaries and
//! events ever cross the wire, preserving biome sovereignty (ADR-264 §6).

use crate::state::{now_ns, GatewayState, Inner, PeerSummary};
use rucelium_core::{EnvironmentalEvent, EventKind};
use rucelium_federation::{verify_event, verify_summary, RegionalSummary};
use serde::Deserialize;
use std::time::Duration;

/// Window (seconds) requested from each peer's summary endpoint.
const PEER_SUMMARY_WINDOW_S: u64 = 3600;
/// Per-request HTTP timeout.
const HTTP_TIMEOUT: Duration = Duration::from_secs(5);

/// Response shape of `GET /api/federation/pubkey`.
#[derive(Debug, Deserialize)]
struct PubkeyResponse {
    /// Peer biome identity.
    biome_id: String,
    /// Peer biome ed25519 public key, hex.
    pubkey_hex: String,
}

/// Apply one peer `DeviceRevoked` event to the local registry. Returns
/// `true` only when the event was **verified and newly applied**:
///
/// 1. `kind == DeviceRevoked`;
/// 2. the event's signer key equals the peer's published key (a valid
///    signature from any *other* key is refused — peers may only revoke on
///    their own authority);
/// 3. the ed25519 signature verifies over the canonical event bytes;
/// 4. the `event_id` was not already applied;
/// 5. the target node is registered locally (otherwise the event is left
///    unapplied so a later provisioning can pick it up on the next poll).
///
/// Factored out of the network task so it is unit-testable without any I/O.
pub fn apply_peer_revocation(
    inner: &mut Inner,
    event: &EnvironmentalEvent,
    peer_pubkey_hex: &str,
) -> bool {
    if event.kind != EventKind::DeviceRevoked {
        return false;
    }
    if event.signer_pubkey_hex.as_deref() != Some(peer_pubkey_hex) {
        return false;
    }
    if !verify_event(event) {
        return false;
    }
    let Some(evidence) = event.evidence.first() else {
        return false;
    };
    if inner.applied_revocation_ids.contains(&event.event_id) {
        return false;
    }
    if inner.ingest.registry().get(evidence.node_id).is_none() {
        return false;
    }
    inner.ingest.registry_mut().revoke(evidence.node_id);
    inner.applied_revocation_ids.insert(event.event_id.clone());
    inner.applied_peer_revocations += 1;
    true
}

/// Run the federation poller forever: every `poll_ms`, sync each peer. Peer
/// failures are logged and never fatal — a dead peer must not stop the
/// others (or the gateway).
pub async fn run_federation(state: GatewayState, peers: Vec<String>, poll_ms: u64) {
    let client = match reqwest::Client::builder().timeout(HTTP_TIMEOUT).build() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("gateway: federation disabled, http client failed: {e}");
            return;
        }
    };
    let mut tick = tokio::time::interval(Duration::from_millis(poll_ms.max(50)));
    loop {
        tick.tick().await;
        for peer in &peers {
            if let Err(e) = sync_peer(&state, &client, peer).await {
                eprintln!("gateway: federation peer {peer}: {e}");
            }
        }
    }
}

/// One sync pass against one peer: pubkey, then summary, then revocations.
async fn sync_peer(
    state: &GatewayState,
    client: &reqwest::Client,
    peer: &str,
) -> Result<(), String> {
    let base = peer.trim_end_matches('/');

    let pk: PubkeyResponse = fetch_json(client, &format!("{base}/api/federation/pubkey")).await?;

    let summary: RegionalSummary = fetch_json(
        client,
        &format!("{base}/api/federation/summary?window_s={PEER_SUMMARY_WINDOW_S}"),
    )
    .await?;
    if verify_summary(&summary) && summary.signer_pubkey_hex.as_deref() == Some(&pk.pubkey_hex) {
        let mut inner = state.inner.lock().await;
        inner.peer_summaries.retain(|p| p.peer != peer);
        inner.peer_summaries.push(PeerSummary {
            peer: peer.to_string(),
            summary,
            fetched_ns: now_ns(),
        });
    } else {
        eprintln!(
            "gateway: skipping unverifiable summary from peer {peer} (biome {})",
            pk.biome_id
        );
    }

    let revocations: Vec<EnvironmentalEvent> =
        fetch_json(client, &format!("{base}/api/federation/revocations")).await?;
    let mut inner = state.inner.lock().await;
    for event in &revocations {
        if apply_peer_revocation(&mut inner, event, &pk.pubkey_hex) {
            eprintln!(
                "gateway: applied revocation {} from peer {peer}",
                event.event_id
            );
        }
    }
    Ok(())
}

/// GET a JSON body, mapping transport and decode failures to strings.
async fn fetch_json<T: serde::de::DeserializeOwned>(
    client: &reqwest::Client,
    url: &str,
) -> Result<T, String> {
    client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("GET {url}: {e}"))?
        .error_for_status()
        .map_err(|e| format!("GET {url}: {e}"))?
        .json::<T>()
        .await
        .map_err(|e| format!("decode {url}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::testutil::test_inner;
    use rucelium_abi::{NodeSigner, RvEnvSampleV1, RV_ENV_SCHEMA_V1};
    use rucelium_federation::{Biome, BiomeConfig};
    use rucelium_ingest::RejectReason;

    const PEER_SEED: &[u8; 32] = b"rucelium-peer-biome-seed-32-b!!!";
    const OTHER_SEED: &[u8; 32] = b"rucelium-wrong-key-seed-32-byte!";
    const NODE_SEED: &[u8; 32] = b"rucelium-gateway-test-seed-32b!!";
    const NODE: u64 = 0x5C00_0000_0000_0042;

    /// A valid wire sample from `NODE`.
    fn wire(sequence: u32) -> RvEnvSampleV1 {
        RvEnvSampleV1 {
            schema_version: RV_ENV_SCHEMA_V1,
            sensor_type: 5, // weather
            flags: 0,
            node_id: NODE,
            timestamp_ns: 1_754_000_000_000_000_000,
            sequence,
            latitude_e7: 514_778_216,
            longitude_e7: -14_767,
            altitude_mm: 46_000,
            value_q16: 16 * 65_536,
            quality_q15: 0x7000,
            battery_mv: 3_600,
            calibration_id: 0,
        }
    }

    fn peer_biome() -> Biome {
        Biome::new(BiomeConfig::new("biome/peer"), PEER_SEED)
    }

    fn inner_with_registered_node(tag: &str) -> Inner {
        let mut inner = test_inner(tag);
        inner.ingest.registry_mut().register(
            NODE,
            NodeSigner::for_node(NODE_SEED, NODE).public_key(),
            "sha256:fw".into(),
        );
        inner
    }

    #[test]
    fn verified_peer_revocation_is_applied_once_and_registry_rejects() {
        let mut inner = inner_with_registered_node("fed-apply");
        let mut peer = peer_biome();
        let event = peer.revoke_device(NODE, 1_000, "compromised");

        assert!(apply_peer_revocation(
            &mut inner,
            &event,
            &peer.public_key_hex()
        ));
        assert!(inner.ingest.registry().is_revoked(NODE));
        assert_eq!(inner.applied_peer_revocations, 1);

        // Idempotent: the same event never counts twice.
        assert!(!apply_peer_revocation(
            &mut inner,
            &event,
            &peer.public_key_hex()
        ));
        assert_eq!(inner.applied_peer_revocations, 1);

        // The revoked node's envelopes are rejected at ingest from now on.
        let env = NodeSigner::for_node(NODE_SEED, NODE)
            .sign_sample(&wire(1))
            .encode();
        assert_eq!(
            inner.ingest.ingest(&env, crate::state::now_ns()),
            Err(RejectReason::RevokedDevice(NODE))
        );
    }

    #[test]
    fn event_signed_by_the_wrong_key_is_not_applied() {
        let mut inner = inner_with_registered_node("fed-wrong-key");
        let peer = peer_biome();
        // A different biome signs a revocation but claims the peer's slot.
        let mut impostor = Biome::new(BiomeConfig::new("biome/impostor"), OTHER_SEED);
        let event = impostor.revoke_device(NODE, 1_000, "forged");

        // The impostor's signature is valid — but not the peer's key.
        assert!(verify_event(&event));
        assert!(!apply_peer_revocation(
            &mut inner,
            &event,
            &peer.public_key_hex()
        ));
        assert!(!inner.ingest.registry().is_revoked(NODE));
        assert_eq!(inner.applied_peer_revocations, 0);
    }

    #[test]
    fn tampered_or_wrong_kind_events_are_not_applied() {
        let mut inner = inner_with_registered_node("fed-tamper");
        let mut peer = peer_biome();
        let event = peer.revoke_device(NODE, 1_000, "compromised");

        let mut tampered = event.clone();
        tampered.message.push('!');
        assert!(!apply_peer_revocation(
            &mut inner,
            &tampered,
            &peer.public_key_hex()
        ));

        let mut wrong_kind = event.clone();
        wrong_kind.kind = EventKind::Anomaly;
        peer.sign_event(&mut wrong_kind);
        assert!(!apply_peer_revocation(
            &mut inner,
            &wrong_kind,
            &peer.public_key_hex()
        ));

        assert!(!inner.ingest.registry().is_revoked(NODE));
        assert_eq!(inner.applied_peer_revocations, 0);
    }

    #[test]
    fn unregistered_node_leaves_event_unapplied_for_retry() {
        let mut inner = test_inner("fed-unregistered");
        let mut peer = peer_biome();
        let event = peer.revoke_device(NODE, 1_000, "compromised");
        assert!(!apply_peer_revocation(
            &mut inner,
            &event,
            &peer.public_key_hex()
        ));
        // After provisioning, the same event applies on the next poll.
        inner
            .ingest
            .registry_mut()
            .register(NODE, [0xAA; 32], "sha256:fw".into());
        assert!(apply_peer_revocation(
            &mut inner,
            &event,
            &peer.public_key_hex()
        ));
        assert!(inner.ingest.registry().is_revoked(NODE));
    }
}
