// Who is on the other end of a connection.
//
// iroh authenticates the remote endpoint id (QUIC/TLS proves the peer holds
// its secret key), but not the k5. The peer proves its k5 in the hello with
// its self attestation and its iroh attestation, signed by that k5 and naming
// the authenticated endpoint id. A replayed record is useless without the
// endpoint's secret key.
//
// Access is limited to the web of trust: the k5s reachable from the local
// one through keysigns, as `attest merge` does.

use iroh::EndpointId;
use k5lib::{
    api::K5,
    attestations::{iroh as iroh_record, me},
    message::Keyring,
};

/// A peer whose k5 was proven by its records.
pub struct Peer {
    pub k5: String,
    me_record: String,
    iroh_record: String,
}

/// The hex form of an endpoint id, as in iroh attestations.
pub fn endpoint_hex(id: &EndpointId) -> String {
    hex::encode(id.as_bytes())
}

/// Parses the hex form of an endpoint id.
pub fn parse_endpoint(endpoint: &str) -> Result<EndpointId, String> {
    let bytes: [u8; 32] = hex::decode(endpoint)
        .map_err(|e| format!("invalid endpoint id `{endpoint}`: {e}"))?
        .try_into()
        .map_err(|_| format!("invalid endpoint id `{endpoint}`: expected 32 bytes"))?;
    EndpointId::from_bytes(&bytes).map_err(|e| format!("invalid endpoint id `{endpoint}`: {e}"))
}

/// Verifies the records of a hello from the endpoint `remote`: a self
/// attestation, and an iroh attestation signed by the same k5 naming
/// `remote`.
pub fn verify(me_record: &str, iroh_record: &str, remote: &EndpointId) -> Result<Peer, String> {
    let me = me::verify(me_record).map_err(|e| format!("invalid self attestation: {e}"))?;
    if me.fake {
        return Err("fake identity".to_string());
    }
    let keyring = Keyring::from([(me.k5.clone(), me.public)]);
    let iroh = iroh_record::verify(iroh_record, &keyring)
        .map_err(|e| format!("invalid iroh attestation: {e}"))?;
    if iroh.k5 != me.k5 {
        return Err(format!(
            "iroh attestation of k5:{} with the self attestation of k5:{}",
            iroh.k5, me.k5
        ));
    }
    if iroh.endpoint != endpoint_hex(remote) {
        return Err(format!(
            "iroh attestation of k5:{} is for endpoint {}, not {}",
            iroh.k5,
            iroh.endpoint,
            endpoint_hex(remote)
        ));
    }

    Ok(Peer {
        k5: me.k5,
        me_record: me_record.to_string(),
        iroh_record: iroh_record.to_string(),
    })
}

/// Whether `k5` is on the web of trust of the local k5.
pub async fn is_trusted(local: &K5, k5: &str) -> Result<bool, String> {
    let listing = local.list().await.map_err(|e| e.to_string())?;
    Ok(local.web_of_trust(&listing.attestations).contains(k5))
}

/// Stores the records of a verified peer: its self attestation if missing, and
/// its iroh attestation if missing or newer, so the peer can be reached by its
/// k5 later.
pub async fn store(local: &K5, peer: &Peer) -> Result<(), String> {
    let db = local.db();
    let me_name = me::name(&peer.k5);
    if db.get(&me_name).await.map_err(|e| e.to_string())?.is_none() {
        db.put(&me_name, &peer.me_record)
            .await
            .map_err(|e| e.to_string())?;
    }

    let iroh_name = iroh_record::name(&peer.k5);
    let stale = match db.get(&iroh_name).await.map_err(|e| e.to_string())? {
        None => true,
        Some(existing) => {
            existing != peer.iroh_record && iroh_record::is_newer(&peer.iroh_record, &existing)
        }
    };
    if stale {
        db.put(&iroh_name, &peer.iroh_record)
            .await
            .map_err(|e| e.to_string())?;
    }

    Ok(())
}

/// The hello of the local k5: its self attestation and its iroh attestation,
/// from the database.
pub async fn local_hello(local: &K5) -> Result<String, String> {
    let k5 = local.k5();
    let get = |name: String| async move {
        local
            .db()
            .get(&name)
            .await
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("missing {name}"))
    };

    Ok(crate::proto::hello(
        &get(me::name(&k5)).await?,
        &get(iroh_record::name(&k5)).await?,
    ))
}

#[cfg(test)]
mod tests {
    use k5lib::key::Keys;

    use super::*;

    /// The hello records of new keys at a new endpoint.
    fn records() -> (String, String, EndpointId) {
        let keys = Keys::generate().unwrap();
        let id = iroh::SecretKey::generate().public();
        (
            me::create(&keys, false).unwrap(),
            iroh_record::create(&keys, &endpoint_hex(&id)).unwrap(),
            id,
        )
    }

    #[test]
    fn test_verify() {
        let (me_a, iroh_a, id_a) = records();
        let (me_b, iroh_b, id_b) = records();

        let peer = verify(&me_a, &iroh_a, &id_a).unwrap();
        assert_eq!(peer.k5, me::verify(&me_a).unwrap().k5);

        // Replaying a's records from another endpoint.
        let err = verify(&me_a, &iroh_a, &id_b).err().unwrap();
        assert!(err.contains("is for endpoint"), "{err}");
        // Mixing the records of two k5s.
        assert!(verify(&me_a, &iroh_b, &id_b).is_err());
        assert!(verify(&me_b, &iroh_a, &id_a).is_err());
        // A fake identity.
        let keys = Keys::generate().unwrap();
        let fake = me::create(&keys, true).unwrap();
        let iroh = iroh_record::create(&keys, &endpoint_hex(&id_a)).unwrap();
        assert!(verify(&fake, &iroh, &id_a).is_err());
    }

    #[test]
    fn test_endpoint_hex() {
        let id = iroh::SecretKey::generate().public();
        assert_eq!(parse_endpoint(&endpoint_hex(&id)).unwrap(), id);
        assert!(parse_endpoint("zz").is_err());
    }
}
