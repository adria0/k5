// k5net: k5 peer to peer over iroh.
//
// Two k5s talk directly, addressed by public key, to send each other private
// (signcrypted) messages and to merge each other's attestations.
//
// A k5 cannot be dialed by its id (an OpenPGP fingerprint), so each k5 has its
// own iroh key, stored in the `[iroh]` section of `k5.toml`, and publishes its
// endpoint id in an iroh attestation signed by the k5 key
// (`k5lib::attestations::iroh`). Those records travel with the others through
// export and merge, so the web of trust is how k5s find each other; n0's
// address lookup and relays then find the way to the endpoint. A first
// contact uses a ticket instead (`Node::ticket` / `Node::connect_ticket`): a
// pairing, with a check phrase both sides compare before keysigning.
//
// Only k5s on the web of trust (reachable through keysigns) are served.

mod node;
mod peer;
mod proto;

pub use iroh::{address_lookup::MemoryLookup, SecretKey};
pub use node::{load_or_create_secret, Contact, Event, Network, Node, PAIRING_WINDOW};

/// The DKIM public key of `domain` for `selector`, as published in DNS
/// (`<selector>._domainkey.<domain>`), for email attestations.
pub async fn dkim_key(domain: &str, selector: &str) -> anyhow::Result<k5lib::api::DkimKey> {
    use anyhow::Context as _;

    let name = format!("{selector}._domainkey.{domain}");
    let resolver = iroh::dns::DnsResolver::new();
    let records = resolver
        .lookup_txt(&name, std::time::Duration::from_secs(10))
        .await
        .with_context(|| format!("no DKIM key at {name}"))?;
    let record = records
        .map(|record| record.to_string())
        .find(|record| record.contains("p="))
        .with_context(|| format!("no DKIM key at {name}"))?;

    Ok(k5lib::api::DkimKey {
        domain: domain.to_string(),
        selector: selector.to_string(),
        record,
    })
}

#[cfg(test)]
mod tests {
    /// Fetches the DKIM key of the zk-email fixture (icloud.com, selector
    /// 1a1hai) from DNS: the one recorded with the fixture. Needs internet.
    #[tokio::test]
    #[ignore = "needs DNS on the internet"]
    async fn test_dkim_key() {
        let key = super::dkim_key("icloud.com", "1a1hai").await.unwrap();
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../plonky2-zkemail/examples/fixtures/icloud-dkim.json"
        ))
        .unwrap();
        assert_eq!(key.record, fixture["record"].as_str().unwrap());

        assert!(super::dkim_key("example.invalid", "none").await.is_err());
    }
}
