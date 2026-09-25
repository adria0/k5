// Fake TLSNotary attestations, for generated identities (`fakegraph`).
//
// They claim the same profiles as TLSNotary attestations (X, GitHub, website)
// without any TLS session or notary: the identity signs a statement about its
// own profile:
//
// aiwot fake tlsn
// aiwot:<aiwot>
// platform:<X | github | site>
// user:<user>
// server:<server of the profile>
// date:<creation time, RFC 3339>
//
// The record has `- Type: tlsn` and `- Fake: true` in its `# info` section,
// followed by the signed statement (an armored, OpenPGP cleartext-signed
// message). A fake attestation proves nothing about the profile: it is only
// accepted as fake, and is always displayed as such.

use super::{Error, Profile};
use crate::{
    key::Keys,
    message::{self, Keyring},
};

const STATEMENT_HEADER: &str = "aiwot fake tlsn";

/// The platforms of fake attestations, with the server of their profiles (a
/// website is its own server).
const PLATFORMS: &[(&str, Option<&str>)] = &[
    ("X", Some("cdn.syndication.twimg.com")),
    ("github", Some("gist.githubusercontent.com")),
    ("site", None),
];

/// A verified fake attestation.
pub struct Fake {
    pub aiwot: String,
    pub platform: &'static str,
    pub user: String,
    pub server: String,
    pub date: String,
}

impl Fake {
    pub fn profile(&self) -> Profile {
        Profile {
            platform: self.platform,
            user: self.user.clone(),
            aiwot: self.aiwot.clone(),
        }
    }
}

/// Creates a fake attestation of the `platform` profile `user` of `keys`,
/// returning the record file name and content.
pub fn create(keys: &Keys, platform: &str, user: &str) -> Result<(String, String), Error> {
    let aiwot = keys.aiwot();
    let (platform, server) = server(platform, user)?;
    let date = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

    let fake = Fake {
        aiwot,
        platform,
        user: user.to_string(),
        server,
        date,
    };
    let armored = message::sign(&keys.secret, &statement(&fake))?;

    let record = format!(
        "# info\n\
         \n\
         - Type: {record_type}\n\
         - Fake: true\n\
         - Created: {date}\n\
         - Profile: {profile}\n\
         - Server: {server}\n\
         - Signed by: aiwot:{aiwot} (no TLS session nor notary)\n\
         \n\
         # statement\n\
         {armored}",
        record_type = super::tlsnotary::RECORD_TYPE,
        date = fake.date,
        profile = fake.profile(),
        server = fake.server,
        aiwot = fake.aiwot,
    );
    let file_name = format!("{}-{}-{}.md", fake.aiwot, fake.platform, fake.user);

    Ok((file_name, record))
}

/// Verifies a fake attestation record, which must be signed by the aiwot of
/// the profile, resolving its public key from `keyring`.
pub fn verify(record: &str, keyring: &Keyring) -> Result<Fake, Error> {
    let (_, armored) = record
        .split_once("\n# statement\n")
        .ok_or("fake attestation has no `# statement` section")?;
    let verified = message::verify(armored, keyring)?;

    let fake = parse_statement(&verified.msg)?;
    if !fake.aiwot.eq_ignore_ascii_case(&verified.from) {
        return Err(format!(
            "fake attestation of aiwot:{} is signed by aiwot:{}",
            fake.aiwot, verified.from
        )
        .into());
    }

    Ok(fake)
}

fn statement(fake: &Fake) -> String {
    format!(
        "{STATEMENT_HEADER}\naiwot:{}\nplatform:{}\nuser:{}\nserver:{}\ndate:{}",
        fake.aiwot, fake.platform, fake.user, fake.server, fake.date
    )
}

fn parse_statement(statement: &str) -> Result<Fake, Error> {
    let mut lines = statement.split('\n');
    let mut field = |prefix: &str| {
        lines
            .next()
            .and_then(|line| line.strip_prefix(prefix))
            .ok_or_else(|| format!("invalid fake attestation statement: expected `{prefix}`"))
    };

    if !field(STATEMENT_HEADER)?.is_empty() {
        return Err("invalid fake attestation statement header".into());
    }
    let aiwot = field("aiwot:")?.to_ascii_lowercase();
    if aiwot.len() != 64 || !aiwot.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("invalid aiwot `{aiwot}`").into());
    }
    let platform = field("platform:")?.to_string();
    let user = field("user:")?.to_string();
    let claimed_server = field("server:")?.to_string();
    let date = field("date:")?.to_string();
    if lines.next().is_some() {
        return Err("invalid fake attestation statement: unexpected content".into());
    }

    let (platform, server) = server(&platform, &user)?;
    if claimed_server != server {
        return Err(format!("the server of a {platform} profile is not `{claimed_server}`").into());
    }

    Ok(Fake {
        aiwot,
        platform,
        user,
        server,
        date,
    })
}

/// Checks a profile, returning its platform and server.
fn server(platform: &str, user: &str) -> Result<(&'static str, String), Error> {
    let &(platform, server) = PLATFORMS
        .iter()
        .find(|(name, _)| *name == platform)
        .ok_or_else(|| format!("unknown platform `{platform}`"))?;

    let valid_user = !user.is_empty()
        && user
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        && !user.starts_with('.')
        && !user.contains("..");
    if !valid_user {
        return Err(format!("invalid {platform} user `{user}`").into());
    }

    match server {
        Some(server) => Ok((platform, server.to_string())),
        // A website is a domain without subdomain.
        None if user.split('.').count() == 2 => Ok((platform, user.to_string())),
        None => Err(format!("invalid site `{user}`: expected a domain without subdomain").into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::test_keys;

    fn keyring_of(keys: &Keys) -> Keyring {
        Keyring::from([(keys.aiwot(), keys.public())])
    }

    #[test]
    fn test_create_verify() {
        let keys = test_keys();
        let keyring = keyring_of(&keys);

        for (platform, user, server) in [
            ("X", "aliceharris", "cdn.syndication.twimg.com"),
            ("github", "aliceharris", "gist.githubusercontent.com"),
            ("site", "aliceharris.com", "aliceharris.com"),
        ] {
            let (file_name, record) = create(&keys, platform, user).unwrap();
            assert_eq!(file_name, format!("{}-{platform}-{user}.md", keys.aiwot()));
            assert!(record.starts_with("# info\n\n- Type: tlsn\n- Fake: true\n"));

            let fake = verify(&record, &keyring).unwrap();
            assert_eq!(fake.aiwot, keys.aiwot());
            assert_eq!(fake.server, server);
            assert_eq!(
                fake.profile().to_string(),
                format!("{platform}/{user}/aiwot:{}", keys.aiwot())
            );

            // The signed statement cannot be changed.
            let forged = record.replace(&format!("\nuser:{user}\n"), "\nuser:mallory\n");
            assert!(verify(&forged, &keyring).is_err());
        }

        assert!(create(&keys, "facebook", "alice").is_err());
        assert!(create(&keys, "site", "www.alice.com").is_err());
        assert!(create(&keys, "X", "../alice").is_err());
    }
}
