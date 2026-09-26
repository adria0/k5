// GitHub plugin.
//
// Raw gists (`gist.githubusercontent.com/<user>/<gist id>/raw/...`). GitHub
// returns 404 if `<user>` does not own the gist, so a 200 response proves the
// user.

use anyhow::Context as _;

use super::{find_k5, Error, Plugin, Profile, Session};

const GIST_DOMAIN: &str = "gist.githubusercontent.com";

pub struct Github;

impl Plugin for Github {
    fn matches(&self, session: &Session) -> bool {
        session.server_name == GIST_DOMAIN
    }

    fn profile(&self, session: &Session) -> Result<Profile, Error> {
        let path = session.request_target().context("request has no target")?;
        let user = path
            .trim_start_matches('/')
            .split(['/', '?'])
            .next()
            .filter(|user| !user.is_empty())
            .with_context(|| format!("could not parse gist user from `{path}`"))?;

        let k5 = find_k5(session.response_body()?).context("gist has no `k5:` value")?;

        Ok(Profile {
            platform: "github",
            user: user.to_string(),
            k5: k5.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profile() {
        let session = Session {
            server_name: GIST_DOMAIN,
            sent: "GET /adria0/0123abcd/raw/file.txt HTTP/1.1\r\nhost: gist.githubusercontent.com\r\n\r\n",
            recv: "HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nk5:ab12\n",
        };

        assert!(Github.matches(&session));
        assert_eq!(
            Github.profile(&session).unwrap().to_string(),
            "github/adria0/k5:ab12"
        );

        let not_found = Session {
            recv: "HTTP/1.1 404 Not Found\r\nContent-Length: 14\r\n\r\n404: Not Found",
            ..session
        };
        assert!(Github.profile(&not_found).is_err());
    }
}
