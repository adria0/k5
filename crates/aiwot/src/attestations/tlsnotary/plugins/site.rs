// Website plugin.
//
// `https://<domain>/aiwot.txt` on a domain without subdomain, e.g.
// `https://example.com/aiwot.txt`.

use super::{find_aiwot, Error, Plugin, Profile, Session};

const PATH: &str = "/aiwot.txt";

pub struct Site;

impl Plugin for Site {
    fn matches(&self, session: &Session) -> bool {
        session.server_name.split('.').count() == 2 && session.request_target() == Some(PATH)
    }

    fn profile(&self, session: &Session) -> Result<Profile, Error> {
        let aiwot =
            find_aiwot(session.response_body()?).ok_or("aiwot.txt has no `aiwot:` value")?;

        Ok(Profile {
            platform: "site",
            user: session.server_name.to_string(),
            aiwot: aiwot.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profile() {
        let session = Session {
            server_name: "example.com",
            sent: "GET /aiwot.txt HTTP/1.1\r\nhost: example.com\r\n\r\n",
            recv: "HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\naiwot:ab12\n",
        };

        assert!(Site.matches(&session));
        assert!(!Site.matches(&Session {
            server_name: "www.example.com",
            ..session
        }));
        assert!(!Site.matches(&Session {
            sent: "GET /other/aiwot.txt HTTP/1.1\r\n\r\n",
            ..session
        }));
        assert_eq!(
            Site.profile(&session).unwrap().to_string(),
            "site/example.com/aiwot:ab12"
        );
    }
}
