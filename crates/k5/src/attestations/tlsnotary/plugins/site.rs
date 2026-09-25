// Website plugin.
//
// `https://<domain>/k5.txt` on a domain without subdomain, e.g.
// `https://example.com/k5.txt`.

use super::{find_k5, Error, Plugin, Profile, Session};

const PATH: &str = "/k5.txt";

pub struct Site;

impl Plugin for Site {
    fn matches(&self, session: &Session) -> bool {
        session.server_name.split('.').count() == 2 && session.request_target() == Some(PATH)
    }

    fn profile(&self, session: &Session) -> Result<Profile, Error> {
        let k5 = find_k5(session.response_body()?).ok_or("k5.txt has no `k5:` value")?;

        Ok(Profile {
            platform: "site",
            user: session.server_name.to_string(),
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
            server_name: "example.com",
            sent: "GET /k5.txt HTTP/1.1\r\nhost: example.com\r\n\r\n",
            recv: "HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nk5:ab12\n",
        };

        assert!(Site.matches(&session));
        assert!(!Site.matches(&Session {
            server_name: "www.example.com",
            ..session
        }));
        assert!(!Site.matches(&Session {
            sent: "GET /other/k5.txt HTTP/1.1\r\n\r\n",
            ..session
        }));
        assert_eq!(
            Site.profile(&session).unwrap().to_string(),
            "site/example.com/k5:ab12"
        );
    }
}
