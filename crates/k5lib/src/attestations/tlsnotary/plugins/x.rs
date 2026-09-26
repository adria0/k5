// X (Twitter) plugin.
//
// Tweet URLs (`x.com/<user>/status/<id>`) are fetched from X's public
// syndication endpoint (`cdn.syndication.twimg.com/tweet-result`), which
// returns a small JSON document over HTTP/1.1 without requiring
// authentication.

use anyhow::{anyhow, Context as _};
use hyper::Uri;

use super::{find_k5, Error, Plugin, Profile, Session, Target};

const SYNDICATION_DOMAIN: &str = "cdn.syndication.twimg.com";
const DOMAINS: &[&str] = &[
    "x.com",
    "www.x.com",
    "mobile.x.com",
    "twitter.com",
    "www.twitter.com",
    "mobile.twitter.com",
];

pub struct X;

impl Plugin for X {
    fn target(&self, uri: &Uri) -> Option<Result<Target, Error>> {
        let host = uri.host()?.to_ascii_lowercase();
        if !DOMAINS.contains(&host.as_str()) {
            return None;
        }

        let Some(tweet_id) = parse_tweet_id(uri.path()) else {
            return Some(Err(anyhow!("could not parse tweet id from `{uri}`")));
        };

        // The syndication endpoint requires a `token` parameter but does not
        // validate its value.
        Some(Ok(Target {
            host: SYNDICATION_DOMAIN.to_string(),
            port: 443,
            path: format!("/tweet-result?id={tweet_id}&token=a"),
        }))
    }

    fn matches(&self, session: &Session) -> bool {
        session.server_name == SYNDICATION_DOMAIN
    }

    fn profile(&self, session: &Session) -> Result<Profile, Error> {
        let tweet: serde_json::Value = serde_json::from_str(session.response_body()?)?;

        // Deleted or protected tweets are returned as a tombstone.
        if tweet["__typename"] == "TweetTombstone" {
            let reason = tweet["tombstone"]["text"]["text"]
                .as_str()
                .unwrap_or("unknown reason");
            return Err(anyhow!("tweet is not available: {reason}"));
        }

        let user = tweet["user"]["screen_name"]
            .as_str()
            .context("tweet has no user")?;
        let text = tweet["text"].as_str().context("tweet has no text")?;
        let k5 = find_k5(text).with_context(|| format!("tweet has no `k5:` value: {text}"))?;

        Ok(Profile {
            platform: "X",
            user: user.to_string(),
            k5: k5.to_string(),
        })
    }
}

/// Extracts the tweet id from a `/<user>/status/<id>` path.
fn parse_tweet_id(path: &str) -> Option<&str> {
    let id = path.split("/status/").nth(1)?.split('/').next()?;

    (!id.is_empty() && id.bytes().all(|b| b.is_ascii_digit())).then_some(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_target() {
        let uri: Uri = "https://x.com/adria0/status/2102469944159989833?s=20"
            .parse()
            .unwrap();
        let target = X.target(&uri).unwrap().unwrap();
        assert_eq!(target.host, SYNDICATION_DOMAIN);
        assert_eq!(target.path, "/tweet-result?id=2102469944159989833&token=a");

        let uri: Uri = "https://example.com/adria0/status/1".parse().unwrap();
        assert!(X.target(&uri).is_none());
    }

    #[test]
    fn test_profile() {
        let session = Session {
            server_name: SYNDICATION_DOMAIN,
            sent: "GET /tweet-result?id=1&token=a HTTP/1.1\r\n\r\n",
            recv: "HTTP/1.1 200 OK\r\n\r\n{\"text\":\"k5:ab12\",\"user\":{\"screen_name\":\"adria0\"}}",
        };

        assert!(X.matches(&session));
        assert_eq!(X.profile(&session).unwrap().to_string(), "X/adria0/k5:ab12");

        let deleted = Session {
            recv: "HTTP/1.1 200 OK\r\n\r\n{\"__typename\":\"TweetTombstone\",\"tombstone\":{\"text\":{\"text\":\"This Post was deleted by the Post author.\"}}}",
            ..session
        };
        assert_eq!(
            X.profile(&deleted).err().unwrap().to_string(),
            "tweet is not available: This Post was deleted by the Post author."
        );
    }
}
