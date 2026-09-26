// Profile plugins.
//
// A plugin recognizes a platform (X, GitHub, a website, ...) and extracts a
// profile `<platform>/<user>/k5:<hex>` from a verified TLS session. A
// plugin may also rewrite the URL given to `notarize` into the resource that
// is actually requested (e.g. a tweet URL into the syndication API).
//
// To add a platform, implement `Plugin` in a new module and register it in
// `PLUGINS`.

mod github;
mod site;
mod x;

use anyhow::{anyhow, Context as _};
use hyper::Uri;

pub use crate::attestations::{Error, Profile};

/// Registered plugins, in order of precedence.
pub static PLUGINS: &[&dyn Plugin] = &[&x::X, &github::Github, &site::Site];

pub trait Plugin: Sync {
    /// Maps the URL given to `notarize` to the resource to request, or returns
    /// `None` if this plugin does not handle the URL.
    fn target(&self, _uri: &Uri) -> Option<Result<Target, Error>> {
        None
    }

    /// Returns whether this plugin handles the verified session.
    fn matches(&self, session: &Session) -> bool;

    /// Extracts the profile from a verified session this plugin matches.
    fn profile(&self, session: &Session) -> Result<Profile, Error>;
}

/// The HTTPS resource to request.
pub struct Target {
    pub host: String,
    pub port: u16,
    pub path: String,
}

/// The authenticated data of a verified TLS session.
pub struct Session<'a> {
    pub server_name: &'a str,
    pub sent: &'a str,
    pub recv: &'a str,
}

impl Session<'_> {
    /// Returns the target of the first request line, e.g. `/k5.txt`.
    pub fn request_target(&self) -> Option<&str> {
        self.sent.lines().next()?.split(' ').nth(1)
    }

    /// Returns the body of the response, which must have a 200 status.
    pub fn response_body(&self) -> Result<&str, Error> {
        let (head, body) = self
            .recv
            .split_once("\r\n\r\n")
            .context("response has no body")?;
        let status = head.lines().next().unwrap_or_default();
        if status.split(' ').nth(1) != Some("200") {
            return Err(anyhow!("unexpected response status: {status}"));
        }

        Ok(body)
    }
}

/// Resolves the URL given to `notarize` to the resource to request.
pub fn target(url: &str) -> Result<Target, Error> {
    let uri: Uri = url.parse()?;

    if uri.scheme_str() != Some("https") {
        return Err(anyhow!("only https URLs are supported: `{url}`"));
    }

    if let Some(target) = PLUGINS.iter().find_map(|plugin| plugin.target(&uri)) {
        return target;
    }

    let host = uri
        .host()
        .with_context(|| format!("URL has no host: `{url}`"))?;

    Ok(Target {
        host: host.to_string(),
        port: uri.port_u16().unwrap_or(443),
        path: uri
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/")
            .to_string(),
    })
}

/// Returns the profile proven by the session, or `None` if no plugin handles
/// it.
pub fn profile(session: &Session) -> Option<Result<Profile, Error>> {
    PLUGINS
        .iter()
        .find(|plugin| plugin.matches(session))
        .map(|plugin| plugin.profile(session))
}

/// Returns the hex value following the first `k5:` in `text`.
pub fn find_k5(text: &str) -> Option<&str> {
    text.match_indices("k5:").find_map(|(idx, prefix)| {
        let rest = &text[idx + prefix.len()..];
        let len = rest
            .find(|c: char| !c.is_ascii_hexdigit())
            .unwrap_or(rest.len());
        (len > 0).then(|| &rest[..len])
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_k5() {
        assert_eq!(find_k5("hello k5:ab12, bye"), Some("ab12"));
        assert_eq!(find_k5("k5: k5:ff"), Some("ff"));
        assert_eq!(find_k5("nothing here"), None);
    }

    #[test]
    fn test_target() {
        let target = super::target("https://example.com:8443/a?b=c").unwrap();
        assert_eq!(target.host, "example.com");
        assert_eq!(target.port, 8443);
        assert_eq!(target.path, "/a?b=c");

        assert!(super::target("http://example.com/").is_err());
    }
}
