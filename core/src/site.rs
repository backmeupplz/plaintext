//! Which saved logins belong to a web page. Autofill everywhere (the browser
//! extension, and later the phone and desktop apps) asks this one function, so a
//! login offered on one platform is offered on all of them.
//!
//! By default a login matches every page on the same site: the registrable
//! domain, or eTLD+1 (`accounts.google.com` and `mail.google.com` share
//! `google.com`; `a.github.io` and `b.github.io` don't, since `github.io` is a
//! public suffix). An item can ask for its exact host instead (`Item::exact_host`).

use std::collections::HashSet;
use std::sync::OnceLock;

static LIST: &str = include_str!("public_suffix_list.txt");

fn rules() -> &'static HashSet<&'static str> {
    static RULES: OnceLock<HashSet<&'static str>> = OnceLock::new();
    RULES.get_or_init(|| LIST.lines().filter(|l| !l.is_empty() && !l.starts_with("//")).collect())
}

/// The site a host belongs to: its registrable domain, or the host itself for
/// IP addresses, single labels (`localhost`) and public suffixes.
pub fn site(host: &str) -> String {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.parse::<std::net::IpAddr>().is_ok() || host.starts_with('[') {
        return host;
    }
    let labels: Vec<&str> = host.split('.').collect();
    let rules = rules();
    // The longest matching rule wins; an exception (`!`) makes its parent the suffix.
    for i in 0..labels.len() {
        let rest = labels[i..].join(".");
        let suffix_len = if rules.contains(format!("!{rest}").as_str()) {
            labels.len() - i - 1
        } else if rules.contains(rest.as_str()) || (i + 1 < labels.len() && rules.contains(format!("*.{}", labels[i + 1..].join(".")).as_str())) {
            labels.len() - i
        } else {
            continue;
        };
        return if suffix_len < labels.len() { labels[labels.len() - suffix_len - 1..].join(".") } else { host };
    }
    // Not in the list: the default rule `*` makes the last label the suffix.
    if labels.len() >= 2 { labels[labels.len() - 2..].join(".") } else { host }
}

/// `(scheme, host, port)` of a URL as people save them: `https://a.com/x`,
/// `a.com:8443`, `http://user@[::1]:80`. A missing scheme means https.
fn parts(url: &str) -> Option<(String, String, Option<u16>)> {
    let url = url.trim();
    // A scheme only at the very start: `a.com/?next=https://b.com` is a.com.
    let scheme = url.split_once("://").map(|(s, _)| s).filter(|s| {
        let mut c = s.chars();
        c.next().is_some_and(|f| f.is_ascii_alphabetic()) && c.all(|c| c.is_ascii_alphanumeric() || "+.-".contains(c))
    });
    let (scheme, rest) = match scheme {
        Some(s) => (s.to_ascii_lowercase(), &url[s.len() + 3..]),
        None => ("https".into(), url),
    };
    // Browsers end the host at a backslash too.
    let authority = rest.split(['/', '?', '#', '\\']).next()?;
    let authority = authority.rsplit_once('@').map_or(authority, |(_, a)| a);
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) && (!h.contains(':') || h.ends_with(']')) => (h, Some(p.parse().ok()?)),
        _ => (authority, None),
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() || host.chars().any(|c| c.is_whitespace()) {
        return None;
    }
    let port = port.or(match scheme.as_str() {
        "https" => Some(443),
        "http" => Some(80),
        _ => None,
    });
    Some((scheme, host, port))
}

/// Whether a login saved for `saved` may be offered on `page`. Only http(s)
/// pages qualify, and a login saved for https is never offered to a plain http
/// page, where anyone on the network could read what gets filled.
pub fn matches(saved: &str, page: &str, exact_host: bool) -> bool {
    let (Some((s_scheme, s_host, s_port)), Some((p_scheme, p_host, p_port))) = (parts(saved), parts(page)) else { return false };
    let web = |s: &str| matches!(s, "http" | "https");
    if !web(&p_scheme) || !web(&s_scheme) || (p_scheme == "http" && s_scheme != "http") {
        return false;
    }
    if exact_host { s_host == p_host && s_port == p_port } else { site(&s_host) == site(&p_host) }
}

/// The host of a page URL, for naming a new login after it (`www.` dropped).
pub fn host(url: &str) -> Option<String> {
    let (_, h, _) = parts(url)?;
    Some(h.strip_prefix("www.").map(String::from).unwrap_or(h))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registrable_domains() {
        assert_eq!(site("accounts.google.com"), "google.com");
        assert_eq!(site("WWW.Example.CO.UK."), "example.co.uk");
        assert_eq!(site("a.github.io"), "a.github.io");
        assert_eq!(site("github.io"), "github.io");
        assert_eq!(site("x.y.nom.br"), "x.y.nom.br"); // *.nom.br
        assert_eq!(site("a.www.ck"), "www.ck"); // !www.ck
        assert_eq!(site("localhost"), "localhost");
        assert_eq!(site("192.168.1.10"), "192.168.1.10");
        assert_eq!(site("foo.bar.unknowntld"), "bar.unknowntld");
        assert_eq!(site("xn--80ak6aa92e.xn--p1ai"), "xn--80ak6aa92e.xn--p1ai"); // .рф
    }

    #[test]
    fn login_matching() {
        assert!(matches("https://accounts.google.com/signin", "https://mail.google.com/", false));
        assert!(matches("google.com", "https://www.google.com/x?y#z", false));
        assert!(!matches("https://a.github.io", "https://b.github.io", false));
        assert!(!matches("https://google.com.evil.com", "https://google.com", false));
        assert!(!matches("https://google.com", "https://google.com.evil.com", false));
        // Exact host: subdomains and other ports don't count.
        assert!(matches("https://login.example.com", "https://login.example.com:443/a", true));
        assert!(!matches("https://login.example.com", "https://www.example.com", true));
        assert!(!matches("https://example.com", "https://example.com:8443", true));
        // An https login never goes to a plain http page; an http one goes to both.
        assert!(!matches("https://example.com", "http://example.com", false));
        assert!(matches("http://192.168.1.1", "http://192.168.1.1/login", false));
        assert!(matches("http://router.lan:8080", "https://router.lan:8080", true));
        // Only web pages.
        assert!(!matches("example.com", "file:///etc/example.com", false));
        assert!(!matches("example.com", "javascript://example.com/", false));
        assert!(!matches("", "https://example.com", false));
        // User info never decides the host.
        assert!(!matches("https://example.com", "https://example.com@evil.com/", false));
        assert!(matches("http://[::1]:3000", "http://[::1]:3000/", true));
        // A URL inside a saved URL is not its host; nor is what follows a backslash.
        assert!(!matches("bank.com/login?next=https://evil.com", "https://evil.com", false));
        assert!(matches("bank.com/login?next=https://evil.com", "https://bank.com", false));
        assert!(!matches("https://evil.com\\@bank.com", "https://bank.com", false));
        // App links and other schemes never fill web pages.
        assert!(!matches("androidapp://com.google.android.gm", "https://android.gm", false));
        assert!(!matches("ftp://example.com", "https://example.com", false));
        assert_eq!(host("https://www.example.com/login").as_deref(), Some("example.com"));
    }
}
