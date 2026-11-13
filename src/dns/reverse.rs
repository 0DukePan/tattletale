//! Reverse DNS: give an address a name when the browser hid the lookup.
//!
//! DNS over HTTPS is the largest accuracy gap in this tool. A browser resolving
//! through its own resolver never puts those names in the Windows cache, so the
//! connections arrive as bare addresses and are reported as unknown.
//!
//! But the *owner* of an address is a property of the address, not of how it was
//! resolved. `142.250.x.x` has a PTR record pointing into `1e100.net`, and that
//! is Google whoever asked. A reverse lookup therefore recovers the company
//! even when it cannot recover the hostname.
//!
//! This is opt-in. Sending reverse queries to the local resolver tells it which
//! addresses this machine is talking to, which is exactly the fact DoH was
//! hiding. That trade is the user's to make, not ours to make quietly.

/// Names longer than this are not hostnames.
const MAX_NAME: usize = 1025;

/// Ask the system resolver for the name of `ip`.
///
/// Returns `None` when the address has no PTR record, when the resolver is
/// unreachable, or when the answer is the address itself.
pub fn lookup(ip: &str) -> Option<String> {
    platform::lookup(ip)
}

/// Whether a PTR answer is worth showing.
///
/// Some resolvers answer a failed reverse lookup with the address, or with a
/// placeholder. Neither is a name, and reporting one would invent an
/// attribution.
pub fn is_usable(name: &str, ip: &str) -> bool {
    let name = name.trim().trim_end_matches('.');
    if name.is_empty() || name.len() > MAX_NAME {
        return false;
    }
    if name == ip {
        return false;
    }
    // A hostname with no dot is a single label: a local name, not a company.
    if !name.contains('.') {
        return false;
    }
    // `localhost`, and the arpa form of the address itself.
    if name.eq_ignore_ascii_case("localhost") || name.ends_with(".in-addr.arpa") {
        return false;
    }
    true
}

/// Known address-owner suffixes, most specific first.
///
/// A PTR name identifies an organisation, not a site. Saying "Google" when the
/// only evidence is `xx.1e100.net` is honest; saying "google.com" would not be.
pub const OWNERS: &[(&str, &str)] = &[
    ("1e100.net", "Google"),
    ("google.com", "Google"),
    ("googleusercontent.com", "Google"),
    ("gvt1.com", "Google"),
    ("googlevideo.com", "Google"),
    ("ggpht.com", "Google"),
    ("fbcdn.net", "Meta"),
    ("facebook.com", "Meta"),
    ("instagram.com", "Meta"),
    ("cloudfront.net", "Amazon"),
    ("amazonaws.com", "Amazon"),
    ("aaplimg.com", "Apple"),
    ("apple.com", "Apple"),
    ("icloud.com", "Apple"),
    ("akamaiedge.net", "Akamai"),
    ("akamai.net", "Akamai"),
    ("akamaitechnologies.com", "Akamai"),
    ("edgekey.net", "Akamai"),
    ("fastly.net", "Fastly"),
    ("llnwd.net", "Limelight"),
    ("azureedge.net", "Microsoft"),
    ("microsoft.com", "Microsoft"),
    ("msedge.net", "Microsoft"),
    ("live.com", "Microsoft"),
    ("office.net", "Microsoft"),
    ("windowsupdate.com", "Microsoft"),
    ("cloudflare.net", "Cloudflare"),
    ("cloudflare.com", "Cloudflare"),
    ("discord.com", "Discord"),
    ("discordapp.com", "Discord"),
    ("spotify.com", "Spotify"),
    ("scdn.co", "Spotify"),
    ("slack.com", "Slack"),
    ("slack-edge.com", "Slack"),
    ("github.com", "GitHub"),
    ("githubusercontent.com", "GitHub"),
];

/// The organisation a reverse-DNS name belongs to, if it is a known network.
pub fn owner_of(hostname: &str) -> Option<&'static str> {
    let host = hostname.trim_end_matches('.').to_ascii_lowercase();
    OWNERS
        .iter()
        .find(|(suffix, _)| host == *suffix || host.ends_with(&format!(".{suffix}")))
        .map(|(_, owner)| *owner)
}

#[cfg(windows)]
mod platform {
    use std::mem::zeroed;
    use std::sync::Once;

    use windows_sys::Win32::Networking::WinSock::{
        GetNameInfoW, WSAStartup, AF_INET, AF_INET6, NI_MAXHOST, NI_NAMEREQD, SOCKADDR,
        SOCKADDR_IN, SOCKADDR_IN6, WSADATA,
    };

    static INIT: Once = Once::new();

    /// Winsock must be initialised once per process before any name lookup.
    fn init() {
        INIT.call_once(|| unsafe {
            let mut data: WSADATA = zeroed();
            // 2.2 is the only version that has ever been accepted.
            let _ = WSAStartup(0x0202, &mut data);
        });
    }

    pub fn lookup(ip: &str) -> Option<String> {
        init();

        let parsed: std::net::IpAddr = ip.parse().ok()?;
        let mut host = vec![0u16; NI_MAXHOST as usize];

        let status = match parsed {
            std::net::IpAddr::V4(v4) => unsafe {
                let mut sa: SOCKADDR_IN = zeroed();
                sa.sin_family = AF_INET;
                // The DWORD layout matches the one the MIB tables use.
                sa.sin_addr.S_un.S_addr = u32::from_le_bytes(v4.octets());
                GetNameInfoW(
                    &sa as *const SOCKADDR_IN as *const SOCKADDR,
                    std::mem::size_of::<SOCKADDR_IN>() as i32,
                    host.as_mut_ptr(),
                    host.len() as u32,
                    std::ptr::null_mut(),
                    0,
                    NI_NAMEREQD as i32,
                )
            },
            std::net::IpAddr::V6(v6) => unsafe {
                let mut sa: SOCKADDR_IN6 = zeroed();
                sa.sin6_family = AF_INET6;
                sa.sin6_addr.u.Byte = v6.octets();
                GetNameInfoW(
                    &sa as *const SOCKADDR_IN6 as *const SOCKADDR,
                    std::mem::size_of::<SOCKADDR_IN6>() as i32,
                    host.as_mut_ptr(),
                    host.len() as u32,
                    std::ptr::null_mut(),
                    0,
                    NI_NAMEREQD as i32,
                )
            },
        };

        if status != 0 {
            return None;
        }

        let end = host.iter().position(|c| *c == 0).unwrap_or(host.len());
        let name = String::from_utf16_lossy(&host[..end]);
        if super::is_usable(&name, ip) {
            Some(name)
        } else {
            None
        }
    }
}

#[cfg(not(windows))]
mod platform {
    /// No reverse lookup is implemented off Windows yet.
    pub fn lookup(_ip: &str) -> Option<String> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_address_is_not_a_name() {
        assert!(!is_usable("203.0.113.5", "203.0.113.5"));
        assert!(!is_usable("", "203.0.113.5"));
        assert!(!is_usable("localhost", "203.0.113.5"));
    }

    #[test]
    fn a_single_label_is_a_local_name_not_a_company() {
        assert!(!is_usable("printer", "203.0.113.5"));
    }

    #[test]
    fn an_arpa_name_is_not_an_answer() {
        assert!(!is_usable("5.113.0.203.in-addr.arpa", "203.0.113.5"));
    }

    #[test]
    fn a_public_ptr_name_is_usable() {
        assert!(is_usable("xx.1e100.net", "142.250.75.238"));
        assert!(is_usable("ec2-1-2-3-4.compute.amazonaws.com", "1.2.3.4"));
        // A resolver may return the name with the trailing dot.
        assert!(is_usable("xx.1e100.net.", "142.250.75.238"));
    }

    #[test]
    fn a_ptr_name_maps_to_its_owner() {
        assert_eq!(owner_of("xx.1e100.net"), Some("Google"));
        assert_eq!(owner_of("a.b.1e100.net"), Some("Google"));
        assert_eq!(
            owner_of("ec2-1-2-3-4.compute.amazonaws.com"),
            Some("Amazon")
        );
        assert_eq!(owner_of("edge.akamaiedge.net"), Some("Akamai"));
        assert_eq!(owner_of("d123.cloudfront.net"), Some("Amazon"));
    }

    #[test]
    fn an_unknown_name_has_no_owner() {
        assert_eq!(owner_of("mail.example.org"), None);
        assert_eq!(owner_of(""), None);
    }

    #[test]
    fn owner_matching_does_not_match_a_lookalike_suffix() {
        // `not1e100.net` is not Google, and a substring test would say it was.
        assert_eq!(owner_of("not1e100.net"), None);
        assert_eq!(owner_of("1e100.net.evil.example"), None);
    }

    #[test]
    fn a_real_address_resolves_or_fails_cleanly() {
        // The lookup goes to whatever resolver this machine has; either an
        // answer or None is acceptable, but it must not panic or hang.
        let result = lookup("127.0.0.1");
        assert!(result.as_deref().is_none_or(|name| !name.is_empty()));
    }
}
