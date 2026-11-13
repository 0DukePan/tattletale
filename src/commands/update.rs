//! `tattle update` — check for and install a newer release.
//!
//! This is deliberately **not** an auto-updater. The product's promise is that
//! the binary makes no outbound connection unless you ask it to, and a silent
//! update check is an outbound connection on every run. It is also the single
//! most attractive target in any program: whoever controls the update channel
//! controls every installed copy.
//!
//! So the check is a command you type, the download is verified against the
//! release checksum before anything is written, and nothing is replaced while
//! it is running.

use std::io::{Read, Write};
use std::path::PathBuf;

use crate::commands::paths;

/// The release feed this binary trusts. One constant, easy to audit.
pub const RELEASES: &str = "https://api.github.com/repos/0DukePan/tattletale/releases/latest";

/// Where the checksummed assets live for a release.
pub const DOWNLOAD_ROOT: &str = "https://github.com/0DukePan/tattletale/releases/latest/download";

/// A release the feed knows about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Release {
    pub version: String,
    pub exe_url: Option<String>,
    pub checksum_url: Option<String>,
}

/// Compare two versions as dotted integers.
///
/// Deliberately not semver-complete: this project has never published a
/// prerelease, and an updater that guesses at precedence is worse than one that
/// reports "not comparable" and leaves the user alone.
pub fn is_newer(latest: &str, current: &str) -> Option<bool> {
    fn parse(text: &str) -> Option<(u64, u64, u64)> {
        let text = text.trim().trim_start_matches('v');
        let mut parts = text.split('.');
        let major = parts.next()?.parse().ok()?;
        let minor = parts.next()?.parse().ok()?;
        let patch = parts.next().unwrap_or("0").parse().ok()?;
        // Anything after the third component means this is not a plain release.
        if parts.next().is_some() {
            return None;
        }
        Some((major, minor, patch))
    }
    Some(parse(latest)? > parse(current)?)
}

/// Fetch and parse the latest release.
pub fn fetch() -> anyhow::Result<Release> {
    let response = ureq::builder()
        .timeout(std::time::Duration::from_secs(20))
        .user_agent(concat!("tattletale/", env!("CARGO_PKG_VERSION")))
        .build()
        .get(RELEASES)
        .call()?;
    let body = response.into_string()?;
    parse_release(&body)
}

/// Pull the version and asset URLs out of a release payload.
///
/// Parsed rather than pattern-matched so a change in the feed is a clear error
/// instead of a silent "you are up to date".
pub fn parse_release(body: &str) -> anyhow::Result<Release> {
    let value: serde_json::Value = serde_json::from_str(body)
        .map_err(|err| anyhow::anyhow!("the release feed is not JSON: {err}"))?;

    let tag = value
        .get("tag_name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("the release feed has no tag_name"))?;

    let mut exe_url = None;
    let mut checksum_url = None;
    if let Some(assets) = value.get("assets").and_then(|v| v.as_array()) {
        for asset in assets {
            let Some(name) = asset.get("name").and_then(|v| v.as_str()) else {
                continue;
            };
            let Some(url) = asset.get("browser_download_url").and_then(|v| v.as_str()) else {
                continue;
            };
            if name.eq_ignore_ascii_case("tattle.exe") {
                exe_url = Some(url.to_string());
            } else if name.eq_ignore_ascii_case("SHA256SUMS.txt") {
                checksum_url = Some(url.to_string());
            }
        }
    }

    Ok(Release {
        version: tag.trim_start_matches('v').to_string(),
        exe_url,
        checksum_url,
    })
}

/// The expected hash for `filename` in a `SHA256SUMS.txt` body.
pub fn expected_hash(sums: &str, filename: &str) -> Option<String> {
    sums.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .find_map(|line| {
            let mut parts = line.split_whitespace();
            let hash = parts.next()?;
            let name = parts.next()?;
            if name.eq_ignore_ascii_case(filename) {
                Some(hash.to_ascii_lowercase())
            } else {
                None
            }
        })
}

/// Download the release binary, verify it, and stage it beside the running one.
///
/// Returns the path of the staged file. Windows holds a lock on a running
/// executable, so nothing is replaced in place: the new binary is written next
/// to the old one and the swap is left to the user. That is also the safer
/// design — an updater that cannot half-replace the binary it is running from
/// cannot brick the installation.
pub fn stage(release: &Release, out: &mut dyn Write) -> anyhow::Result<PathBuf> {
    let exe_url = release
        .exe_url
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("release {} ships no tattle.exe", release.version))?;
    let sums_url = release
        .checksum_url
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("release {} ships no SHA256SUMS.txt", release.version))?;

    let agent = |url: &str| -> anyhow::Result<Vec<u8>> {
        let response = ureq::builder()
            .timeout(std::time::Duration::from_secs(120))
            .user_agent(concat!("tattletale/", env!("CARGO_PKG_VERSION")))
            .build()
            .get(url)
            .call()?;
        let mut bytes = Vec::new();
        response.into_reader().read_to_end(&mut bytes)?;
        Ok(bytes)
    };

    let sums = String::from_utf8(agent(sums_url)?)?;
    let expected = expected_hash(&sums, "tattle.exe")
        .ok_or_else(|| anyhow::anyhow!("SHA256SUMS.txt does not list tattle.exe"))?;

    writeln!(out, "downloading tattle {} ...", release.version)?;
    let bytes = agent(exe_url)?;

    let actual = sha256_hex(&bytes);
    if actual != expected {
        anyhow::bail!("checksum mismatch: expected {expected}, got {actual}. Nothing was written.");
    }
    writeln!(out, "  checksum ok ({})", &expected[..16])?;

    let staged = staged_path();
    std::fs::write(&staged, &bytes)?;
    writeln!(out, "  written to {}", staged.display())?;
    Ok(staged)
}

/// Where the new binary is placed: next to the old one, with a suffix.
pub fn staged_path() -> PathBuf {
    let current = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("tattle.exe"));
    let stem = current
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("tattle");
    current.with_file_name(format!("{stem}.new.exe"))
}

/// SHA-256 of a byte slice, lowercase hex.
///
/// Implemented here rather than pulled in: a twenty-line hash is smaller than a
/// dependency, and it has a published test vector.
pub fn sha256_hex(bytes: &[u8]) -> String {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    let mut data = bytes.to_vec();
    let bit_len = (bytes.len() as u64) * 8;
    data.push(0x80);
    while data.len() % 64 != 56 {
        data.push(0);
    }
    data.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in data.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, word) in chunk.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut v = h;
        for i in 0..64 {
            let s1 = v[4].rotate_right(6) ^ v[4].rotate_right(11) ^ v[4].rotate_right(25);
            let ch = (v[4] & v[5]) ^ (!v[4] & v[6]);
            let t1 = v[7]
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = v[0].rotate_right(2) ^ v[0].rotate_right(13) ^ v[0].rotate_right(22);
            let maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
            let t2 = s0.wrapping_add(maj);

            v[7] = v[6];
            v[6] = v[5];
            v[5] = v[4];
            v[4] = v[3].wrapping_add(t1);
            v[3] = v[2];
            v[2] = v[1];
            v[1] = v[0];
            v[0] = t1.wrapping_add(t2);
        }
        for i in 0..8 {
            h[i] = h[i].wrapping_add(v[i]);
        }
    }

    h.iter().map(|word| format!("{word:08x}")).collect()
}

/// Run the whole flow.
pub fn run(out: &mut dyn Write, check_only: bool, now_unused: i64) -> anyhow::Result<()> {
    let _ = now_unused;
    writeln!(
        out,
        "tattletale {} → checking the release feed",
        crate::VERSION
    )?;

    let release = fetch()?;
    writeln!(out, "  latest release: {}", release.version)?;

    match is_newer(&release.version, crate::VERSION) {
        Some(false) => {
            writeln!(out, "  already up to date")?;
            return Ok(());
        }
        None => {
            writeln!(
                out,
                "  cannot compare {} with {}; not doing anything",
                release.version,
                crate::VERSION
            )?;
            return Ok(());
        }
        Some(true) => {}
    }

    if check_only {
        writeln!(
            out,
            "  a newer release is available; run `tattle update` to fetch it"
        )?;
        return Ok(());
    }

    let staged = stage(&release, out)?;
    writeln!(out)?;
    writeln!(
        out,
        "  to finish, close every running copy of tattle and run:"
    )?;
    writeln!(
        out,
        "    move /Y \"{}\" \"{}\"",
        staged.display(),
        current_binary().display()
    )?;
    writeln!(out, "  nothing was replaced automatically")?;
    Ok(())
}

fn current_binary() -> PathBuf {
    std::env::current_exe().unwrap_or_else(|_| paths::data_dir().join("tattle.exe"))
}

/// The modules allowed to open a socket: the list loader and this one. Both are
/// only reachable by an explicit command, which is what `tests/privacy.rs`
/// enforces.
pub const NETWORK_MODULES: &[&str] = &["classify.rs", "update.rs"];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_compare_by_dotted_integers() {
        assert_eq!(is_newer("0.2.0", "0.1.0"), Some(true));
        assert_eq!(is_newer("0.1.10", "0.1.9"), Some(true));
        assert_eq!(is_newer("1.0.0", "0.99.99"), Some(true));
        assert_eq!(is_newer("0.1.0", "0.1.0"), Some(false));
        assert_eq!(is_newer("0.1.0", "0.2.0"), Some(false));
    }

    #[test]
    fn a_leading_v_is_accepted() {
        assert_eq!(is_newer("v0.2.0", "0.1.0"), Some(true));
        assert_eq!(is_newer("0.2.0", "v0.1.0"), Some(true));
    }

    #[test]
    fn a_prerelease_is_not_comparable() {
        // Better to say nothing than to guess at precedence.
        assert_eq!(is_newer("0.2.0-rc1", "0.1.0"), None);
        assert_eq!(
            is_newer("0.2", "0.1.0"),
            Some(true),
            "a missing patch is zero"
        );
        assert_eq!(is_newer("", "0.1.0"), None);
    }

    #[test]
    fn the_release_feed_is_parsed_for_assets() {
        let body = r#"{
            "tag_name": "v0.2.0",
            "assets": [
                {"name": "SHA256SUMS.txt", "browser_download_url": "https://x/sums"},
                {"name": "tattle.exe", "browser_download_url": "https://x/exe"},
                {"name": "tattle.zip", "browser_download_url": "https://x/zip"}
            ]
        }"#;
        let release = parse_release(body).expect("parse");
        assert_eq!(release.version, "0.2.0");
        assert_eq!(release.exe_url.as_deref(), Some("https://x/exe"));
        assert_eq!(release.checksum_url.as_deref(), Some("https://x/sums"));
    }

    #[test]
    fn a_release_without_assets_is_reported_not_guessed() {
        let body = r#"{"tag_name": "v0.2.0", "assets": []}"#;
        let release = parse_release(body).expect("parse");
        assert!(release.exe_url.is_none());
        assert!(release.checksum_url.is_none());
    }

    #[test]
    fn a_malformed_feed_is_an_error_not_an_up_to_date_message() {
        assert!(parse_release("not json").is_err());
        assert!(parse_release(r#"{"assets": []}"#).is_err(), "no tag_name");
    }

    #[test]
    fn the_checksum_line_for_a_file_is_found() {
        let sums = "aaaa  tattle.exe\nbbbb  tattle-v0.1.0.zip\n";
        assert_eq!(expected_hash(sums, "tattle.exe").as_deref(), Some("aaaa"));
        assert_eq!(expected_hash(sums, "missing.exe"), None);
    }

    #[test]
    fn checksum_parsing_handles_crlf_and_extra_spaces() {
        let sums = "AABB  tattle.exe\r\n";
        assert_eq!(expected_hash(sums, "tattle.exe").as_deref(), Some("aabb"));
    }

    #[test]
    fn sha256_matches_the_published_test_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        // 56 bytes is the length that forces an extra padding block.
        assert_eq!(
            sha256_hex(&[b'a'; 56]),
            "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a"
        );
    }

    #[test]
    fn the_staged_binary_sits_beside_the_running_one() {
        // The name of the running executable is not knowable here: under
        // `cargo test` it is the hashed harness binary, and in production it is
        // tattle.exe. The contract is about the location and the suffix, so
        // assert those rather than a hard-coded filename.
        let staged = staged_path();
        let current = std::env::current_exe().expect("current exe");

        let staged_name = staged
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        let current_stem = current
            .file_stem()
            .and_then(|n| n.to_str())
            .unwrap_or_default();

        assert_eq!(
            staged.parent(),
            current.parent(),
            "the new binary is staged beside the old one"
        );
        assert!(staged_name.ends_with(".new.exe"), "got {staged_name}");
        assert!(
            staged_name.starts_with(current_stem),
            "{staged_name} does not derive from {current_stem}"
        );
        assert_ne!(
            staged, current,
            "a file cannot be replaced while it is running"
        );
    }
}
