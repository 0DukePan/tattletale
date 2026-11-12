# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[semantic versioning](https://semver.org/).

## [Unreleased]

### Planned for v0.1.1

- Read the browsers' own DNS caches, so DNS-over-HTTPS lookups become visible.
  This is the largest accuracy gap in v0.1 and the first thing to fix.

## [0.1.0] - 2026-11-12

First release. Windows 10/11, standard user, no elevation.

### Added

- **Collector** — the Windows TCP table via `GetExtendedTcpTable`, with owning
  process ids, at about 0.6 ms per poll. No packet capture, no driver.
- **Process identification** — pid to image path via
  `QueryFullProcessImageNameW`, cached for 30 seconds to survive pid reuse.
- **DNS observation** — `ipconfig /displaydns` parsed by value shape rather
  than label text, so it survives a localised Windows. First-seen tracking with
  TTL-refresh detection, so a stale address does not look freshly resolved.
- **Attribution engine** — tiered confidence (exact, high, probable, unknown)
  scored against a 90-second window, with explicit handling for shared CDN
  addresses. Unknown connections are reported as unknown.
- **Storage** — SQLite with WAL, or an in-memory store for tests; both are held
  to the same contract by `tests/store_contract.rs`.
- **HTML receipt** — a single self-contained file with headline numbers, an
  hourly chart, top talkers, per-app cards, a confidence legend and a print
  stylesheet.
- **Live view** — bare `tattle` shows a redrawn table until Ctrl-C.
- **Tracker lists** — a 110-rule seed authored in-tree, plus on-demand download
  of OISD and EasyList (about 73,000 rules). Suffix matching, most specific rule
  wins, with a test that a lookalike domain is not flagged.
- **Demo mode** — `tattle demo` renders a synthetic day, clearly labelled as
  synthetic in the receipt.
- **Disclosure** — the receipt reports the fraction of connections it could
  name and names the applications bypassing the system resolver through DNS
  over HTTPS.

### Known limitations

- **DNS over HTTPS is invisible.** A browser resolving through DoH never
  populates the system cache, so its connections appear as bare addresses. On
  the development machine this left 85% of connections unnamed. Disclosed, not
  papered over.
- **QUIC is not attributed.** `MIB_UDPROW_OWNER_PID` carries no remote address,
  so UDP connections cannot be tied to a peer.
- **Windows only.** The engine is portable; the collectors are not.
- **Unencrypted database.** It contains a record of your traffic and relies on
  the filesystem permissions of your user profile.

[Unreleased]: https://github.com/OWNER/tattletale/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/OWNER/tattletale/releases/tag/v0.1.0
