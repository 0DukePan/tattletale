# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[semantic versioning](https://semver.org/).

## [Unreleased]

Nothing yet.

## [0.1.1] - 2026-11-13

### Added

- **Keyless release signing and build provenance.** Every artifact is signed by
  the release workflow with a short-lived certificate bound to that run, and
  attested by GitHub. `cosign verify-blob` proves the workflow signed it;
  `gh attestation verify` proves GitHub built it from this repository. A
  purchased certificate would be better for SmartScreen reputation; it is not
  required for verifiability, and it is not something this project can afford.
- **winget manifests**, generated during the release so they always carry the
  hash of the artifact that was just built.
- **`tattle update [--check]`** — an updater you invoke, not one that runs. It
  fetches the release, verifies the SHA-256 before writing anything, and stages
  the new binary beside the running one because Windows will not replace a
  locked executable. There is deliberately no background update check: that
  would be an outbound connection on every run, and it would contradict the
  claim on the front page.

### Added

- **`--reverse-dns`** — names the owner of an address when no hostname explains
  it, which is the only thing that can be recovered for traffic that bypassed
  the system resolver. In a controlled test with a flushed cache, four
  connections to bare addresses went from 0 named to 4 named. Off by default,
  because it tells the local resolver which addresses this machine is using.
- **A reverse-DNS confidence tier.** A PTR answer names the owner of an address,
  not the site an application asked for, so it is always `probable` and never
  outranks a real hostname. There is a test for exactly that.
- **`tattle block`** — writes a hosts-file fragment for the domains flagged on
  this machine, with a header, an explanation of how to apply it, and how to
  undo it. It does not modify the hosts file and never asks for elevation.
- **`docs/METHODOLOGY.md`** now documents the reverse-DNS tier alongside the
  others.

### Fixed

- Reverse lookups ran inside the collection tick and stalled the one-second
  poll: a single slow resolver made the tool miss connections in order to
  describe them. They now run on threads of their own, with the collection loop
  reading whatever has arrived.
- A single shared worker thread queued every lookup behind the slowest one, so
  one timing-out address silenced the feature. Lookups are now concurrent.
- The observation window was anchored to the connection's timestamp, so an
  answer that arrived two ticks later was filtered out. That is why enrichment
  only appeared to work when the resolver cache already held the name.

### Planned for v0.2.0

- Read the browsers' own DNS caches, which would recover hostnames rather than
  just owners, and remove the need for the flag entirely.

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

[Unreleased]: https://github.com/0DukePan/tattletale/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/0DukePan/tattletale/releases/tag/v0.1.1
[0.1.0]: https://github.com/0DukePan/tattletale/releases/tag/v0.1.0
