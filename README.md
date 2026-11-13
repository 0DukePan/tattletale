<div align="center">

<img src="docs/demo.gif" width="860" alt="tattle running live: a table of applications filling in with connection counts, sites and flagged columns, ending with a receipt being written">

# tattletale

**Your apps are talking behind your back. Here are the receipts.**

A single Windows binary that shows which application contacted which company,
when, and how often — then writes it up as one HTML receipt you can keep,
print, or post.

[![CI](https://github.com/0DukePan/tattletale/actions/workflows/ci.yml/badge.svg)](https://github.com/0DukePan/tattletale/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/0DukePan/tattletale?color=informational)](https://github.com/0DukePan/tattletale/releases/latest)
[![Downloads](https://img.shields.io/github/downloads/0DukePan/tattletale/total)](https://github.com/0DukePan/tattletale/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Windows 10/11](https://img.shields.io/badge/platform-Windows%2010%2F11-lightgrey.svg)](#requirements)

```powershell
irm https://raw.githubusercontent.com/0DukePan/tattletale/main/install.ps1 | iex
```

No account. No cloud. No packet capture. No admin prompt.

</div>

---

## Why

You can see your bandwidth anywhere. Seeing the *pattern* — which app, which
company, how often, and whether that company is on a public tracker list — is
almost impossible without commercial software that reports on you itself.

`tattletale` reads metadata Windows already keeps. It does not capture packets,
does not intercept TLS, and does not send anything anywhere.

## The receipt

<img src="docs/receipt.png" width="760" alt="A tattletale receipt showing headline numbers, an hourly chart, a top talkers table and per-app cards with flagged domains">

One self-contained HTML file: headline numbers, an hour-by-hour chart, a top
talkers table, per-app cards, a confidence legend and a print stylesheet. It
opens from a USB stick with no network.

The image above comes from `tattle demo`, which is why it carries a
synthetic-data banner. A real receipt names your machine and shows your numbers.

## Install

**Windows 10 or 11**, no administrator rights needed.

```powershell
irm https://raw.githubusercontent.com/0DukePan/tattletale/main/install.ps1 | iex
```

The installer downloads the latest release, checks its SHA256 against the
published checksum, and puts `tattle.exe` under `%LOCALAPPDATA%\tattletale\bin`.

Every release also carries a winget manifest, so this works too:

```powershell
winget install --manifest https://github.com/0DukePan/tattletale/releases/latest/download/0DukePan.tattletale.installer.yaml
```

### Verify before you run it

The binary is not signed with a purchased certificate — it is signed keylessly,
with a short-lived certificate bound to the CI run that produced it. There is no
private key anywhere to steal:

```powershell
cosign verify-blob tattle.exe `
  --signature tattle.exe.sig `
  --certificate tattle.exe.pem `
  --certificate-identity-regexp "https://github.com/0DukePan/tattletale/.*" `
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

gh attestation verify tattle.exe --repo 0DukePan/tattletale
```

The first proves the workflow signed it; the second proves GitHub built it from
this repository's source.

> cosign v3 prints a deprecation warning for `--signature` and `--certificate`;
> verification still succeeds and exits 0. The flags are kept because they are
> the form this release publishes.

Both checks reject a modified binary: flipping a single byte makes `cosign`
report an invalid signature and makes `gh` return 404 for that digest. That was
tested, not assumed.

### Updating

```powershell
tattle update --check    # is there a newer release? changes nothing
tattle update            # download, verify the checksum, stage the new binary
```

**There is no background updater, deliberately.** A silent update check is an
outbound connection on every run, which would make the privacy claim on this
page false for the way the tool is normally used. An update channel is also the
most valuable thing in any program to compromise. `tattle update` verifies the
release checksum and stages the new binary next to the old one; swapping it is
a command you run.

### From source

```powershell
git clone https://github.com/0DukePan/tattletale
cd tattletale
cargo build --release
.\target\release\tattle.exe doctor
```

Requires [Rust](https://rustup.rs). This project is developed on a machine with
no Visual Studio Build Tools, so the local toolchain is GNU with
[WinLibs](https://winlibs.com) MinGW; CI builds the released binaries with MSVC.
See [CONTRIBUTING.md](CONTRIBUTING.md).

<a id="requirements"></a>

## Requirements

Windows 10 or 11, x86-64. Nothing else — no .NET, no Visual C++ redistributable,
no driver, no service. The binary is about 2.8 MB.

## Usage

```powershell
tattle                      # live view, until Ctrl-C
tattle report --open        # write a receipt and open it
tattle demo                 # a labelled example, before recording anything
```

| Command | What it does |
|---|---|
| `tattle` | Live table of what is talking right now |
| `tattle report --since 24h --open` | Write and open an HTML receipt |
| `tattle watch --duration 10m` | Record for a fixed time |
| `tattle top --since 24h --by sites` | Rank apps, sites or domains in the terminal |
| `tattle app chrome` | One application's traffic, by site |
| `tattle demo` | A clearly labelled synthetic day |
| `tattle lists update` | Download public tracker lists — the only outbound request |
| `tattle lists status` | Show which lists are loaded and where they came from |
| `tattle bench` | Score the attribution against labelled scenarios |
| `tattle doctor` | Check whether this machine can be measured |
| `tattle block` | Turn flagged domains into a hosts-file fragment you apply |
| `tattle update --check` | Ask the release feed whether a newer version exists |
| `tattle purge` | Delete everything it has recorded |
| `tattle top --json` | Machine-readable output for scripts |

Global flags: `--db <PATH>`, `--json`, `--no-color`, `--reverse-dns`.

## How it works

| Source | What it gives | Cost |
|---|---|---|
| `GetExtendedTcpTable` | every TCP connection and its owning process | ~0.6 ms per poll |
| `ipconfig /displaydns` | name → address pairs the resolver currently holds | ~40 ms, every 3 s |
| `GetAdaptersAddresses` | this machine's own addresses, to drop self-connections | once a minute |

The first two are joined by address inside a 90-second window. That join is the
whole attribution system, and it is documented in
[docs/METHODOLOGY.md](docs/METHODOLOGY.md).

## How accurate is it?

Every row carries a confidence tier, and the tier is always shown:

| Tier | Meaning |
|---|---|
| ●●● **Exact** | The DNS event named the requesting process. Requires admin; **never produced in v0.1**. |
| ●●○ **High** | Exactly one name resolved in the 90 seconds before the connection. |
| ●○○ **Probable** | Several names, or the address is shared between applications. |
| ○○○ **Unknown** | No name resolved. The address is shown, and no guess is made. |

**It would rather say "unknown" than invent a name.** A privacy report that
accuses the wrong application is worse than no report at all.

### Measured, not asserted

`tattle bench` runs nine labelled scenarios where the answer is known — shared
CDN addresses, expired cache entries, CNAME chains, DoH traffic with and without
a reverse record, reconnecting clients — and scores precision and recall against
the labels:

```
  precision        100.0%   of the names offered, how many were right
  recall           100.0%   of the names knowable, how many were found
  false positives  0        none: the tool never named something that was not there
  wrong but high   0        no confident answer was wrong
```

The scenarios are deliberately adversarial, and the benchmark is checked for
*vacuity*: disabling contention detection makes it fail. It measures correctness
and confidence, not coverage — "85% unnamed" and "100% of what was named was
right" are different claims, and only the second one matters.

### The DNS-over-HTTPS blind spot, and what can be recovered

Browsers using DNS over HTTPS resolve names inside their own process. Those
lookups never reach the Windows resolver cache, so their connections arrive as
bare addresses. On the machine this was built on, that left **15%** of
connections named.

The tool does not hide this: the receipt reports the fraction it could name,
next to the headline numbers, and names the applications bypassing the resolver.

Part of it is recoverable, because the *owner* of an address is a property of
the address rather than of how it was resolved. `142.250.75.238` has a PTR
record pointing into `1e100.net`, and that is Google whoever asked.

```powershell
tattle watch --duration 10m --reverse-dns
```

In a controlled test — connecting to four bare addresses, which is exactly what
DoH traffic looks like to this tool, with the resolver cache flushed first —
naming went from **0 of 4 to 4 of 4**:

| | named |
|---|---|
| without `--reverse-dns` | 0 of 4 |
| with `--reverse-dns` | 4 of 4 — `1e100.net`, `dns.google`, `github.com`, `one.one` |

Every one of those is `●○○ probable`, never `high`: a reverse lookup names the
owner of an address, not the site an application asked for, and the tool will
not pretend otherwise.

**It is off by default, on purpose.** A reverse lookup tells your resolver which
addresses this machine is talking to — precisely the fact DoH was hiding. That
trade is yours to make, which is why it is a flag and not a default.

## Privacy

| | |
|---|---|
| **Reads** | the connection table, process image paths, the resolver cache, interface addresses |
| **Sends** | nothing, except `tattle lists update`, which you must invoke |
| **Stores** | a SQLite database at `%LOCALAPPDATA%\tattletale\tattletale.db` |
| **Retention** | 7 days of connections, 24 hours of name observations |
| **Delete** | `tattle purge` |

These are enforced, not just promised. `tests/privacy.rs` fails the build if a
second HTTP client appears, if the receipt gains an external reference, or if a
hostname reaches the HTML unescaped. [SECURITY.md](SECURITY.md) states exactly
what the program reads and sends, and how to check it yourself.

The database is **not encrypted**. It is a record of what this machine talked to,
protected by your user profile's permissions. If that is not sufficient for your
threat model, do not run the tool.

## FAQ

**Does it need administrator rights?**
No, and that is a design constraint — everything it reads is available to a
standard user. The exact-confidence tier needs ETW and therefore elevation,
which is why v0.1 does not offer it.

**Does it block trackers?**
It does not enforce anything, and that is deliberate: a blocker needs elevation
and a filter driver, and it inherits a failure mode this project will not own —
silently breaking an application with no way to tell why.

`tattle block` produces the artefact a blocker would need, a hosts-file fragment
for the domains actually flagged on this machine, so you can see what you are
about to break and undo it in a text editor.

**Why is the "named" percentage low on my machine?**
Because your browser resolves over HTTPS. See [the blind spot](#the-known-blind-spot).

**Does it work on macOS or Linux?**
No. Collection is Windows-only, and so is the crate: the recording loop is bound
to the Windows collector, which means the library does not currently compile on
other platforms. The attribution engine, the store and the receipt are
platform-neutral and sit behind a `ConnectionSource` trait, so a port is a new
source implementation plus removing that binding — not a rewrite. It is the
largest piece of available work and it is not started.

**Is it a spyware detector?**
No. It has no access to content, only to the metadata Windows keeps about
connections, and it does not judge applications — only the domains they contact.

## Status

Early but functional: collector, DNS parser, attribution engine, SQLite and
in-memory stores, HTML receipt, live view, tracker lists, demo mode, purge.

- 183 tests; `cargo clippy --all-targets -- -D warnings` clean
- Verified against live Windows machines, not only against fixtures
- 72,999 tracker rules from OISD and EasyList; a 110-rule seed works offline
- [docs/METHODOLOGY.md](docs/METHODOLOGY.md) — how attribution works and where it fails
- [CHANGELOG.md](CHANGELOG.md) — what shipped and what is next

## Contributing

The most valuable contribution is a **false attribution**: a case where the tool
named the wrong application. There is an issue template for it. See
[CONTRIBUTING.md](CONTRIBUTING.md) for the build setup and the house rules.

## License

MIT. See [LICENSE](LICENSE).
