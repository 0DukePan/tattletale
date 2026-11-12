<div align="center">

# tattletale

**Your apps are talking behind your back. Here are the receipts.**

A single Windows binary that shows which application contacted which company,
when, and how often — then writes it up as one HTML receipt you can keep,
print, or post.

[![CI](https://github.com/OWNER/tattletale/actions/workflows/ci.yml/badge.svg)](https://github.com/OWNER/tattletale/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Windows 10/11](https://img.shields.io/badge/platform-Windows%2010%2F11-lightgrey.svg)](#)

<img src=".github/assets/demo.png" alt="A tattletale receipt: 39 connections, 8 apps, 44% flagged, with red ADS chips on doubleclick.net and amber ANALYTICS chips on google-analytics.com" width="820">

<sub>The receipt, rendered by <code>tattle demo</code>. The banner in the image is part of the
output: synthetic data is always labelled as synthetic.</sub>

</div>

---

## Install

```powershell
irm https://raw.githubusercontent.com/OWNER/tattletale/main/install.ps1 | iex
```

Or download the zip from [Releases](https://github.com/OWNER/tattletale/releases),
check it against `SHA256SUMS.txt`, and put `tattle.exe` on your `PATH`.

No account. No cloud. No packet capture. No admin prompt.

## Use

```powershell
tattle                      # live view, until Ctrl-C
tattle report --open        # write a receipt and open it
tattle demo                 # see a labelled example first
```

| Command | What it does |
|---|---|
| `tattle` | Live table of what is talking right now |
| `tattle report --since 24h --open` | Write and open an HTML receipt |
| `tattle watch --duration 10m` | Record for a fixed time |
| `tattle top --since 24h --by sites` | Rank sites, apps or domains in the terminal |
| `tattle app chrome` | One application's traffic, by site |
| `tattle demo` | A labelled synthetic day, for a look before recording |
| `tattle lists update` | Download public tracker lists (the only outbound request) |
| `tattle doctor` | Check whether this machine can be measured |
| `tattle purge` | Delete everything it has recorded |
| `tattle top --json` | The same data, for scripts |

## What it actually does

Every app contacts dozens of domains you never asked for. You can see your
*bandwidth* anywhere; seeing the *pattern* — which app, which company, how often
— is nearly impossible without commercial software that phones home itself.

`tattle` reads the connection and DNS metadata Windows already keeps:

| Source | What it gives | Cost |
|---|---|---|
| `GetExtendedTcpTable` | every TCP connection and its owning process | ~0.6 ms per poll |
| `ipconfig /displaydns` | name → address pairs the resolver holds | ~40 ms, every 3 s |

No packet capture. No TLS interception. No kernel driver. No service.

## How sure is it?

Every attribution carries a tier, and the tier is always shown:

| Tier | Meaning |
|---|---|
| ●●● Exact | The DNS event named the requesting process. Requires admin; **never produced in v0.1**. |
| ●●○ High | Exactly one name resolved in the 90 seconds before the connection. |
| ●○○ Probable | Several names, or the address is shared between apps. |
| ○○○ Unknown | No name resolved. The address is shown, and no guess is made. |

**It would rather say "unknown" than invent a name.** The full rules, the
window, and every exclusion are in [docs/METHODOLOGY.md](docs/METHODOLOGY.md).

## The known blind spot

Browsers using DNS over HTTPS resolve names inside their own process. Those
lookups never reach the Windows resolver cache, so their connections arrive as
bare addresses.

The tool does not hide this. The receipt reports what fraction of connections it
could name, next to the headline numbers, and names the applications that are
bypassing the system resolver.

On the machine this was built on, that figure was **15%**. That is the honest
number, and it is why the demo scene exists: so the tool can be judged on what
it shows rather than on what a particular machine happened to browse.

Recovering browser lookups is the first item in v0.1.1.

## What it does NOT do

- **No packet capture, no TLS interception, no SNI inspection.** Metadata only.
- **No cloud, no telemetry, no update check.** The binary makes no outbound
  connections. `tests/privacy.rs` fails the build if that changes.
- **No kernel driver, no admin prompt.** It runs as a standard user.
- **No accusations.** It reports what a *domain* is on a public list and how
  often it was contacted. It does not label software as spyware.
- **No macOS or Linux yet.** The engine is portable; the collectors are not.

## Status

Working: collector, DNS parser, attribution engine, SQLite and in-memory stores,
HTML receipt, live view, tracker lists, demo mode, purge.

- 106 tests; `cargo clippy --all-targets -- -D warnings` clean
- Verified against a live Windows 10 machine, not only against fixtures
- 72,999 tracker rules from OISD and EasyList; a 110-rule seed works offline
- [docs/METHODOLOGY.md](docs/METHODOLOGY.md) — how attribution works and where it fails
- [SECURITY.md](SECURITY.md) — exactly what it reads and what it sends
- [CONTRIBUTING.md](CONTRIBUTING.md) — build setup and the house rules

## Build from source

```powershell
git clone https://github.com/OWNER/tattletale
cd tattletale
cargo build --release
.\target\release\tattle.exe doctor
```

Requires [Rust](https://rustup.rs). This project is developed on a machine with
no Visual Studio Build Tools, so the local toolchain is GNU with
[WinLibs](https://winlibs.com) MinGW; CI builds the released binaries with MSVC.
See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT. See [LICENSE](LICENSE).
