<div align="center">

# tattletale

**Your apps are talking behind your back. Here are the receipts.**

A single Windows binary that shows which application contacted which company,
when, and how often — and writes it up as one HTML receipt you can keep,
print, or post.

No account. No cloud. No packet capture. No admin prompt.

<sub>Windows 10/11 · MIT · written in Rust</sub>

</div>

---

## What it looks like

```
$ tattle report

  receipt written to receipt.html
  13 connections | 5 apps | 2 sites | 0% flagged | 15% named
```

```text
  APP                     CONNS   SITES   FLAGGED
  brave.exe                   6       1         0
  DeepSeek Harness.exe        2       1         0
  Discord.exe                 2       0         0
  NVIDIA Overlay.exe          2       0         0
```

The receipt is a single self-contained HTML file: headline numbers, a
connections-by-hour chart, top talkers, per-app cards, and a legend that says
how sure each attribution is. It opens from a USB stick with no network and
prints on A4.

## Why

Every app on your computer contacts dozens of domains you never asked for.
You can see your *bandwidth* anywhere; seeing the *pattern* — which app, which
company, how often — is nearly impossible without commercial software that
phones home itself.

`tattle` reads the connection and DNS metadata Windows already keeps. It does
not capture packets, does not intercept TLS, and does not send anything
anywhere.

## Install

Build from source (v0.1 has no packaged release yet):

```powershell
git clone https://github.com/tattletale/tattletale
cd tattletale
cargo build --release
.\target\release\tattle.exe doctor
```

Requires [Rust](https://rustup.rs). On Windows without Visual Studio Build
Tools, use the GNU toolchain (`rust-toolchain.toml` pins it) and install
[WinLibs](https://winlibs.com) MinGW.

## Use

```powershell
tattle doctor              # can this machine be measured?
tattle watch --duration 10m   # record traffic
tattle report --since 24h     # write receipt.html
tattle report --open          # ...and open it
```

| Command | What it does |
|---|---|
| `tattle doctor` | Checks the collector, the interface list, and the DNS source |
| `tattle watch --duration 10m` | Records into the local database |
| `tattle report --since 24h` | Writes a single-file HTML receipt |
| `tattle demo` | Renders a labelled synthetic scene, for a look before recording |
| `tattle lists update` | Downloads public tracker lists (the only outbound request) |
| `tattle lists status` | Shows how many rules are loaded and where they came from |
| `tattle --db <path>` | Uses a different database file |

## How sure is it?

Every attribution carries a tier, and the tier is always shown:

| Tier | Meaning |
|---|---|
| ●●● Exact | The DNS event named the requesting process. Requires admin; **never produced in v0.1**. |
| ●●○ High | Exactly one name resolved in the 90-second window before the connection. |
| ●○○ Probable | Several names, or the address is shared between apps. |
| ○○○ Unknown | No name resolved. The address is shown, and no guess is made. |

**The tool would rather say "unknown" than invent a name.** Full rules, the
window, and the exclusions are in [docs/METHODOLOGY.md](docs/METHODOLOGY.md).

## The known blind spot

Browsers using DNS over HTTPS resolve names inside their own process. Those
lookups never reach the Windows resolver cache, so their connections appear as
bare addresses. This is not hidden: the receipt reports what fraction of
connections could be named, and names the applications hiding their lookups.

On the development machine, that number was **15%**. That is the honest figure,
and it is why the tool does not claim to show everything.

Recovering browser lookups is the first item in v0.1.1.

## What it does NOT do

- **No packet capture, no TLS interception, no SNI inspection.** Metadata only.
- **No cloud, no telemetry, no update check.** The binary makes no outbound
  connections.
- **No kernel driver, no admin prompt.** It works as a standard user.
- **No accusations.** It reports what a *domain* is on a public list and how
  often it was contacted. It does not label software as spyware.
- **No macOS or Linux yet.** The engine is portable; the collectors are not.

## Status

Working: the collector, the DNS parser, the attribution engine, the two stores,
the receipt renderer, tracker lists, and a labelled demo mode.
Not yet built: the live TUI and packaged releases.

- 87 tests, `clippy -D warnings` clean
- Verified against a live Windows 10 machine, not only against fixtures
- 72,999 tracker rules load from OISD and EasyList; the bundled seed works offline
- [docs/METHODOLOGY.md](docs/METHODOLOGY.md) — how attribution works and where it fails

## License

MIT. See [LICENSE](LICENSE).
