# Security policy

`tattletale` reads the operating system's connection table and resolver cache.
That is a privileged-looking thing for a program to do, so this document states
exactly what it touches, what it sends, and how to verify both.

## What the program reads

| Source | Access | Requires elevation |
|---|---|---|
| `GetExtendedTcpTable` / `GetExtendedUdpTable` | the connection table, with owning process ids | No |
| `QueryFullProcessImageNameW` | the image path of a process, for pids visible in that table | No |
| `ipconfig /displaydns` | the system resolver cache, as text | No |
| `GetAdaptersAddresses` | this machine's own interface addresses | No |

No packet capture. No TLS interception. No SNI inspection. No kernel driver. No
service installation. No firewall rules.

## What the program sends

**Nothing, except when you explicitly ask for a list update.**

- No telemetry, no crash reporting, no update check, no analytics.
- `tattle lists update` makes an HTTPS request to a public blocklist host. That
  is the only network code in the product, and it never runs automatically.
- The receipt is written to a local file and is never uploaded.

Verify the first claim yourself:

```powershell
tattle               # run it, then look at what it recorded about itself
tattle report --open
```

The tool excludes its own process id from collection, so it will not appear in
its own receipt.

## Verifying a downloaded release

Releases are **not** signed with a purchased code-signing certificate. They are
signed keylessly: GitHub Actions issues a short-lived OIDC token to the release
workflow, cosign signs the artifact with it, and the certificate is published
alongside. Nothing long-lived exists to be stolen, and the signature names the
exact workflow run that made the file.

```powershell
cosign verify-blob tattle.exe `
  --signature tattle.exe.sig `
  --certificate tattle.exe.pem `
  --certificate-identity-regexp "https://github.com/0DukePan/tattletale/.*" `
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

gh attestation verify tattle.exe --repo 0DukePan/tattletale
```

What this proves: the file was produced by that workflow, in this repository,
from the commit the run records. What it does not prove: that the maintainer's
account was not compromised. No signature scheme survives that.

Windows SmartScreen will still warn on first run, because SmartScreen reputation
comes from a paid certificate and download volume, neither of which this project
has. Verifying the hash or the attestation is the substitute.

## What it stores

A SQLite database at `%LOCALAPPDATA%\tattletale\tattletale.db` containing the
domains and addresses this machine contacted, the applications that contacted
them, and timestamps. This is sensitive: it is a record of what you did online.

Default retention is 7 days for connections and 24 hours for name observations.
Delete everything with:

```powershell
tattle purge --all
```

The database is not encrypted. It lives under your user profile with the
default ACLs for that location. If that is not sufficient for your threat
model, do not run the tool.

## Reporting a vulnerability

Open a private security advisory through GitHub:
**Security → Advisories → Report a vulnerability**.

Please do not open a public issue for anything that could expose a user's
traffic data.

Include the version (`tattle --version`), the Windows build, and a minimal
reproduction. I aim to acknowledge within 72 hours.

## Scope

In scope: memory-safety issues in the Windows collectors, HTML injection
through a hostile hostname into the receipt, path traversal in the list loader,
any outbound connection the program makes that is not `lists update`, and
anything that causes the tool to attribute traffic to the wrong application.

Out of scope: the documented DNS-over-HTTPS blind spot, which is a known and
disclosed limitation rather than a vulnerability, and the absence of
encryption at rest, which is a design decision documented above.
