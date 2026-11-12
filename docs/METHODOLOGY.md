# How tattletale decides what a connection is

This document exists because the top question about a tool like this is always
the same: **how do you know it was that app?** The answer is a tiered system,
and the tool shows which tier every single row came from.

If you only read one line: **we would rather say "unknown" than guess.** A
privacy report that invents names is worse than no report.

## What is measured

Two independent sources are sampled on different cadences:

| Source | What it gives | How often | Cost |
|---|---|---|---|
| `GetExtendedTcpTable` | every TCP connection, its address, port, and owning process id | 1 s | ~0.6 ms |
| `ipconfig /displaydns` | name → address pairs the system resolver currently holds | 3 s | ~40 ms |

They are joined by **address**, inside a **time window**. That join is the whole
attribution system.

## The confidence tiers

| Tier | Glyph | Meaning | How it happens |
|---|---|---|---|
| Exact | ●●● | The DNS event itself named the requesting process. | Requires ETW, which requires administrator rights. **Never produced in standard mode.** |
| High | ●●○ | Exactly one name resolved in the window, and no other app used that address. | The common, reliable case. |
| Probable | ●○○ | Several names resolved for the address, or two apps shared it. | A CDN, or genuine ambiguity. All candidates are kept and shown. |
| Unknown | ○○○ | No name resolved for the address in the window. | The address is shown as-is. No name is invented. |

`Exact` exists in the data model so the tier ordering is total and a future ETW
collector can slot in without changing the store. The standard-mode engine
never emits it, and there is a test that asserts exactly that.

## The window

A name may explain a connection if the resolver produced it:

- at most **90 seconds before** the connection opened, and
- at most **3 seconds after** it opened.

The forward slack exists because the connection table and the resolver cache are
sampled at different moments; a connection can be seen before the cache poll that
contains its name. Three seconds covers that skew and nothing more.

Ninety seconds is deliberately short. A browser resolves immediately before it
connects. A name resolved two minutes ago belongs to some earlier, unrelated
connection, and treating it as an explanation is how tools end up confidently
wrong.

### Why `last_open_at` and not `first_at`

A client that reconnects every minute resolves again just before each reconnect.
Scoring against the first sighting of a connection would leave it permanently
matched to a name that expired long ago. The engine scores against the most
recent open, so a reconnecting client is re-evaluated each time.

## Shared addresses

When two applications connect to the same address inside the same window, the
second one cannot be `High`: the address has no single owner. It becomes
`Probable` with the method `address-shared-between-apps`. The same application
reusing its own address stays `High`, because there is no ambiguity.

## What is deliberately excluded

Filtered before attribution, because including it would be noise or a lie:

- **Loopback, link-local, multicast, broadcast.** Not remote traffic.
- **The machine's own interface addresses.** An app dialling the laptop's own
  `192.168.x.x` is not talking to a peer. Detected from the real interface list,
  not from a `192.168.` prefix guess — a NAS on the LAN is genuine traffic and
  must survive.
- **UDP connections.** `MIB_UDPROW_OWNER_PID` carries only the *local* bound
  address; there is no remote peer to attribute. The collector sees them and
  discards them rather than reporting the local address as if it were remote.
  This means QUIC traffic is not attributed in v0.1.
- **mDNS (port 5353).** Local discovery.
- **Single-label names, `.local`, `.lan`, `.internal`, and reverse-lookup
  zones.** A NetBIOS neighbour is not a website.

## The known blind spot: DNS over HTTPS

This is the honest part, and it is the single largest limitation of v0.1.

A browser that performs DNS over HTTPS resolves names inside its own process,
over a TLS connection to a resolver. Those lookups never reach the Windows
resolver cache. The connections are still visible — the tool sees the traffic and
counts it — but the name is not, so they arrive as `Unknown`.

On the machine this was developed on, a real measurement found **zero overlap**
between 42 cached names and 8 live connections. Every browser connection was
unnamed. `tattletale` reports that as `15% named`, not as a complete picture.

What the tool does about it:

1. **Detects it.** A connection to a known resolver endpoint on port 443
   (Cloudflare, Google, Quad9, AdGuard, NextDNS, OpenDNS, CleanBrowsing) is
   recognised, and the app making it is named in the receipt caveat.
2. **Discloses it.** The receipt shows the named-coverage percentage next to the
   headline numbers, and prints the caveat under the legend.
3. **Does not compensate for it.** No heuristic renaming, no guessing from
   reverse lookups, no silent under-reporting.

This is a deliberate v0.1 choice: ship honest, then recover the names. v0.1.1
adds reads of the browsers' own DNS caches, which is the correct fix for this
specific blind spot rather than a guess layered on top of it.

## What the numbers mean

- **connections** counts *opens*, not polls. A socket sampled every second for
  ten minutes is one connection. A tuple that disappears and returns is a new
  connection, because it is a new conversation.
- **flagged** counts connections whose best candidate is on a tracker list.
  It is a property of the *domain*, never of an application. This tool does not
  label software as spyware; it shows what a domain is on a list, and how often
  it was contacted.
- **named** is the fraction of connections that carry any domain at all. It is
  a measure of how much of the picture is complete, not of how bad the traffic is.

## What this tool cannot see

- Traffic that never touches a TCP connection table: raw sockets, tunnels that
  are already established before it starts.
- The *content* of anything. No packet capture, no TLS interception, no SNI
  inspection. It reads metadata the operating system already keeps.
- Anything historical. There is no retroactive record; it starts at zero.
- Connections owned by processes it cannot open. On the development machine,
  about two of seven pids had no readable image path. They are counted as
  unknown processes rather than dropped.

## Verifying these claims

The claims in this document are executable:

- Tier rules and edge cases: `cargo test --lib resolve`
- End-to-end on the live OS: `cargo test -- --ignored live_`
- The parser against a real 361-line `ipconfig` dump: `cargo test --test dns_real`

The tool never sends data anywhere. The only outbound request in the entire
product is a user-initiated tracker-list update, and it does not exist yet in
v0.1.
