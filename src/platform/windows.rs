//! Windows collectors.
//!
//! Two OS facts drive this module:
//!
//! * `GetExtendedTcpTable` / `GetExtendedUdpTable` give the full connection
//!   table with owning process ids in a single syscall. Spawning `netstat`
//!   costs ~12 ms per tick; this costs ~1 ms.
//! * `QueryFullProcessImageNameW` turns a pid into an image path without
//!   elevation. The cheaper `GetModuleFileNameEx` needs `PROCESS_VM_READ`,
//!   which is not granted for other users' processes.
//!
//! Both work as a standard user, which is the whole point: no admin prompt.

use std::collections::HashMap;
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_INSUFFICIENT_BUFFER, FILETIME, HANDLE, NO_ERROR,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetAdaptersAddresses, GetExtendedTcpTable, GetExtendedUdpTable, GAA_FLAG_SKIP_ANYCAST,
    GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST, IP_ADAPTER_ADDRESSES_LH,
    MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID, MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID,
    MIB_UDP6ROW_OWNER_PID, MIB_UDP6TABLE_OWNER_PID, MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID,
    TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_IN, SOCKADDR_IN6,
};
use windows_sys::Win32::System::Threading::QueryFullProcessImageNameW;
use windows_sys::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
};

use crate::model::{Proto, Sample};

/// TCP states worth counting. `LISTEN` and the closing states are noise: they
/// describe a socket that will never carry a byte to a remote peer.
const TCP_ESTABLISHED: u32 = 5;
const TCP_SYN_SENT: u32 = 3;

/// How long a pidâ†’path answer is trusted before it is refreshed. Pid reuse is
/// the reason this cache has a lifetime at all.
const PROC_CACHE_TTL: Duration = Duration::from_secs(30);

/// A process, resolved to the image path that identifies it across restarts.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProcessInfo {
    pub pid: u32,
    pub path: String,
    pub name: String,
}

/// Raw row from the OS, before attribution to an application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawConn {
    pub pid: u32,
    pub ip: String,
    pub port: u16,
    pub proto: Proto,
    pub state: u32,
    /// The address this end of the socket is bound to. When it equals `ip`,
    /// the machine is talking to itself.
    pub local_ip: String,
}

/// Collector for the Windows connection table and process image paths.
pub struct Collector {
    proc_cache: HashMap<u32, (ProcessInfo, Instant)>,
    /// Addresses bound to this machine's interfaces. Refreshed every few poll
    /// ticks, because a laptop changes networks without telling anyone.
    local_addresses: Vec<String>,
    local_refreshed: Option<Instant>,
}

/// How often the interface list is re-read.
const LOCAL_ADDR_TTL: Duration = Duration::from_secs(60);

impl Default for Collector {
    fn default() -> Self {
        Self::new()
    }
}

impl Collector {
    pub fn new() -> Self {
        Self {
            proc_cache: HashMap::new(),
            local_addresses: Vec::new(),
            local_refreshed: None,
        }
    }

    /// The addresses assigned to this machine right now.
    pub fn local_addresses(&mut self, now: Instant) -> &[String] {
        let fresh = self
            .local_refreshed
            .map(|t| now.duration_since(t) < LOCAL_ADDR_TTL)
            .unwrap_or(false);
        if !fresh {
            self.local_addresses = interface_addresses().unwrap_or_default();
            self.local_refreshed = Some(now);
        }
        &self.local_addresses
    }

    /// One polling tick: every remote-facing connection, resolved to an app.
    ///
    /// Addresses that cannot reach a remote peer (loopback, link-local,
    /// multicast, mDNS) are dropped here rather than in the engine, because
    /// only this layer knows what the OS reported.
    ///
    /// UDP rows are collected by [`Collector::raw_connections`] but never
    /// returned here: `MIB_UDPROW_OWNER_PID` carries only the *local* bound
    /// address, so there is no peer to attribute. Reporting the local address
    /// as if it were remote would be a lie, and this program does not lie about
    /// what it knows. QUIC therefore shows up as TCP fallback or not at all;
    /// see `docs/METHODOLOGY.md`.
    pub fn tick(&mut self, at: i64) -> anyhow::Result<Vec<Sample>> {
        let mut rows = self.raw_connections()?;
        let now = Instant::now();

        // Drop rows addressed to this machine. A socket to the machine's own
        // LAN address is still a self-connection even though it did not use
        // loopback, and reporting it would show apps "talking" to a device that
        // does not exist.
        let local = self.local_addresses(now).to_vec();
        if !local.is_empty() {
            rows.retain(|row| !local.iter().any(|addr| addr == &row.ip));
        }

        let mut samples = Vec::with_capacity(rows.len());
        for row in rows {
            if row.proto == Proto::Udp {
                continue;
            }
            let Some(proc) = self.process(row.pid, now) else {
                continue;
            };
            samples.push(Sample {
                at,
                app_path: proc.path.clone(),
                app_name: proc.name.clone(),
                ip: row.ip,
                port: row.port,
                proto: row.proto,
            });
        }
        Ok(samples)
    }

    /// Every connection row, unfiltered. Exposed for `tattle --dump-raw`, the
    /// fixture recorder, and the tests that compare against `netstat`.
    pub fn raw_connections(&self) -> anyhow::Result<Vec<RawConn>> {
        let mut out = Vec::new();
        out.extend(collect_tcp_v4()?);
        out.extend(collect_tcp_v6()?);
        out.extend(collect_udp_v4()?);
        out.extend(collect_udp_v6()?);
        out.retain(is_remote_facing);
        Ok(out)
    }

    /// Resolve a pid to an image path, memoised for [`PROC_CACHE_TTL`].
    pub fn process(&mut self, pid: u32, now: Instant) -> Option<&ProcessInfo> {
        let fresh = self
            .proc_cache
            .get(&pid)
            .map(|(_, seen)| now.duration_since(*seen) < PROC_CACHE_TTL)
            .unwrap_or(false);
        if !fresh {
            // Process 0 is the idle task and process 4 is the kernel: neither
            // has an image on disk, and neither ever opens a socket worth
            // attributing.
            if pid == 0 || pid == 4 {
                return None;
            }
            let info = process_image(pid)?;
            self.proc_cache.insert(pid, (info, now));
        }
        self.proc_cache.get(&pid).map(|(info, _)| info)
    }

    /// Drop cache entries for pids that no longer appear in the table.
    pub fn gc(&mut self, live: &[u32]) {
        self.proc_cache.retain(|pid, _| live.contains(pid));
    }
}

/// Whether a row can represent traffic to a remote host.
fn is_remote_facing(row: &RawConn) -> bool {
    if row.proto == Proto::Tcp {
        // UDP rows are connectionless; only the state field of TCP is meaningful.
        if row.state != TCP_ESTABLISHED && row.state != TCP_SYN_SENT {
            return false;
        }
    }
    if row.port == 5353 {
        // mDNS: local discovery, never a remote service.
        return false;
    }
    // A socket whose peer is its own bound address is the machine talking to
    // itself. This catches LAN-address self-connections (a local server reached
    // through the machine's own 192.168.x.x) that a loopback check misses.
    if !row.local_ip.is_empty() && row.local_ip == row.ip {
        return false;
    }
    is_routable(&row.ip)
}

/// Reject addresses that cannot belong to a remote service.
pub fn is_routable(ip: &str) -> bool {
    if ip.is_empty() {
        return false;
    }
    if let Ok(v4) = ip.parse::<std::net::Ipv4Addr>() {
        if v4.is_loopback() || v4.is_unspecified() || v4.is_link_local() || v4.is_multicast() {
            return false;
        }
        // 255.255.255.255 broadcast.
        if v4.is_broadcast() {
            return false;
        }
        return true;
    }
    if let Ok(v6) = ip.parse::<std::net::Ipv6Addr>() {
        if v6.is_loopback() || v6.is_unspecified() || v6.is_multicast() {
            return false;
        }
        let first = v6.segments()[0];
        // fc00::/7 unique-local and fe80::/10 link-local.
        if (first & 0xfe00) == 0xfc00 || (first & 0xffc0) == 0xfe80 {
            return false;
        }
        return true;
    }
    false
}

fn collect_tcp_v4() -> anyhow::Result<Vec<RawConn>> {
    let buf = table_buffer(|buf, size| unsafe {
        GetExtendedTcpTable(
            buf.cast(),
            size,
            0,
            AF_INET as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    })?;
    let table = buf.as_ptr().cast::<MIB_TCPTABLE_OWNER_PID>();
    let count = unsafe { (*table).dwNumEntries } as usize;
    let rows = unsafe { std::slice::from_raw_parts((*table).table.as_ptr(), count) };

    Ok(rows
        .iter()
        .map(|row: &MIB_TCPROW_OWNER_PID| RawConn {
            pid: row.dwOwningPid,
            // For an established TCP row the peer is the remote address; a
            // row with a zero remote address is a listening or closing socket.
            ip: ipv4(row.dwRemoteAddr),
            port: u16::from_be(row.dwRemotePort as u16),
            proto: Proto::Tcp,
            state: row.dwState,
            local_ip: ipv4(row.dwLocalAddr),
        })
        .collect())
}

fn collect_tcp_v6() -> anyhow::Result<Vec<RawConn>> {
    let buf = table_buffer(|buf, size| unsafe {
        GetExtendedTcpTable(
            buf.cast(),
            size,
            0,
            AF_INET6 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    })?;
    let table = buf.as_ptr().cast::<MIB_TCP6TABLE_OWNER_PID>();
    let count = unsafe { (*table).dwNumEntries } as usize;
    let rows = unsafe { std::slice::from_raw_parts((*table).table.as_ptr(), count) };

    Ok(rows
        .iter()
        .map(|row: &MIB_TCP6ROW_OWNER_PID| RawConn {
            pid: row.dwOwningPid,
            ip: ipv6(&row.ucRemoteAddr),
            port: u16::from_be(row.dwRemotePort as u16),
            proto: Proto::Tcp,
            state: row.dwState,
            local_ip: ipv6(&row.ucLocalAddr),
        })
        .collect())
}

fn collect_udp_v4() -> anyhow::Result<Vec<RawConn>> {
    let buf = table_buffer(|buf, size| unsafe {
        GetExtendedUdpTable(buf.cast(), size, 0, AF_INET as u32, UDP_TABLE_OWNER_PID, 0)
    })?;
    let table = buf.as_ptr().cast::<MIB_UDPTABLE_OWNER_PID>();
    let count = unsafe { (*table).dwNumEntries } as usize;
    let rows = unsafe { std::slice::from_raw_parts((*table).table.as_ptr(), count) };

    Ok(rows
        .iter()
        .map(|row: &MIB_UDPROW_OWNER_PID| RawConn {
            pid: row.dwOwningPid,
            ip: udp_placeholder_ip(row),
            port: 0,
            proto: Proto::Udp,
            state: 0,
            local_ip: ipv4(row.dwLocalAddr),
        })
        .collect())
}

fn collect_udp_v6() -> anyhow::Result<Vec<RawConn>> {
    let buf = table_buffer(|buf, size| unsafe {
        GetExtendedUdpTable(buf.cast(), size, 0, AF_INET6 as u32, UDP_TABLE_OWNER_PID, 0)
    })?;
    let table = buf.as_ptr().cast::<MIB_UDP6TABLE_OWNER_PID>();
    let count = unsafe { (*table).dwNumEntries } as usize;
    let rows = unsafe { std::slice::from_raw_parts((*table).table.as_ptr(), count) };

    Ok(rows
        .iter()
        .map(|row: &MIB_UDP6ROW_OWNER_PID| RawConn {
            pid: row.dwOwningPid,
            ip: ipv6(&row.ucLocalAddr),
            port: 0,
            proto: Proto::Udp,
            state: 0,
            local_ip: ipv6(&row.ucLocalAddr),
        })
        .collect())
}

/// UDP rows carry only the *local* address: a UDP socket is not bound to a
/// peer, so there is nothing to attribute. The collector reports the bound
/// address and the engine ignores it rather than inventing a remote peer.
fn udp_placeholder_ip(row: &MIB_UDPROW_OWNER_PID) -> String {
    ipv4(row.dwLocalAddr)
}

fn ipv4(raw: u32) -> String {
    // Network order in the low 24 bits plus host order in the high byte; the
    // byte order dance is what every Windows network tool does here.
    let bytes = raw.to_le_bytes();
    format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
}

fn ipv6(raw: &[u8; 16]) -> String {
    let mut octets = [0u8; 16];
    octets.copy_from_slice(raw);
    std::net::Ipv6Addr::from(octets).to_string()
}

/// Every unicast address assigned to this machine, IPv4 and IPv6.
///
/// Used to recognise self-connections that do not use loopback: an app that
/// dials the laptop's own `192.168.x.x` address is not talking to a peer.
pub fn interface_addresses() -> anyhow::Result<Vec<String>> {
    const FLAGS: u32 = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;

    let mut size: u32 = 16 * 1024;
    let mut buf: Vec<u8> = Vec::new();
    for _ in 0..4 {
        buf.resize(size as usize, 0);
        let status = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC as u32,
                FLAGS,
                std::ptr::null(),
                buf.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>(),
                &mut size,
            )
        };
        match status {
            0 => break,
            // ERROR_BUFFER_OVERFLOW: `size` now holds what we need.
            111 => {
                if buf.len() >= size as usize {
                    anyhow::bail!("GetAdaptersAddresses reported the same insufficient size twice");
                }
                continue;
            }
            other => anyhow::bail!("GetAdaptersAddresses failed with status {other}"),
        }
    }

    let mut out = Vec::new();
    let mut adapter = buf.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
    while !adapter.is_null() {
        unsafe {
            let mut unicast = (*adapter).FirstUnicastAddress;
            while !unicast.is_null() {
                let sockaddr = (*unicast).Address.lpSockaddr;
                if !sockaddr.is_null() {
                    let family = (*sockaddr).sa_family;
                    if family == AF_INET {
                        let v4 = sockaddr.cast::<SOCKADDR_IN>();
                        // `S_addr` is in network order, which on a little-endian
                        // machine is the same DWORD layout the MIB tables use.
                        // Do not byte-swap it here.
                        out.push(ipv4((*v4).sin_addr.S_un.S_addr));
                    } else if family == AF_INET6 {
                        let v6 = sockaddr.cast::<SOCKADDR_IN6>();
                        out.push(ipv6(&(*v6).sin6_addr.u.Byte));
                    }
                }
                unicast = (*unicast).Next;
            }
            adapter = (*adapter).Next;
        }
    }
    out.sort_unstable();
    out.dedup();
    Ok(out)
}

/// Call a `GetExtended*Table` function with the retry-on-`ERROR_INSUFFICIENT_BUFFER`
/// dance the API requires.
fn table_buffer(mut call: impl FnMut(*mut u8, &mut u32) -> u32) -> anyhow::Result<Vec<u8>> {
    let mut size: u32 = 0;
    let mut buf: Vec<u8> = Vec::new();
    for _ in 0..4 {
        let status = call(buf.as_mut_ptr(), &mut size);
        if status == NO_ERROR {
            return Ok(buf);
        }
        if status != ERROR_INSUFFICIENT_BUFFER {
            anyhow::bail!("GetExtended*Table failed with status {status}");
        }
        // Add slack: the table can grow between the size query and the call.
        buf.resize(size as usize + 1024, 0);
    }
    anyhow::bail!("GetExtended*Table did not return a stable size after 4 attempts")
}

/// Resolve an image path for a pid without elevation.
pub fn process_image(pid: u32) -> Option<ProcessInfo> {
    unsafe {
        let handle: HANDLE = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            return None;
        }
        let mut buffer = vec![0u16; 1024];
        let mut len = buffer.len() as u32;
        let ok = QueryFullProcessImageNameW(handle, 0, buffer.as_mut_ptr(), &mut len);
        CloseHandle(handle);
        if ok == 0 {
            return None;
        }
        let wide: OsString = OsString::from_wide(&buffer[..len as usize]);
        let path = wide.to_string_lossy().into_owned();
        let name = path.rsplit('\\').next().unwrap_or(&path).to_string();
        Some(ProcessInfo { pid, path, name })
    }
}

/// Creation time of a process, used to distinguish a recycled pid from the
/// original one.
pub fn process_created_at(pid: u32) -> Option<u64> {
    unsafe {
        let handle: HANDLE = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            return None;
        }
        let mut creation = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let mut exit = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let mut kernel = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let mut user = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let ok = GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user);
        CloseHandle(handle);
        if ok == 0 {
            None
        } else {
            Some(((creation.dwHighDateTime as u64) << 32) | creation.dwLowDateTime as u64)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routable_rejects_local_addresses() {
        for bad in [
            "0.0.0.0",
            "127.0.0.1",
            "169.254.1.1",
            "224.0.0.251",
            "255.255.255.255",
            "::1",
            "::",
            "fe80::1",
            "ff02::fb",
            "fc00::1",
            "",
            "not-an-ip",
        ] {
            assert!(!is_routable(bad), "{bad} must not be treated as routable");
        }
    }

    #[test]
    fn routable_accepts_public_addresses() {
        for good in [
            "142.250.75.238",
            "8.8.8.8",
            "2606:4700:4700::1111",
            "192.168.1.10",
        ] {
            assert!(is_routable(good), "{good} must be routable");
        }
    }

    #[test]
    fn tcp_rows_need_a_live_state() {
        let base = RawConn {
            pid: 1,
            ip: "8.8.8.8".into(),
            port: 443,
            proto: Proto::Tcp,
            state: TCP_ESTABLISHED,
            local_ip: "192.168.1.10".into(),
        };
        assert!(is_remote_facing(&base));
        assert!(
            !is_remote_facing(&RawConn {
                state: 2,
                ..base.clone()
            }),
            "LISTEN is not traffic"
        );
        assert!(
            is_remote_facing(&RawConn {
                state: TCP_SYN_SENT,
                ..base.clone()
            }),
            "a pending outbound connect is still traffic to a remote peer"
        );
        assert!(!is_remote_facing(&RawConn { port: 5353, ..base }));
    }

    #[test]
    fn self_connections_are_dropped_even_on_the_lan() {
        // The machine reaching its own 192.168.x.x address is not remote traffic,
        // and it is the one case a loopback check cannot catch.
        let row = RawConn {
            pid: 1,
            ip: "192.168.1.5".into(),
            port: 8008,
            proto: Proto::Tcp,
            state: TCP_ESTABLISHED,
            local_ip: "192.168.1.5".into(),
        };
        assert!(!is_remote_facing(&row));
        // A different host on the same LAN is real traffic and must survive.
        assert!(is_remote_facing(&RawConn {
            ip: "192.168.1.9".into(),
            ..row
        }));
    }

    #[test]
    fn interface_addresses_include_loopback_and_are_parseable() {
        let addrs = interface_addresses().expect("adapter enumeration must work unelevated");
        assert!(
            !addrs.is_empty(),
            "a machine with no addresses cannot reach the internet"
        );
        assert!(
            addrs.iter().any(|a| a == "127.0.0.1"),
            "loopback must be listed; got {addrs:?}"
        );
        // Byte order is the classic bug here: 127.0.0.1 rendered as 1.0.0.127.
        assert!(
            !addrs.iter().any(|a| a == "1.0.0.127"),
            "IPv4 address byte order is reversed; got {addrs:?}"
        );
        for addr in &addrs {
            assert!(
                addr.parse::<std::net::IpAddr>().is_ok(),
                "{addr} is not a valid address"
            );
        }
    }

    #[test]
    fn udp_rows_are_never_ticked() {
        // MIB_UDPROW_OWNER_PID has no remote address, so a UDP "connection"
        // cannot be attributed. The collector must not invent one.
        let mut collector = Collector::new();
        let samples = collector.tick(0).expect("tick");
        for sample in &samples {
            assert_eq!(
                sample.proto,
                Proto::Tcp,
                "UDP carries no peer address and must not be ticked"
            );
        }
    }

    #[test]
    fn ipv4_byte_order_matches_the_os() {
        // 142.250.75.238 in network order, as the table stores it.
        assert_eq!(ipv4(0xEE4BFA8E), "142.250.75.238");
        assert_eq!(ipv4(0x08080808), "8.8.8.8");
    }

    #[test]
    fn collector_resolves_its_own_process() {
        let mut collector = Collector::new();
        let pid = std::process::id();
        let info = collector
            .process(pid, Instant::now())
            .expect("own process must resolve");
        assert!(info.name.to_ascii_lowercase().ends_with(".exe"));
        assert!(info.path.contains(&info.name));
    }

    #[test]
    fn kernel_pids_are_skipped() {
        let mut collector = Collector::new();
        assert!(collector.process(0, Instant::now()).is_none());
        assert!(collector.process(4, Instant::now()).is_none());
    }

    #[test]
    fn raw_connections_are_well_formed() {
        let collector = Collector::new();
        let rows = collector
            .raw_connections()
            .expect("connection table must be readable");
        for row in &rows {
            assert!(!row.ip.is_empty(), "a row without an address is a bug");
            assert!(
                is_routable(&row.ip),
                "loopback/link-local rows must be filtered: {}",
                row.ip
            );
        }
    }
}
