//! tattletale â€” see every domain your apps phone home to.
//!
//! The library is deliberately split so that everything except [`platform`]
//! compiles and tests on any host:
//!
//! * [`model`] â€” plain data types shared by collector, store and UI
//! * [`store`] â€” SQLite persistence behind a trait, so tests can use any backend
//! * [`dns`] â€” parsing and correlation of name/address observations
//! * [`resolve`] â€” the attribution engine (tiering, ambiguity handling)
//! * [`classify`] â€” tracker list matching
//! * [`report`] â€” HTML receipt rendering, a pure function of a report model
//! * [`platform`] â€” the only OS-specific code (Windows collectors)

pub mod classify;
pub mod commands;
pub mod demo;
pub mod dns;
pub mod health;
pub mod live;
pub mod model;
pub mod platform;
pub mod report;
pub mod resolve;
pub mod store;
pub mod watch;

/// Crate version, surfaced in the HTML receipt footer and in `tattle doctor`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Name shown in reports and the live view header.
pub const PRODUCT: &str = "tattletale";

/// Current unix time in seconds. Panics on a clock before 1970, which cannot
/// happen on any machine this runs on and would be a bug elsewhere anyway.
pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
