//! tattletale — see every domain your apps phone home to.
//!
//! The library is deliberately split so that everything except [`platform`]
//! compiles and tests on any host:
//!
//! * [`model`] — plain data types shared by collector, store and UI
//! * [`store`] — SQLite persistence behind a trait, so tests can use any backend
//! * [`dns`] — parsing and correlation of name/address observations
//! * [`resolve`] — the attribution engine (tiering, ambiguity handling)
//! * [`classify`] — tracker list matching
//! * [`report`] — HTML receipt rendering, a pure function of a report model
//! * [`platform`] — the only OS-specific code (Windows collectors)

pub mod classify;
pub mod dns;
pub mod model;
pub mod platform;
pub mod report;
pub mod resolve;
pub mod store;

/// Crate version, surfaced in the HTML receipt footer and in `tattle doctor`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Name shown in reports and the TUI header.
pub const PRODUCT: &str = "tattletale";
