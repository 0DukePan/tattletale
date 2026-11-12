//! Operating-system specific collectors.
//!
//! Everything else in this crate compiles anywhere. This module is where the
//! platform seam lives, so porting means adding a sibling module, not editing
//! the engine.

#[cfg(windows)]
pub mod windows;
