//! The Phase 2 live surface: monitor a run that is still in flight.
//!
//! [`state`] holds the pure, testable monitor state; [`ui`] renders the Live
//! view; [`driver`] is the interactive loop that launches or attaches to a run,
//! tails its case directory, and hands off to the finalized viewer when the run
//! seals a `verdict.json`. Read-only throughout: it launches the product
//! launcher and renders what the run reports; it never opens evidence, drives a
//! tool, or emits a Finding.

pub mod driver;
pub mod state;
pub mod ui;

pub use state::{LiveState, Phase};
