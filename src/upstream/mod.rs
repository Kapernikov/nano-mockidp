//! Optional gate: testers log in at an upstream OIDC provider before they may pick a persona.

pub mod gate;

pub mod client;
pub use client::Upstream;
