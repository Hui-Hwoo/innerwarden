//! Config-signing section.
//!
//! Spec 068 relocation: moved verbatim out of the former monolithic
//! `config.rs`. No logic change; serde defaults + helpers stay in
//! `config/mod.rs` and resolve through `use super::*`.

use super::*;

#[derive(Debug, Deserialize, Default, Clone)]
#[serde(deny_unknown_fields)]
pub struct ConfigSigningConfig {
    /// When true, agent refuses to start if signature is missing or invalid.
    #[serde(default)]
    pub required: bool,
    /// Hex-encoded Ed25519 public key for signature verification.
    #[serde(default)]
    pub public_key: Option<String>,
}
