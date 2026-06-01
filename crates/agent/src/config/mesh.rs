//! Mesh-network config sections.
//!
//! Spec 068 relocation: moved verbatim out of the former monolithic
//! `config.rs`. No logic change; serde defaults + helpers stay in
//! `config/mod.rs` and resolve through `use super::*`.

use super::*;

/// Mesh network config - mirrors innerwarden_mesh::MeshConfig
/// but decoupled so the agent compiles without the mesh feature.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
#[serde(deny_unknown_fields)]
pub struct MeshNetworkConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_mesh_bind")]
    pub bind: String,
    #[serde(default)]
    pub peers: Vec<MeshPeerEntry>,
    #[serde(default = "default_mesh_poll_secs")]
    pub poll_secs: u64,
    #[serde(default = "default_true_val")]
    pub auto_broadcast: bool,
    #[serde(default = "default_mesh_max_signals")]
    pub max_signals_per_hour: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub struct MeshPeerEntry {
    pub endpoint: String,
    pub public_key: String,
    #[serde(default)]
    pub label: Option<String>,
}

impl Default for MeshNetworkConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind: default_mesh_bind(),
            peers: vec![],
            poll_secs: default_mesh_poll_secs(),
            auto_broadcast: true,
            max_signals_per_hour: default_mesh_max_signals(),
        }
    }
}
