use std::collections::HashSet;
use std::fs;
use std::path::Path;

use serde::Deserialize;

// ---------------------------------------------------------------------------
// Ignore file: /etc/innerwarden/harden-ignore.toml
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
struct HardenIgnore {
    /// List of finding title substrings to ignore.
    /// Example: ["IP forwarding", "SUID binary", "kernel module"]
    #[serde(default)]
    ignore: Vec<String>,
}

pub(super) fn load_ignore_list(path: &Path) -> HashSet<String> {
    let Ok(content) = fs::read_to_string(path) else {
        return HashSet::new();
    };
    let config: HardenIgnore = toml::from_str(&content).unwrap_or_default();
    config.ignore.into_iter().collect()
}

pub(super) fn is_ignored(title: &str, ignore_list: &HashSet<String>) -> bool {
    let lower = title.to_lowercase();
    ignore_list
        .iter()
        .any(|pattern| lower.contains(&pattern.to_lowercase()))
}
