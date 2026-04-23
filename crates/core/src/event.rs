use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::entities::EntityRef;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Debug,
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// `#[serde(default)]` for the `severity` field on `Event` and
/// `Incident`. Derived `Default::default()` on `Severity` would return
/// the first variant (`Debug`), which is semantically wrong for a
/// missing-severity legacy record — `Info` is the neutral "we saw it,
/// we have no opinion yet" value that every downstream filter already
/// treats as non-actionable. See spec 035 PR-A5.
pub(crate) fn default_severity() -> Severity {
    Severity::Info
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    #[serde(default)]
    pub ts: DateTime<Utc>,
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub kind: String,
    #[serde(default = "default_severity")]
    pub severity: Severity,
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub details: serde_json::Value,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub entities: Vec<EntityRef>,
}
