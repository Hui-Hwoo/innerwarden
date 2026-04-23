use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::entities::EntityRef;
use crate::event::{default_severity, Severity};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Incident {
    #[serde(default)]
    pub ts: DateTime<Utc>,
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub incident_id: String,
    #[serde(default = "default_severity")]
    pub severity: Severity,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub evidence: serde_json::Value,
    #[serde(default)]
    pub recommended_checks: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub entities: Vec<EntityRef>,
}
