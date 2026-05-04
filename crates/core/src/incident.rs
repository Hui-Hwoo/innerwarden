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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn incident_serialization() {
        let incident = Incident {
            ts: Utc::now(),
            host: "test-host".to_string(),
            incident_id: "test-id".to_string(),
            severity: Severity::High,
            title: "Test Incident".to_string(),
            summary: "This is a test".to_string(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![],
        };
        let serialized = serde_json::to_string(&incident).unwrap();
        assert!(serialized.contains("test-host"));
        assert!(serialized.contains("test-id"));
    }
}
