use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::entities::EntityRef;
use crate::event::Severity;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signal {
    pub ts: DateTime<Utc>,
    pub host: String,
    pub detector: String,
    pub kind: String,
    pub severity_hint: Severity,
    pub score: f32,
    pub summary: String,
    pub evidence: serde_json::Value,
    pub tags: Vec<String>,
    pub entities: Vec<EntityRef>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signal_serialization() {
        let signal = Signal {
            ts: Utc::now(),
            host: "test-host".to_string(),
            detector: "test-detector".to_string(),
            kind: "test-kind".to_string(),
            severity_hint: Severity::Medium,
            score: 0.8,
            summary: "Test summary".to_string(),
            evidence: serde_json::json!({}),
            tags: vec![],
            entities: vec![],
        };
        let serialized = serde_json::to_string(&signal).unwrap();
        assert!(serialized.contains("test-host"));
        assert!(serialized.contains("test-detector"));
    }
}
