use std::collections::HashSet;

use innerwarden_core::entities::EntityType;
use innerwarden_core::event::Event;
use innerwarden_core::incident::Incident;

pub(crate) struct AiContextInputs<'a> {
    pub(crate) recent_events: Vec<&'a Event>,
    pub(crate) related_incidents: Vec<&'a Incident>,
}

/// Build AI context inputs for one incident.
/// Keeps context selection logic localized and out of `process_incidents`.
pub(crate) fn build_ai_context_inputs<'a>(
    incident: &Incident,
    all_events: &'a [Event],
    related_incidents: &'a [Incident],
    context_events: usize,
) -> AiContextInputs<'a> {
    let entity_ips: HashSet<&str> = incident
        .entities
        .iter()
        .filter(|e| e.r#type == EntityType::Ip)
        .map(|e| e.value.as_str())
        .collect();
    let entity_users: HashSet<&str> = incident
        .entities
        .iter()
        .filter(|e| e.r#type == EntityType::User)
        .map(|e| e.value.as_str())
        .collect();

    let recent_events: Vec<&Event> = all_events
        .iter()
        .filter(|ev| {
            ev.entities.iter().any(|e| {
                (e.r#type == EntityType::Ip && entity_ips.contains(e.value.as_str()))
                    || (e.r#type == EntityType::User && entity_users.contains(e.value.as_str()))
            })
        })
        .rev()
        .take(context_events)
        .collect();
    let related_incidents: Vec<&Incident> = related_incidents.iter().collect();

    AiContextInputs {
        recent_events,
        related_incidents,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use innerwarden_core::entities::EntityRef;
    use innerwarden_core::event::Severity;

    #[test]
    fn test_build_ai_context_filters_by_entities() {
        let incident = Incident {
            ts: chrono::Utc::now(),
            host: "test".into(),
            incident_id: "inc1".into(),
            severity: Severity::Medium,
            title: "Test".into(),
            summary: "Test".into(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip("10.0.0.1"), EntityRef::user("admin")],
        };

        let ev_matching_ip = Event {
            ts: chrono::Utc::now(),
            host: "test".into(),
            source: "sys".into(),
            kind: "k1".into(),
            severity: Severity::Low,
            summary: "s".into(),
            details: serde_json::json!({}),
            tags: vec![],
            entities: vec![EntityRef::ip("10.0.0.1")],
        };

        let ev_matching_user = Event {
            ts: chrono::Utc::now(),
            host: "test".into(),
            source: "sys".into(),
            kind: "k2".into(),
            severity: Severity::Low,
            summary: "s".into(),
            details: serde_json::json!({}),
            tags: vec![],
            entities: vec![EntityRef::user("admin")],
        };

        let ev_no_match = Event {
            ts: chrono::Utc::now(),
            host: "test".into(),
            source: "sys".into(),
            kind: "k3".into(),
            severity: Severity::Low,
            summary: "s".into(),
            details: serde_json::json!({}),
            tags: vec![],
            entities: vec![EntityRef::ip("192.168.1.1")],
        };

        let events = vec![
            ev_no_match.clone(),
            ev_matching_user.clone(),
            ev_matching_ip.clone(),
        ];
        let related = vec![incident.clone()];

        let inputs = build_ai_context_inputs(&incident, &events, &related, 5);
        assert_eq!(inputs.recent_events.len(), 2);
        assert_eq!(inputs.recent_events[0].kind, "k1"); // reversed
        assert_eq!(inputs.recent_events[1].kind, "k2");
        assert_eq!(inputs.related_incidents.len(), 1);
    }
}
