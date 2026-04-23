//! JSONL backwards-compatibility anchor for `core::Event` and
//! `core::Incident`.
//!
//! Anchors spec 035 PR-A5 + `.claude-local/IMPACT.md` "Sensor → Agent
//! pipeline" invariant: daily JSONL files are append-only and survive
//! across many releases, so a new required field on either wire type
//! would crash the agent on every old line. The two wire types now
//! carry `#[serde(default)]` on every field; these tests enforce that
//! the contract holds and doesn't silently regress.
//!
//! If any future PR adds a field to `core::Event` or `core::Incident`
//! without a `#[serde(default)]` attribute, the `*_parses_omitted_*`
//! tests below fail at the v0 fixture line that omits the new field.
//! That is the entire point: turn a silent runtime crash into a
//! compile-time-adjacent test failure.

use std::path::PathBuf;

use innerwarden_core::entities::EntityType;
use innerwarden_core::event::{Event, Severity};
use innerwarden_core::incident::Incident;

fn testdata(name: &str) -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("testdata");
    p.push(name);
    p
}

fn read_jsonl_lines(name: &str) -> Vec<String> {
    let path = testdata(name);
    let content =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.to_string())
        .collect()
}

// ───────────────────────────────────────────────────────────────────────
// v0 compatibility — parsing legacy records with omitted fields
// ───────────────────────────────────────────────────────────────────────

#[test]
fn event_v0_parses_every_line_and_defaults_omitted_fields() {
    let lines = read_jsonl_lines("event_v0.jsonl");
    assert_eq!(
        lines.len(),
        3,
        "fixture must cover fully-populated, sparse, and missing-severity cases",
    );

    // Line 0: fully populated — no defaults kick in.
    let full: Event = serde_json::from_str(&lines[0]).expect("full-event line parses");
    assert_eq!(full.host, "srv-01");
    assert_eq!(full.source, "auth.log");
    assert_eq!(full.severity, Severity::High);
    assert_eq!(full.tags, vec!["ssh", "brute"]);
    assert_eq!(full.entities.len(), 1);
    assert_eq!(full.entities[0].r#type, EntityType::Ip);

    // Line 1: sparse — details/tags/entities omitted, default to Null/empty.
    let sparse: Event = serde_json::from_str(&lines[1]).expect("sparse-event line parses");
    assert_eq!(sparse.severity, Severity::Low);
    assert!(
        sparse.details.is_null(),
        "omitted `details` must default to JSON Null",
    );
    assert!(sparse.tags.is_empty(), "omitted `tags` must default to []");
    assert!(
        sparse.entities.is_empty(),
        "omitted `entities` must default to []",
    );

    // Line 2: severity omitted — must default to Info, NOT Debug (the
    // first enum variant). See `default_severity` in event.rs.
    let no_sev: Event = serde_json::from_str(&lines[2]).expect("no-severity event line parses");
    assert_eq!(
        no_sev.severity,
        Severity::Info,
        "missing `severity` must default to Info, not Debug — otherwise every \
         legacy record without this field would look like a debug-level event",
    );
}

#[test]
fn incident_v0_parses_every_line_and_defaults_omitted_fields() {
    let lines = read_jsonl_lines("incident_v0.jsonl");
    assert_eq!(
        lines.len(),
        3,
        "fixture must cover fully-populated, sparse, and missing-severity cases",
    );

    // Line 0: fully populated.
    let full: Incident = serde_json::from_str(&lines[0]).expect("full-incident line parses");
    assert_eq!(full.incident_id, "ssh_bruteforce:203.0.113.5:1");
    assert_eq!(full.severity, Severity::Critical);
    assert_eq!(full.recommended_checks.len(), 2);
    assert_eq!(full.entities.len(), 1);

    // Line 1: sparse — evidence/recommended_checks/tags/entities omitted.
    let sparse: Incident = serde_json::from_str(&lines[1]).expect("sparse-incident line parses");
    assert_eq!(sparse.severity, Severity::Medium);
    assert!(
        sparse.evidence.is_null(),
        "omitted `evidence` must default to JSON Null",
    );
    assert!(sparse.recommended_checks.is_empty());
    assert!(sparse.tags.is_empty());
    assert!(sparse.entities.is_empty());

    // Line 2: severity omitted → defaults to Info.
    let no_sev: Incident = serde_json::from_str(&lines[2]).expect("no-severity incident parses");
    assert_eq!(
        no_sev.severity,
        Severity::Info,
        "missing `severity` on Incident must default to Info",
    );
}

// ───────────────────────────────────────────────────────────────────────
// Round-trip: serialize → deserialize is identical
// ───────────────────────────────────────────────────────────────────────
//
// Guards against a typo'd `default = "fn"` pointer that silently
// deserializes the wrong value (e.g., misnaming `default_severity` so
// serde falls back to the enum's first variant). If the round-trip
// equality fails, the most likely cause is a broken default fn or a
// field whose `Default::default()` is not the identity for the value
// being round-tripped.

fn json_value_eq<T: serde::Serialize>(a: &T, b: &T) {
    let va = serde_json::to_value(a).expect("serialize lhs");
    let vb = serde_json::to_value(b).expect("serialize rhs");
    assert_eq!(
        va, vb,
        "round-trip must be byte-identical via serde_json::Value"
    );
}

#[test]
fn event_round_trip_is_stable_across_every_fixture_line() {
    for (idx, line) in read_jsonl_lines("event_v0.jsonl").iter().enumerate() {
        let parsed: Event =
            serde_json::from_str(line).unwrap_or_else(|e| panic!("parse event_v0 line {idx}: {e}"));
        let re_serialized = serde_json::to_string(&parsed)
            .unwrap_or_else(|e| panic!("re-serialize event_v0 line {idx}: {e}"));
        let re_parsed: Event = serde_json::from_str(&re_serialized)
            .unwrap_or_else(|e| panic!("re-parse event_v0 line {idx}: {e}"));
        json_value_eq(&parsed, &re_parsed);
    }
}

#[test]
fn incident_round_trip_is_stable_across_every_fixture_line() {
    for (idx, line) in read_jsonl_lines("incident_v0.jsonl").iter().enumerate() {
        let parsed: Incident = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("parse incident_v0 line {idx}: {e}"));
        let re_serialized = serde_json::to_string(&parsed)
            .unwrap_or_else(|e| panic!("re-serialize incident_v0 line {idx}: {e}"));
        let re_parsed: Incident = serde_json::from_str(&re_serialized)
            .unwrap_or_else(|e| panic!("re-parse incident_v0 line {idx}: {e}"));
        json_value_eq(&parsed, &re_parsed);
    }
}
