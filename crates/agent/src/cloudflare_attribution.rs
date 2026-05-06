//! Wave 9 (AUDIT-WAVE9-CF-ATTRIBUTION, 2026-05-05): rewrite the
//! event's `src_ip` to the real client when the socket peer is a
//! Cloudflare edge.
//!
//! ## The problem this fixes
//!
//! Pre-Wave-9 every HTTP request proxied through Cloudflare arrived
//! at the sensor with the CF edge IP as `src_ip` (because that's the
//! actual TCP peer). One scanner hitting our site through CF would
//! produce N events with N different `src_ip`s — one per CF edge in
//! the load-balancer rotation. The agent then:
//!
//! * created N attacker journeys (Threats tab "Needs your attention"
//!   showed 32 IPs for ONE scanner on 2026-05-05),
//! * issued N block decisions (Wave 10b made these visible: site
//!   showed 103 blocked IPs while only 17 unique sources),
//! * placed N CF datacenter pins on the public attack map.
//!
//! The same scanner via CF produces:
//!
//! ```text
//!   src_ip            CF-Connecting-IP   real-client?
//!   172.71.103.154    203.0.113.42       <-- the actual attacker
//!   172.71.95.52      203.0.113.42       <-- same attacker
//!   141.101.76.109    203.0.113.42       <-- same attacker
//!   ... (N edge IPs, all same client)
//! ```
//!
//! Wave 9 collapses these N events to a single attacker (203.0.113.42)
//! by rewriting `src_ip` at ingest time when:
//! 1. The socket peer (`src_ip` as received) is a Cloudflare edge IP, AND
//! 2. The event's `details.cf_connecting_ip` is set to a parseable IP.
//!
//! ## Defence: spoofed-header attack
//!
//! `CF-Connecting-IP` is a plain HTTP header — anyone can set it. An
//! attacker connecting **directly** (not through CF) could send
//! `CF-Connecting-IP: 8.8.8.8` to misattribute their traffic. The
//! defence is the socket-peer-must-be-CF gate: we only honour the
//! header when the TCP connection came from a CF edge IP.
//! [`crate::cloud_safelist::is_cloudflare_edge_ip`] is the trust
//! anchor.
//!
//! ## What the rewrite preserves
//!
//! Per the operator's hard rule on number consistency, the original
//! edge IP is NOT discarded — it lands in `details.cdn_edge_ip` for
//! forensic / audit use. `decisions-*.jsonl` and the JSONL incident
//! file therefore retain both the resolved client IP (`src_ip`) and
//! the edge IP that delivered the request (`cdn_edge_ip`), so an
//! analyst can still ask "which CF edge served this request?" after
//! the fact.

use serde_json::Value;

use innerwarden_core::entities::EntityType;
use innerwarden_core::event::Event;

use crate::cloud_safelist::is_cloudflare_edge_ip;

/// Attempt to resolve the real client IP behind a Cloudflare edge.
///
/// Returns `Some(real_client_ip)` only when ALL of the following hold:
///
/// 1. `socket_ip` parses as a valid IP, AND
/// 2. `socket_ip` is a Cloudflare edge per
///    [`is_cloudflare_edge_ip`] (the trust gate), AND
/// 3. `details["cf_connecting_ip"]` is a non-empty string that
///    parses as a valid IP.
///
/// Returns `None` (no rewrite) on any other shape — fail-closed so a
/// malformed event never ends up attributed to an attacker-controlled
/// header value.
///
/// Pinned by `cloudflare_attribution::tests::*`.
pub fn resolve_real_client_ip(socket_ip: &str, details: &Value) -> Option<String> {
    if !is_cloudflare_edge_ip(socket_ip) {
        return None;
    }
    let cf = details.get("cf_connecting_ip")?.as_str()?;
    let cf = cf.trim();
    if cf.is_empty() {
        return None;
    }
    // Parse to validate; reject `not-an-ip` shapes that an attacker
    // controlling the header could set to confuse downstream geo
    // lookups / block decisions.
    let _: std::net::IpAddr = cf.parse().ok()?;
    Some(cf.to_string())
}

/// Apply the resolution to an Event's `details` map in-place,
/// returning the resolved client IP if the rewrite happened.
///
/// On rewrite:
/// * `details["src_ip"]` is set to the resolved client IP, AND
/// * `details["cdn_edge_ip"]` is set to the original socket IP for
///   forensic preservation, AND
/// * the function returns `Some(client_ip)` so the caller can also
///   update the event's top-level `entities` (e.g. the
///   `EntityRef::ip` that drives the KG node creation).
///
/// On no-rewrite the function returns `None` and `details` is
/// untouched.
pub fn apply_resolution(details: &mut Value) -> Option<String> {
    let socket_ip = details.get("src_ip")?.as_str()?.to_string();
    let resolved = resolve_real_client_ip(&socket_ip, details)?;
    if let Value::Object(map) = details {
        map.insert("src_ip".to_string(), Value::String(resolved.clone()));
        map.insert("cdn_edge_ip".to_string(), Value::String(socket_ip));
    }
    Some(resolved)
}

/// Wave 9 production hook: rewrite a slice of `Event`s in place,
/// resolving the real client IP for each event whose socket peer is
/// a Cloudflare edge.
///
/// For each event with a recognised CF edge in `details["src_ip"]`
/// AND a parseable `details["cf_connecting_ip"]`:
/// * `details["src_ip"]` flips to the resolved client IP, AND
/// * `details["cdn_edge_ip"]` is set to the original edge IP, AND
/// * any IP entities in `event.entities` whose value matches the
///   pre-rewrite edge IP are updated to the resolved client IP.
///
/// Returns the count of events that were rewritten — useful for
/// telemetry and the production logger.
///
/// Called from `slow_loop::tick` on the freshly-loaded events
/// slice, BEFORE telemetry / narrative / KG / correlation / baseline
/// consume them. That ordering means every downstream surface
/// (Threats tab, Intel, attacker-profiles, dashboard live-feed,
/// site live-feed, etc.) sees the resolved attribution.
pub fn rewrite_events_for_cloudflare(events: &mut [Event]) -> usize {
    let mut rewrites = 0usize;
    for event in events.iter_mut() {
        // Capture original src_ip BEFORE the rewrite mutates details.
        let original_socket_ip = event
            .details
            .get("src_ip")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        if let Some(resolved) = apply_resolution(&mut event.details) {
            rewrites += 1;
            // Also rewrite IP entities pointing at the original
            // socket peer. Other entities (User, Container, etc.)
            // are left alone — the rewrite is an IP-attribution
            // change, not a wholesale entity overwrite.
            if let Some(ref edge_ip) = original_socket_ip {
                for entity in event.entities.iter_mut() {
                    if entity.r#type == EntityType::Ip && entity.value == *edge_ip {
                        entity.value = resolved.clone();
                    }
                }
            }
        }
    }
    rewrites
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Wave 9 anchor: 32 events from a single scanner via 32 CF edge
    /// IPs collapse to ONE resolved client IP. This is the headline
    /// shape the operator hit on 2026-05-05.
    #[test]
    fn wave9_thirty_two_cf_edges_resolve_to_one_real_client() {
        // Real CF edge IPs from the 2026-05-05 prod incident.
        let cf_edges = [
            "172.71.103.154",
            "104.23.166.25",
            "104.23.170.61",
            "172.70.46.32",
            "141.101.76.109",
            "172.71.99.169",
            "162.159.113.23",
            "104.23.172.18",
        ];
        // Initialize the agent's CF range cache.
        crate::cloud_safelist::init();

        let mut resolved_set = std::collections::HashSet::new();
        for edge in cf_edges {
            let mut details = json!({
                "src_ip": edge,
                "cf_connecting_ip": "203.0.113.42",
                "x_forwarded_for": "203.0.113.42",
            });
            let resolved = apply_resolution(&mut details).expect("CF edge with header rewrites");
            resolved_set.insert(resolved);
            // Edge IP preserved for forensic.
            assert_eq!(
                details.get("cdn_edge_ip").and_then(|v| v.as_str()),
                Some(edge),
                "edge IP must be retained in details.cdn_edge_ip"
            );
            // src_ip rewritten to client.
            assert_eq!(
                details.get("src_ip").and_then(|v| v.as_str()),
                Some("203.0.113.42")
            );
        }
        assert_eq!(
            resolved_set.len(),
            1,
            "all CF edges with the same CF-Connecting-IP must resolve to ONE client"
        );
    }

    /// Wave 9 anchor: a non-CF socket peer that sets
    /// `CF-Connecting-IP` to attempt spoofing is REJECTED. The
    /// header is untrusted from anyone but a real CF edge.
    #[test]
    fn wave9_non_cf_peer_with_spoofed_header_is_rejected() {
        crate::cloud_safelist::init();
        // 8.8.8.8 is Google DNS — definitely NOT a CF edge.
        let mut details = json!({
            "src_ip": "8.8.8.8",
            "cf_connecting_ip": "127.0.0.1",
        });
        let result = apply_resolution(&mut details);
        assert!(
            result.is_none(),
            "spoofed CF-Connecting-IP from non-CF peer must NOT trigger rewrite"
        );
        // src_ip untouched.
        assert_eq!(
            details.get("src_ip").and_then(|v| v.as_str()),
            Some("8.8.8.8")
        );
        // No phantom cdn_edge_ip created.
        assert!(details.get("cdn_edge_ip").is_none());
    }

    /// Wave 9 anchor: CF socket peer with NO header → no rewrite.
    /// A CF edge that didn't pass `CF-Connecting-IP` (rare but
    /// possible on health checks etc.) must keep its CF edge IP as
    /// the attribution; falsifying via XFF would be wrong here.
    #[test]
    fn wave9_cf_peer_without_header_is_not_rewritten() {
        crate::cloud_safelist::init();
        let mut details = json!({
            "src_ip": "172.71.103.154",  // CF edge
            "cf_connecting_ip": "",      // empty
            "x_forwarded_for": "",
        });
        assert!(apply_resolution(&mut details).is_none());
        assert_eq!(
            details.get("src_ip").and_then(|v| v.as_str()),
            Some("172.71.103.154")
        );
    }

    /// Wave 9 anchor: malformed `CF-Connecting-IP` (not a valid IP)
    /// is rejected. An attacker who somehow got onto a CF edge
    /// peer cannot inject `cf_connecting_ip: "../etc/passwd"` to
    /// break downstream geo/block logic.
    #[test]
    fn wave9_malformed_cf_header_is_rejected() {
        crate::cloud_safelist::init();
        let mut details = json!({
            "src_ip": "172.71.103.154",  // CF edge
            "cf_connecting_ip": "not-an-ip",
        });
        assert!(apply_resolution(&mut details).is_none());
        // Not even a partial rewrite.
        assert_eq!(
            details.get("src_ip").and_then(|v| v.as_str()),
            Some("172.71.103.154")
        );
        assert!(details.get("cdn_edge_ip").is_none());
    }

    /// Wave 9 anchor: missing `src_ip` field on details (defensive
    /// — should never happen in production but the function must
    /// not panic).
    #[test]
    fn wave9_missing_src_ip_does_not_panic() {
        crate::cloud_safelist::init();
        let mut details = json!({
            "cf_connecting_ip": "203.0.113.42",
        });
        assert!(apply_resolution(&mut details).is_none());
    }

    /// Wave 9 anchor: end-to-end Event-level rewrite. A batch of
    /// events from CF edges with a shared CF-Connecting-IP collapses
    /// to a single attacker — both in `details.src_ip` AND in
    /// `event.entities` (the EntityRef::ip that drives KG node
    /// creation). Pre-Wave-9 the entities array was the source of
    /// truth for the dashboard's "32 distinct attackers" rendering;
    /// rewriting only details would have left the entities stale.
    #[test]
    fn wave9_rewrite_events_for_cloudflare_collapses_entities_too() {
        crate::cloud_safelist::init();
        use innerwarden_core::entities::EntityRef;
        use innerwarden_core::event::Severity;

        let mut events: Vec<Event> = ["172.71.103.154", "104.23.166.25", "141.101.76.109"]
            .iter()
            .map(|edge| Event {
                ts: chrono::Utc::now(),
                host: "h".into(),
                source: "http_capture".into(),
                kind: "http.request".into(),
                severity: Severity::Info,
                summary: "s".into(),
                details: serde_json::json!({
                    "src_ip": *edge,
                    "cf_connecting_ip": "203.0.113.42",
                    "method": "GET",
                    "path": "/",
                }),
                tags: vec![],
                entities: vec![EntityRef::ip(*edge)],
            })
            .collect();

        let n = rewrite_events_for_cloudflare(&mut events);
        assert_eq!(n, 3, "all 3 CF-edge events must rewrite");

        // Every event's IP entity now points at the real client.
        let mut unique_entity_ips = std::collections::HashSet::new();
        for ev in &events {
            assert_eq!(
                ev.details.get("src_ip").and_then(|v| v.as_str()),
                Some("203.0.113.42"),
                "details.src_ip must be the resolved client"
            );
            for ent in &ev.entities {
                if ent.r#type == EntityType::Ip {
                    unique_entity_ips.insert(ent.value.clone());
                }
            }
        }
        assert_eq!(
            unique_entity_ips.len(),
            1,
            "all entity IPs must collapse to ONE — pre-Wave-9 there were 3"
        );
        assert!(unique_entity_ips.contains("203.0.113.42"));
    }

    /// Wave 9 anchor: events from non-CF peers in the SAME batch
    /// pass through untouched. Mixed-batch invariant — CF rewrite
    /// must not affect non-CF events.
    #[test]
    fn wave9_rewrite_events_does_not_touch_non_cf_events() {
        crate::cloud_safelist::init();
        use innerwarden_core::entities::EntityRef;
        use innerwarden_core::event::Severity;

        let mut events = vec![
            Event {
                ts: chrono::Utc::now(),
                host: "h".into(),
                source: "http_capture".into(),
                kind: "http.request".into(),
                severity: Severity::Info,
                summary: "s".into(),
                details: serde_json::json!({
                    "src_ip": "172.71.103.154", // CF
                    "cf_connecting_ip": "203.0.113.42",
                }),
                tags: vec![],
                entities: vec![EntityRef::ip("172.71.103.154")],
            },
            Event {
                ts: chrono::Utc::now(),
                host: "h".into(),
                source: "http_capture".into(),
                kind: "http.request".into(),
                severity: Severity::Info,
                summary: "s".into(),
                details: serde_json::json!({
                    "src_ip": "8.8.8.8", // not CF
                    "cf_connecting_ip": "spoofed",
                }),
                tags: vec![],
                entities: vec![EntityRef::ip("8.8.8.8")],
            },
        ];

        assert_eq!(rewrite_events_for_cloudflare(&mut events), 1);
        // CF event rewritten.
        assert_eq!(
            events[0].details.get("src_ip").and_then(|v| v.as_str()),
            Some("203.0.113.42")
        );
        assert_eq!(events[0].entities[0].value, "203.0.113.42");
        // Non-CF event untouched.
        assert_eq!(
            events[1].details.get("src_ip").and_then(|v| v.as_str()),
            Some("8.8.8.8")
        );
        assert_eq!(events[1].entities[0].value, "8.8.8.8");
    }

    /// Wave 9 anchor: every CF CIDR range is recognised. Walks a
    /// representative IP from each published CF /XX block and asserts
    /// it classifies as a CF edge.
    #[test]
    fn wave9_recognises_every_cloudflare_cidr_range() {
        crate::cloud_safelist::init();
        // One IP from each currently-published CF range. If CF
        // publishes a new range, the constant in `cloud_safelist.rs`
        // is the canonical source; updating it here in lockstep is
        // the contract this test enforces.
        let representative_ips = [
            "173.245.48.1",
            "103.21.244.1",
            "103.22.200.1",
            "103.31.4.1",
            "141.101.64.1",
            "108.162.192.1",
            "190.93.240.1",
            "188.114.96.1",
            "197.234.240.1",
            "198.41.128.1",
            "162.158.0.1",
            "104.16.0.1",
            "104.24.0.1",
            "172.64.0.1",
        ];
        for ip in representative_ips {
            assert!(
                is_cloudflare_edge_ip(ip),
                "CF edge IP {ip} must be recognised by the trust gate"
            );
        }
    }

    /// Wave 9 anchor: random non-CF IPs are NOT classified as CF
    /// edges. Anti-regression for accidentally widening the gate
    /// to AWS / Azure / etc.
    #[test]
    fn wave9_rejects_aws_azure_oracle_as_cf_edges() {
        crate::cloud_safelist::init();
        for ip in [
            "8.8.8.8",         // Google DNS
            "1.1.1.1",         // Cloudflare DNS — NOT a CF EDGE PROXY (different range)
            "52.84.150.39",    // AWS CloudFront
            "20.81.1.1",       // Azure
            "130.162.171.105", // Oracle (our own server)
            "127.0.0.1",       // loopback
        ] {
            assert!(
                !is_cloudflare_edge_ip(ip),
                "{ip} must NOT be classified as a CF edge"
            );
        }
    }
}
