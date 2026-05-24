use super::formatting::{escape_html, friendly_detector_name};

/// Format the daily digest message.
/// Simple mode: friendly, non-technical. Technical mode: concise stats.
#[allow(dead_code)]
pub fn format_daily_digest(
    incidents_today: u32,
    blocks_today: u32,
    critical_count: u32,
    high_count: u32,
    top_detector: &str,
    top_count: u32,
    is_simple: bool,
) -> String {
    if is_simple {
        // Spec 044 Phase 1 (2026-05-09): the legacy `100 − critical*20 − high*5` "Health" score
        // clamped to 0 whenever the day saw more than ~5 high-severity incidents — even when
        // every one of those was auto-resolved silently. The score lied about effective host
        // health, so it is removed. Posture-aware severity (Phase 3) replaces the intent.
        let footer = if critical_count == 0 && high_count == 0 {
            "All clear. Nothing needs you."
        } else {
            "Auto-handled \u{2014} review when convenient."
        };

        format!(
            "\u{2600}\u{fe0f} Good morning! Your server in the last 24h:\n\
             \n\
             \u{00a0}\u{00a0}{blocks_today} attacks blocked\n\
             \u{00a0}\u{00a0}{critical_count} critical threats\n\
             \n\
             {footer}"
        )
    } else {
        let date = chrono::Local::now().format("%Y-%m-%d");
        format!(
            "\u{1f4ca} Daily digest ({date}):\n\
             \u{00a0}\u{00a0}Total: {incidents_today} incidents, {blocks_today} blocks\n\
             \u{00a0}\u{00a0}{top_detector}: {top_count}\n\
             \u{00a0}\u{00a0}Critical: {critical_count} | High: {high_count}",
            top_detector = escape_html(top_detector),
        )
    }
}

/// Pipeline digest stats for enriched daily digest.
pub struct PipelineDigestStats {
    pub suppressed_count: u32,
    pub auto_resolved_groups: u32,
    pub needs_review_groups: u32,
    /// Incidents deferred from immediate Telegram (per-detector counts).
    pub deferred: Vec<(String, u32)>,
}

/// Format an enriched daily digest with pipeline grouping stats.
#[allow(clippy::too_many_arguments)]
pub fn format_daily_digest_enriched(
    incidents_today: u32,
    blocks_today: u32,
    critical_count: u32,
    high_count: u32,
    top_detector: &str,
    top_count: u32,
    is_simple: bool,
    pipeline: &PipelineDigestStats,
) -> String {
    // Spec 044 Phase 1 (2026-05-09): "Server health: X/100" line removed. The formula
    // (100 − critical*20 − high*5, clamp 0..100) clamped to 0 whenever the day saw more than
    // ~5 high-severity incidents, even when every one was auto-resolved silently — the same
    // briefing that read "🔴 0/100" listed "✅ 160 threat groups auto-resolved" two lines
    // below it. The score did not credit auto-resolution, did not subtract for hardening
    // posture, and so was anti-informative. Phase 3 of spec 044 introduces posture-aware
    // severity to fix the underlying signal-vs-noise problem; this phase just stops lying.
    if is_simple {
        // Spec 044 Phase 4 (2026-05-09): "real compromises" wording. The
        // counts here are POST-downgrade (see narrative_daily_summary.rs::
        // maybe_write_daily_summary_and_digest, which routes every
        // incident through posture::downgrade::effective_severity before
        // tallying). So a "high" count of 0 with 60 silent SSH
        // bruteforces below means "60 attempts, none would have worked
        // given the host's posture", not "no high-severity detections
        // happened today". The wording reflects what the count means.
        // Header counter rename 2026-05-24: "Blocked N attacks" was
        // operator-misleading because `blocks_today` counts ALL
        // decisions (block + monitor + honeypot + suspend + dismiss
        // + ignore + …), not just blocks. Operators saw the body list
        // "282 SSH brute force attempts blocked / 105 credential
        // stuffing attempts blocked" right under "Blocked 4 attacks"
        // and the arithmetic obviously did not add up. The accurate
        // framing is: this is the number of times the agent reached a
        // decision (which the body then breaks down per detector).
        let mut msg = format!(
            "\u{1f6e1}\u{fe0f} <b>Daily Security Briefing</b>\n\
             \n\
             While you were away, InnerWarden:\n\
             \u{00a0}\u{00a0}\u{2022} Made <b>{blocks_today}</b> autonomous decisions\n\
             \u{00a0}\u{00a0}\u{2022} Analyzed <b>{incidents_today}</b> security events\n\
             \u{00a0}\u{00a0}\u{2022} Detected <b>{critical_count}</b> real compromises, <b>{high_count}</b> high-severity threats (post-posture)"
        );

        // Deferred incident breakdown — the bulk of silent work.
        if !pipeline.deferred.is_empty() {
            msg.push_str("\n\n\u{1f916} <b>Handled silently:</b>");
            for (detector, count) in &pipeline.deferred {
                let label = escape_html(friendly_detector_name(detector));
                msg.push_str(&format!("\n\u{00a0}\u{00a0}\u{2022} {count} {label}"));
            }
        }

        if pipeline.auto_resolved_groups > 0 {
            msg.push_str(&format!(
                "\n\n\u{2705} {} threat groups auto-resolved",
                pipeline.auto_resolved_groups
            ));
        }

        if pipeline.needs_review_groups > 0 {
            msg.push_str(&format!(
                "\n\n\u{26a0}\u{fe0f} <b>{} groups need your review</b>",
                pipeline.needs_review_groups
            ));
        } else if critical_count > 0 || high_count > 0 || !pipeline.deferred.is_empty() {
            // Bug 5 (2026-05-06): the same briefing announced
            // "Detected N critical, M high severity threats" + listed
            // deferred detectors under "Handled silently:" — saying
            // "All clear. Nothing needs you." right after lied to the
            // operator. Operator-honesty hard rule: only emit "All
            // clear" when there is genuinely nothing to acknowledge.
            // Auto-resolved is fine on its own; high+ activity or any
            // deferred entry means the briefing must say so honestly.
            msg.push_str("\n\n\u{2705} Auto-handled \u{2014} review when convenient.");
        } else {
            msg.push_str("\n\n\u{2705} All clear. Nothing needs you.");
        }

        msg
    } else {
        let date = chrono::Local::now().format("%Y-%m-%d");
        let mut msg = format!(
            "\u{1f4ca} <b>Daily Digest</b> ({date})\n\
             \n\
             Incidents: {incidents_today} | Blocks: {blocks_today}\n\
             Critical: {critical_count} | High: {high_count}\n\
             Top: {top_detector} ({top_count})",
            top_detector = escape_html(top_detector),
        );

        if pipeline.suppressed_count > 0 || pipeline.auto_resolved_groups > 0 {
            msg.push_str(&format!(
                "\nPipeline: {} grouped, {} auto-resolved, {} need review",
                pipeline.suppressed_count,
                pipeline.auto_resolved_groups,
                pipeline.needs_review_groups,
            ));
        }

        if !pipeline.deferred.is_empty() {
            msg.push_str("\nDeferred:");
            for (detector, count) in &pipeline.deferred {
                let detector = escape_html(detector);
                msg.push_str(&format!(" {detector}={count}"));
            }
        }

        msg
    }
}

// ---------------------------------------------------------------------------
// Simple /status
// ---------------------------------------------------------------------------

/// Format a simple /status response.
/// Returns the semaphore status message for non-technical users.
pub fn format_simple_status(
    has_critical_last_24h: bool,
    has_high_last_hour: bool,
    has_critical_last_hour: bool,
    uptime_days: u64,
    total_blocked: u64,
    last_threat_ago: &str,
) -> String {
    let (semaphore, status_word) = if has_critical_last_hour {
        ("\u{1f534}", "needs attention") // 🔴
    } else if has_high_last_hour {
        ("\u{1f7e1}", "under watch") // 🟡
    } else {
        ("\u{1f7e2}", "safe") // 🟢
    };

    // Suppress "no critical" label when there are none
    let _ = has_critical_last_24h;

    format!(
        "{semaphore} <b>Server is {status_word}</b>\n\
         \n\
         \u{1f6e1}\u{fe0f} Protected for <b>{uptime_days}</b> days\n\
         \u{1f6ab} <b>{total_blocked}</b> attacks blocked\n\
         \u{23f1}\u{fe0f} Last threat: {last_threat_ago}",
        last_threat_ago = escape_html(last_threat_ago),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_pipeline() -> PipelineDigestStats {
        PipelineDigestStats {
            suppressed_count: 0,
            auto_resolved_groups: 0,
            needs_review_groups: 0,
            deferred: Vec::new(),
        }
    }

    #[test]
    fn format_daily_digest_simple_zero_incidents_is_all_clear() {
        let msg = format_daily_digest(0, 0, 0, 0, "n/a", 0, true);
        assert!(msg.contains("Good morning"));
        assert!(msg.contains("0 attacks blocked"));
        assert!(msg.contains("0 critical threats"));
        assert!(msg.contains("All clear"));
    }

    /// Spec 044 Phase 1 anchor (2026-05-09): the legacy `Health: X/100` line was
    /// removed because the underlying formula (`100 − critical*20 − high*5`, clamped)
    /// reported `🔴 0/100` whenever the day saw more than ~5 high-severity incidents,
    /// even when every one was auto-resolved silently. Pin the absence so a future
    /// "let's add a score back" change forces an explicit conversation rather than
    /// regressing the briefing copy.
    #[test]
    fn format_daily_digest_omits_health_score() {
        let cases = [
            // Zero state.
            format_daily_digest(0, 0, 0, 0, "n/a", 0, true),
            format_daily_digest(0, 0, 0, 0, "n/a", 0, false),
            // The exact production shape the operator hit on 2026-05-09 (1 critical + 61 high
            // → legacy formula clamps to 0).
            format_daily_digest(316, 47, 1, 61, "proto_anomaly", 169, true),
            format_daily_digest(316, 47, 1, 61, "proto_anomaly", 169, false),
        ];
        for msg in &cases {
            assert!(!msg.contains("Health:"), "found Health: in: {msg}");
            assert!(!msg.contains("/100"), "found /100 in: {msg}");
            assert!(
                !msg.contains("\u{1f7e2}"),
                "found 🟢 (health emoji) in: {msg}"
            );
            assert!(
                !msg.contains("\u{1f7e1}"),
                "found 🟡 (health emoji) in: {msg}"
            );
            assert!(
                !msg.contains("\u{1f534}"),
                "found 🔴 (health emoji) in: {msg}"
            );
        }
    }

    #[test]
    fn format_daily_digest_technical_includes_counts_and_top_detector() {
        let msg = format_daily_digest(7, 3, 1, 2, "WAF/cve-2025-1234", 4, false);
        assert!(msg.contains("Daily digest"));
        assert!(msg.contains("Total: 7 incidents, 3 blocks"));
        assert!(msg.contains("WAF/cve-2025-1234: 4"));
        assert!(msg.contains("Critical: 1 | High: 2"));
        // Technical mode does NOT include the simple-mode greeting.
        assert!(!msg.contains("Good morning"));
    }

    #[test]
    fn format_daily_digest_simple_vs_technical_differs() {
        let simple = format_daily_digest(5, 2, 1, 0, "rule_X", 1, true);
        let technical = format_daily_digest(5, 2, 1, 0, "rule_X", 1, false);
        assert_ne!(simple, technical);
        assert!(simple.contains("Good morning"));
        assert!(technical.contains("Daily digest"));
    }

    #[test]
    fn format_daily_digest_technical_html_escapes_top_detector() {
        let msg = format_daily_digest(0, 0, 0, 0, "evil<script>&", 0, false);
        assert!(msg.contains("evil&lt;script&gt;&amp;"));
        assert!(!msg.contains("evil<script>&:"));
    }

    #[test]
    fn format_daily_digest_enriched_zero_state_does_not_panic() {
        let msg = format_daily_digest_enriched(0, 0, 0, 0, "n/a", 0, true, &empty_pipeline());
        // Empty deferred + zero auto-resolved + zero needs-review -> ends with "All clear".
        assert!(msg.contains("Daily Security Briefing"));
        assert!(msg.contains("All clear. Nothing needs you."));
        assert!(!msg.contains("Handled silently:"));
        assert!(!msg.contains("threat groups auto-resolved"));
        assert!(!msg.contains("groups need your review"));
    }

    #[test]
    fn format_daily_digest_enriched_renders_deferred_entries() {
        let pipeline = PipelineDigestStats {
            suppressed_count: 4,
            auto_resolved_groups: 2,
            needs_review_groups: 0,
            deferred: vec![
                ("waf.path_traversal".to_string(), 12),
                ("waf.sql_injection".to_string(), 5),
            ],
        };

        let simple = format_daily_digest_enriched(20, 17, 0, 1, "waf", 12, true, &pipeline);
        assert!(simple.contains("Handled silently:"));
        // friendly_detector_name is exercised here; both counts must appear.
        assert!(simple.contains("12"));
        assert!(simple.contains("5"));
        assert!(simple.contains("2 threat groups auto-resolved"));
        // Bug 5 anchor (2026-05-06): with high_count=1 AND deferred non-empty,
        // the briefing MUST NOT say "All clear" — it must use the honest
        // "Auto-handled" copy instead.
        assert!(!simple.contains("All clear. Nothing needs you."));
        assert!(simple.contains("Auto-handled \u{2014} review when convenient."));

        let technical = format_daily_digest_enriched(20, 17, 0, 1, "waf", 12, false, &pipeline);
        assert!(technical.contains("Daily Digest"));
        assert!(technical.contains("Pipeline: 4 grouped, 2 auto-resolved, 0 need review"));
        assert!(technical.contains("Deferred:"));
        assert!(technical.contains("waf.path_traversal=12"));
        assert!(technical.contains("waf.sql_injection=5"));
    }

    #[test]
    fn format_daily_digest_enriched_simple_renders_needs_review_warning() {
        let pipeline = PipelineDigestStats {
            suppressed_count: 0,
            auto_resolved_groups: 0,
            needs_review_groups: 3,
            deferred: Vec::new(),
        };

        let msg = format_daily_digest_enriched(2, 1, 1, 0, "n/a", 0, true, &pipeline);
        assert!(msg.contains("3 groups need your review"));
        // "All clear" is replaced by the review warning when needs_review_groups > 0.
        assert!(!msg.contains("All clear. Nothing needs you."));
    }

    #[test]
    fn format_daily_digest_enriched_technical_html_escapes_top_detector() {
        let pipeline = empty_pipeline();
        let msg = format_daily_digest_enriched(1, 0, 0, 0, "evil<script>&", 1, false, &pipeline);
        assert!(msg.contains("evil&lt;script&gt;&amp;"));
    }

    /// Bug 5 anchor (2026-05-06 prod observation): operator saw the
    /// briefing emit "Detected 0 critical, 3 high severity threats"
    /// and immediately after "✅ All clear. Nothing needs you." That
    /// contradicted the same paragraph the operator had just read.
    /// The fix gates "All clear" on critical+high+deferred; this test
    /// pins the high_count > 0 branch.
    #[test]
    fn format_daily_digest_enriched_high_count_suppresses_all_clear() {
        let pipeline = empty_pipeline();
        let msg = format_daily_digest_enriched(5, 0, 0, 3, "n/a", 0, true, &pipeline);
        assert!(
            !msg.contains("All clear. Nothing needs you."),
            "high_count > 0 must suppress \"All clear\""
        );
        assert!(
            msg.contains("Auto-handled \u{2014} review when convenient."),
            "high_count > 0 must emit the honest auto-handled copy"
        );
    }

    /// Bug 5 anchor: critical_count > 0 must also suppress "All clear".
    #[test]
    fn format_daily_digest_enriched_critical_count_suppresses_all_clear() {
        let pipeline = empty_pipeline();
        let msg = format_daily_digest_enriched(5, 0, 1, 0, "n/a", 0, true, &pipeline);
        assert!(
            !msg.contains("All clear. Nothing needs you."),
            "critical_count > 0 must suppress \"All clear\""
        );
        assert!(msg.contains("Auto-handled \u{2014} review when convenient."));
    }

    /// Bug 5 anchor: any deferred entry (incident silently routed to
    /// "Handled silently:" list) must suppress "All clear" because the
    /// briefing already announces those detectors as something the
    /// operator can review.
    #[test]
    fn format_daily_digest_enriched_deferred_entry_suppresses_all_clear() {
        let pipeline = PipelineDigestStats {
            suppressed_count: 0,
            auto_resolved_groups: 0,
            needs_review_groups: 0,
            deferred: vec![("crontab_persistence".to_string(), 1)],
        };
        let msg = format_daily_digest_enriched(1, 0, 0, 0, "n/a", 0, true, &pipeline);
        assert!(
            !msg.contains("All clear. Nothing needs you."),
            "non-empty deferred must suppress \"All clear\""
        );
        assert!(msg.contains("Auto-handled \u{2014} review when convenient."));
        assert!(msg.contains("crontab_persistence") || msg.contains("Persistence"));
    }

    /// Bug 5 anchor: positive case — when there is genuinely no
    /// activity (zero counts AND empty deferred AND zero needs-review),
    /// "All clear" is still the right copy.
    #[test]
    fn format_daily_digest_enriched_truly_quiet_day_keeps_all_clear() {
        let pipeline = empty_pipeline();
        let msg = format_daily_digest_enriched(0, 0, 0, 0, "n/a", 0, true, &pipeline);
        assert!(msg.contains("All clear. Nothing needs you."));
        assert!(!msg.contains("Auto-handled"));
    }

    /// Spec 044 Phase 1 anchor (2026-05-09 prod observation): operator received
    /// `🔴 Server health: 0/100` while the same briefing reported `✅ 160 threat
    /// groups auto-resolved` immediately below — the score did not credit
    /// auto-resolution. This test reproduces the exact production input shape
    /// (1 critical + 61 high) plus a couple of representative cases and pins
    /// that the enriched briefing no longer contains the score line.
    #[test]
    fn format_daily_digest_enriched_omits_health_score() {
        let big_pipeline = PipelineDigestStats {
            suppressed_count: 30,
            auto_resolved_groups: 160,
            needs_review_groups: 30,
            deferred: vec![
                ("proto_anomaly".to_string(), 169),
                ("crontab_persistence".to_string(), 2),
            ],
        };
        let cases = [
            // Zero state, simple + technical.
            format_daily_digest_enriched(0, 0, 0, 0, "n/a", 0, true, &empty_pipeline()),
            format_daily_digest_enriched(0, 0, 0, 0, "n/a", 0, false, &empty_pipeline()),
            // The exact prod observation: 316 events, 47 blocks, 1 critical, 61 high — legacy
            // formula clamped to 0/100 with the 🔴 emoji.
            format_daily_digest_enriched(316, 47, 1, 61, "proto_anomaly", 169, true, &big_pipeline),
            format_daily_digest_enriched(
                316,
                47,
                1,
                61,
                "proto_anomaly",
                169,
                false,
                &big_pipeline,
            ),
        ];
        for msg in &cases {
            assert!(
                !msg.contains("Server health"),
                "found 'Server health' in: {msg}"
            );
            assert!(!msg.contains("Health:"), "found 'Health:' in: {msg}");
            assert!(!msg.contains("/100"), "found '/100' in: {msg}");
            assert!(
                !msg.contains("\u{1f7e2}"),
                "found 🟢 (health emoji) in: {msg}"
            );
            assert!(
                !msg.contains("\u{1f7e1}"),
                "found 🟡 (health emoji) in: {msg}"
            );
            assert!(
                !msg.contains("\u{1f534}"),
                "found 🔴 (health emoji) in: {msg}"
            );
        }
    }

    /// Spec 044 Phase 4 anchor (2026-05-09): the `Detected X critical, Y
    /// high severity threats` wording was renamed to "real compromises"
    /// after the Phase 3 downgrade engine landed. The counts are now
    /// post-downgrade — a high count of 0 alongside 60 silent SSH
    /// bruteforces means "60 attempts, none would have worked given
    /// posture", not "no high-severity detections happened today". The
    /// wording must reflect what the count means, otherwise the
    /// briefing is back to lying about what 'high' is. This anchor pins
    /// the new copy so future edits to this template trigger an
    /// explicit conversation.
    #[test]
    fn format_daily_digest_enriched_uses_real_compromises_wording() {
        let pipeline = PipelineDigestStats {
            suppressed_count: 30,
            auto_resolved_groups: 160,
            needs_review_groups: 30,
            deferred: vec![("proto_anomaly".to_string(), 60)],
        };
        let msg = format_daily_digest_enriched(
            316,
            47,
            1,  // critical (post-downgrade)
            61, // high (post-downgrade)
            "proto_anomaly",
            60,
            true,
            &pipeline,
        );
        assert!(
            msg.contains("real compromises"),
            "Phase 4 wording missing in: {msg}"
        );
        assert!(
            msg.contains("post-posture"),
            "Phase 4 hint about post-downgrade meaning missing in: {msg}"
        );
        // The previous "high severity threats" wording is retained
        // (with "high-severity" hyphenated) so the operator still sees
        // the high-count line — the change is the *meaning*, not the
        // disappearance of the high count.
        assert!(msg.contains("61"), "high count must still be visible");
        assert!(msg.contains("1"), "critical count must still be visible");
    }

    #[test]
    fn format_daily_digest_enriched_html_escapes_deferred_detector_names() {
        let pipeline = PipelineDigestStats {
            suppressed_count: 1,
            auto_resolved_groups: 0,
            needs_review_groups: 0,
            deferred: vec![("evil<script>&".to_string(), 2)],
        };

        let simple = format_daily_digest_enriched(2, 1, 0, 0, "safe", 1, true, &pipeline);
        assert!(simple.contains("evil&lt;script&gt;&amp;"));
        assert!(!simple.contains("evil<script>&"));

        let technical = format_daily_digest_enriched(2, 1, 0, 0, "safe", 1, false, &pipeline);
        assert!(technical.contains("evil&lt;script&gt;&amp;=2"));
        assert!(!technical.contains("evil<script>&=2"));
    }

    /// 2026-05-24 anchor: the "Blocked N attacks" header was renamed to
    /// "Made N autonomous decisions" because `blocks_today` counts ALL
    /// decisions (block + monitor + honeypot + suspend + dismiss + ignore
    /// + …), not just blocks. The operator received a briefing where the
    /// header said "Blocked 4 attacks" while the body listed "282 SSH
    /// brute force attempts blocked + 105 credential stuffing blocked
    /// + …" — a flagrant contradiction. Pin the new wording so a future
    /// "let's tighten this copy" PR cannot quietly revert to the
    /// misleading label.
    #[test]
    fn enriched_header_uses_autonomous_decisions_wording() {
        let pipeline = empty_pipeline();
        let msg = format_daily_digest_enriched(50, 7, 1, 2, "ssh_bruteforce", 5, true, &pipeline);
        assert!(
            msg.contains("Made <b>7</b> autonomous decisions"),
            "expected new 'Made N autonomous decisions' wording in: {msg}"
        );
        assert!(
            !msg.contains("Blocked <b>7</b> attacks"),
            "must not regress to misleading 'Blocked N attacks' label"
        );
    }
}
