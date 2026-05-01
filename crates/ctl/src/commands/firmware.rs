use anyhow::Result;

// ── SMM (Ring -2) ───────────────────────────────────────────────────────────

pub fn cmd_smm(json: bool) -> Result<()> {
    let report = innerwarden_smm::full_audit();

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    println!("╔══════════════════════════════════════════════╗");
    println!("║  InnerWarden SMM — Firmware Security Audit   ║");
    println!("╚══════════════════════════════════════════════╝");
    println!();
    println!("  Architecture: {:?}", report.arch);
    println!("  Timestamp:    {}", report.ts);
    println!("  Trust Score:  {}", format_trust(report.trust_score));
    println!();

    for check in &report.checks {
        print_check(
            check.status_icon(),
            check.id,
            check.name,
            check.confidence,
            &check.detail,
        );
    }

    // Correlated threats.
    if !report.correlated_threats.is_empty() {
        println!("  \x1b[35;1m══ Correlated Threats ══\x1b[0m");
        println!();
        for threat in &report.correlated_threats {
            let color = correlated_threat_color(threat.confidence);
            println!(
                "  {color}⚡ [{id}] {name} ({conf:.0}% confidence)\x1b[0m",
                id = threat.id,
                name = threat.name,
                conf = threat.confidence * 100.0,
            );
            println!("    {color}{detail}\x1b[0m", detail = threat.detail);
            println!("    Evidence:");
            for e in &threat.evidence {
                println!("      → {e}");
            }
            println!();
        }
    }

    // Summary.
    let counts = smm_status_counts(&report.checks);

    println!("  ──────────────────────────────────────────");
    println!(
        "  \x1b[32m{secure} secure\x1b[0m  \
         \x1b[33m{warnings} warnings\x1b[0m  \
         \x1b[31m{critical} critical\x1b[0m  \
         \x1b[90m{unavailable} unavailable\x1b[0m  \
         \x1b[35m{corr} correlated\x1b[0m",
        secure = counts.secure,
        warnings = counts.warnings,
        critical = counts.critical,
        unavailable = counts.unavailable,
        corr = report.correlated_threats.len(),
    );

    if counts.critical > 0 || !report.correlated_threats.is_empty() {
        println!();
        if report.trust_score < 0.1 {
            println!(
                "  \x1b[31;1m⚠ FIRMWARE INTEGRITY COMPROMISED — investigate immediately.\x1b[0m"
            );
        } else if report.trust_score < 0.5 {
            println!(
                "  \x1b[31m⚠ Firmware trust degraded — review correlated threats above.\x1b[0m"
            );
        }
    }

    // Baseline hint.
    let baseline_path = innerwarden_smm::baseline::FirmwareBaseline::default_path();
    if !baseline_path.exists() {
        println!();
        println!("  \x1b[36mTip: run `innerwarden system smm --baseline` to enable drift detection.\x1b[0m");
    }

    Ok(())
}

pub fn cmd_smm_baseline() -> Result<()> {
    let path = innerwarden_smm::baseline::FirmwareBaseline::default_path();
    eprintln!("Capturing firmware baseline...");
    let b = innerwarden_smm::baseline::FirmwareBaseline::capture();
    if let Err(e) = b.save(&path) {
        anyhow::bail!("Failed to save baseline: {e}");
    }
    eprintln!("  Saved to {}", path.display());
    eprintln!("  BIOS: {} {}", b.bios.vendor, b.bios.version);
    eprintln!("  ACPI tables: {}", b.acpi_tables.len());
    eprintln!("  PCR values: {}", b.pcrs.len());
    if let Some(smi) = b.smi_count {
        eprintln!("  SMI count: {smi}");
    }
    eprintln!();
    eprintln!("  Re-run `innerwarden system smm` to audit against this baseline.");
    Ok(())
}

pub fn cmd_smm_drift() -> Result<()> {
    let path = innerwarden_smm::baseline::FirmwareBaseline::default_path();
    let Ok(b) = innerwarden_smm::baseline::FirmwareBaseline::load(&path) else {
        anyhow::bail!("No baseline found. Run `innerwarden system smm --baseline` first.");
    };

    let drift = innerwarden_smm::baseline::detect_drift(&b);
    println!("Drift report (baseline from {})", drift.baseline_date);
    println!();

    if drift.drifts.is_empty() {
        println!("  No changes detected since baseline.");
        return Ok(());
    }

    for d in &drift.drifts {
        let (icon, color) = drift_severity_icon(d.severity);
        println!(
            "  {color}{icon}\x1b[0m {}: {color}{}\x1b[0m",
            d.component, d.detail
        );
    }

    Ok(())
}

// ── Hypervisor (Ring -1) ────────────────────────────────────────────────────

pub fn cmd_hypervisor(json: bool) -> Result<()> {
    let report = innerwarden_hypervisor::full_audit();

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    println!("╔══════════════════════════════════════════════╗");
    println!("║  InnerWarden Hypervisor — Ring -1 Audit      ║");
    println!("╚══════════════════════════════════════════════╝");
    println!();

    let env_str = hypervisor_environment_label(&report.environment);
    println!("  Environment: {env_str}");
    println!(
        "  VM Score:    {}/100 ({} evidence signals)",
        report.vm_verdict.score, report.vm_verdict.evidence_count
    );
    if let Some(ref brand) = report.vm_verdict.brand {
        println!("  VM Brand:    \x1b[36m{brand}\x1b[0m");
    }
    println!("  Trust Score: {}", format_trust(report.trust_score));
    println!();

    println!("  \x1b[1m── Deep Checks ──\x1b[0m");
    println!();
    for check in &report.checks {
        let (icon, color) = hypervisor_status_icon(check.status);
        let conf = confidence_suffix(check.confidence);
        println!(
            "  {color}{icon}\x1b[0m [{id}] {name}{conf}",
            id = check.id,
            name = check.name
        );
        println!("    {color}{detail}\x1b[0m", detail = check.detail);
        println!();
    }

    // Probe evidence.
    let positive_probes: Vec<_> = report
        .probe_results
        .iter()
        .filter(|p| p.score > 0)
        .collect();
    if !positive_probes.is_empty() {
        println!(
            "  \x1b[1m── VM Evidence ({} signals) ──\x1b[0m",
            positive_probes.len()
        );
        println!();
        for p in &positive_probes {
            let color = probe_score_color(p.score);
            println!(
                "  {color}[{score:>3}] {id}: {detail}\x1b[0m",
                score = p.score,
                id = p.id,
                detail = p.detail,
            );
        }
        println!();
    }

    // Summary.
    let counts = hypervisor_status_counts(&report.checks);

    println!("  ──────────────────────────────────────────");
    println!(
        "  \x1b[32m{secure} secure\x1b[0m  \x1b[33m{warnings} warnings\x1b[0m  \
         \x1b[31m{critical} critical\x1b[0m  \x1b[90m{unavail} unavailable\x1b[0m  \
         \x1b[36m{probes} probes ({evidence} positive)\x1b[0m",
        secure = counts.secure,
        warnings = counts.warnings,
        critical = counts.critical,
        unavail = counts.unavailable,
        probes = report.probe_results.len(),
        evidence = report.vm_verdict.evidence_count,
    );

    Ok(())
}

// ── Helpers ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StatusCounts {
    secure: usize,
    warnings: usize,
    critical: usize,
    unavailable: usize,
}

fn correlated_threat_color(confidence: f64) -> &'static str {
    if confidence >= 0.9 {
        "\x1b[31;1m"
    } else if confidence >= 0.7 {
        "\x1b[31m"
    } else {
        "\x1b[33m"
    }
}

fn drift_severity_icon(
    severity: innerwarden_smm::baseline::DriftSeverity,
) -> (&'static str, &'static str) {
    match severity {
        innerwarden_smm::baseline::DriftSeverity::Info => ("~", "\x1b[36m"),
        innerwarden_smm::baseline::DriftSeverity::Suspicious => ("?", "\x1b[33m"),
        innerwarden_smm::baseline::DriftSeverity::Critical => ("!", "\x1b[31m"),
    }
}

fn probe_score_color(score: u32) -> &'static str {
    if score >= 80 {
        "\x1b[36m"
    } else if score >= 50 {
        "\x1b[33m"
    } else {
        "\x1b[90m"
    }
}

fn smm_status_counts(checks: &[innerwarden_smm::CheckResult]) -> StatusCounts {
    StatusCounts {
        secure: checks
            .iter()
            .filter(|c| c.status == innerwarden_smm::CheckStatus::Secure)
            .count(),
        warnings: checks
            .iter()
            .filter(|c| c.status == innerwarden_smm::CheckStatus::Warning)
            .count(),
        critical: checks
            .iter()
            .filter(|c| c.status == innerwarden_smm::CheckStatus::Critical)
            .count(),
        unavailable: checks
            .iter()
            .filter(|c| c.status == innerwarden_smm::CheckStatus::Unavailable)
            .count(),
    }
}

fn hypervisor_status_counts(checks: &[innerwarden_hypervisor::CheckResult]) -> StatusCounts {
    StatusCounts {
        secure: checks
            .iter()
            .filter(|c| c.status == innerwarden_hypervisor::CheckStatus::Secure)
            .count(),
        warnings: checks
            .iter()
            .filter(|c| c.status == innerwarden_hypervisor::CheckStatus::Warning)
            .count(),
        critical: checks
            .iter()
            .filter(|c| c.status == innerwarden_hypervisor::CheckStatus::Critical)
            .count(),
        unavailable: checks
            .iter()
            .filter(|c| c.status == innerwarden_hypervisor::CheckStatus::Unavailable)
            .count(),
    }
}

trait StatusIcon {
    fn status_icon(&self) -> (&'static str, &'static str);
}

impl StatusIcon for innerwarden_smm::CheckResult {
    fn status_icon(&self) -> (&'static str, &'static str) {
        match self.status {
            innerwarden_smm::CheckStatus::Secure => ("✓", "\x1b[32m"),
            innerwarden_smm::CheckStatus::Warning => ("⚠", "\x1b[33m"),
            innerwarden_smm::CheckStatus::Critical => ("✗", "\x1b[31m"),
            innerwarden_smm::CheckStatus::Unavailable => ("–", "\x1b[90m"),
        }
    }
}

fn hypervisor_environment_label(environment: &innerwarden_hypervisor::Environment) -> String {
    match environment {
        innerwarden_hypervisor::Environment::BareMetal => "\x1b[32mBare Metal\x1b[0m".to_string(),
        innerwarden_hypervisor::Environment::VirtualMachine { hypervisor } => {
            format!("\x1b[36mVirtual Machine ({hypervisor})\x1b[0m")
        }
        innerwarden_hypervisor::Environment::HypervisorHost { vm_count } => {
            format!("\x1b[35mKVM Host ({vm_count} VMs)\x1b[0m")
        }
        innerwarden_hypervisor::Environment::UnknownHypervisor => {
            "\x1b[31;1mUNKNOWN HYPERVISOR\x1b[0m".to_string()
        }
    }
}

fn hypervisor_status_icon(
    status: innerwarden_hypervisor::CheckStatus,
) -> (&'static str, &'static str) {
    match status {
        innerwarden_hypervisor::CheckStatus::Secure => ("✓", "\x1b[32m"),
        innerwarden_hypervisor::CheckStatus::Warning => ("⚠", "\x1b[33m"),
        innerwarden_hypervisor::CheckStatus::Critical => ("✗", "\x1b[31m"),
        innerwarden_hypervisor::CheckStatus::Unavailable => ("–", "\x1b[90m"),
    }
}

fn confidence_suffix(confidence: f64) -> String {
    if confidence > 0.0 {
        format!(" \x1b[90m({:.0}%)\x1b[0m", confidence * 100.0)
    } else {
        String::new()
    }
}

fn print_check((icon, color): (&str, &str), id: &str, name: &str, confidence: f64, detail: &str) {
    let conf = confidence_suffix(confidence);
    println!("  {color}{icon}\x1b[0m [{id}] {name}{conf}");
    println!("    {color}{detail}\x1b[0m");
    println!();
}

fn trust_bucket(pct: u32) -> (&'static str, &'static str) {
    if pct >= 90 {
        ("\x1b[32m", "TRUSTED")
    } else if pct >= 60 {
        ("\x1b[33m", "DEGRADED")
    } else if pct >= 30 {
        ("\x1b[31m", "AT RISK")
    } else {
        ("\x1b[31;1m", "COMPROMISED")
    }
}

fn format_trust(score: f64) -> String {
    let pct = (score * 100.0) as u32;
    let (color, label) = trust_bucket(pct);
    format!("{color}{pct}% — {label}\x1b[0m")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn smm_check(status: innerwarden_smm::CheckStatus) -> innerwarden_smm::CheckResult {
        innerwarden_smm::CheckResult {
            id: "id",
            name: "name",
            status,
            confidence: 0.5,
            detail: "detail".to_string(),
        }
    }

    fn hypervisor_check(
        status: innerwarden_hypervisor::CheckStatus,
    ) -> innerwarden_hypervisor::CheckResult {
        innerwarden_hypervisor::CheckResult {
            id: "id",
            name: "name",
            status,
            confidence: 0.5,
            detail: "detail".to_string(),
        }
    }

    #[test]
    fn cmd_smm_json_smoke_renders_audit_report() {
        cmd_smm(true).unwrap();
    }

    #[test]
    fn cmd_smm_text_smoke_renders_audit_report() {
        cmd_smm(false).unwrap();
    }

    #[test]
    fn cmd_hypervisor_json_smoke_renders_audit_report() {
        cmd_hypervisor(true).unwrap();
    }

    #[test]
    fn cmd_hypervisor_text_smoke_renders_audit_report() {
        cmd_hypervisor(false).unwrap();
    }

    #[test]
    fn smm_status_counts_tallies_every_status_variant() {
        let counts = smm_status_counts(&[
            smm_check(innerwarden_smm::CheckStatus::Secure),
            smm_check(innerwarden_smm::CheckStatus::Warning),
            smm_check(innerwarden_smm::CheckStatus::Warning),
            smm_check(innerwarden_smm::CheckStatus::Critical),
            smm_check(innerwarden_smm::CheckStatus::Unavailable),
        ]);

        assert_eq!(
            counts,
            StatusCounts {
                secure: 1,
                warnings: 2,
                critical: 1,
                unavailable: 1,
            }
        );
    }

    #[test]
    fn hypervisor_status_counts_tallies_every_status_variant() {
        let counts = hypervisor_status_counts(&[
            hypervisor_check(innerwarden_hypervisor::CheckStatus::Secure),
            hypervisor_check(innerwarden_hypervisor::CheckStatus::Secure),
            hypervisor_check(innerwarden_hypervisor::CheckStatus::Warning),
            hypervisor_check(innerwarden_hypervisor::CheckStatus::Critical),
            hypervisor_check(innerwarden_hypervisor::CheckStatus::Unavailable),
        ]);

        assert_eq!(
            counts,
            StatusCounts {
                secure: 2,
                warnings: 1,
                critical: 1,
                unavailable: 1,
            }
        );
    }

    #[test]
    fn correlated_threat_color_uses_confidence_thresholds() {
        assert_eq!(correlated_threat_color(0.95), "\x1b[31;1m");
        assert_eq!(correlated_threat_color(0.70), "\x1b[31m");
        assert_eq!(correlated_threat_color(0.69), "\x1b[33m");
    }

    #[test]
    fn drift_severity_icon_maps_all_severities() {
        assert_eq!(
            drift_severity_icon(innerwarden_smm::baseline::DriftSeverity::Info),
            ("~", "\x1b[36m")
        );
        assert_eq!(
            drift_severity_icon(innerwarden_smm::baseline::DriftSeverity::Suspicious),
            ("?", "\x1b[33m")
        );
        assert_eq!(
            drift_severity_icon(innerwarden_smm::baseline::DriftSeverity::Critical),
            ("!", "\x1b[31m")
        );
    }

    #[test]
    fn probe_score_color_uses_score_thresholds() {
        assert_eq!(probe_score_color(95), "\x1b[36m");
        assert_eq!(probe_score_color(80), "\x1b[36m");
        assert_eq!(probe_score_color(50), "\x1b[33m");
        assert_eq!(probe_score_color(49), "\x1b[90m");
    }

    #[test]
    fn hypervisor_environment_label_formats_all_variants() {
        // Ensures each environment variant maps to the intended operator-facing label text.
        assert!(
            hypervisor_environment_label(&innerwarden_hypervisor::Environment::BareMetal)
                .contains("Bare Metal")
        );
        assert!(hypervisor_environment_label(
            &innerwarden_hypervisor::Environment::VirtualMachine {
                hypervisor: "KVM".to_string(),
            }
        )
        .contains("Virtual Machine (KVM)"));
        assert!(hypervisor_environment_label(
            &innerwarden_hypervisor::Environment::HypervisorHost { vm_count: 4 }
        )
        .contains("KVM Host (4 VMs)"));
        assert!(hypervisor_environment_label(
            &innerwarden_hypervisor::Environment::UnknownHypervisor
        )
        .contains("UNKNOWN HYPERVISOR"));
    }

    #[test]
    fn hypervisor_status_icon_maps_each_status() {
        // Guards per-status icon/color mapping used when rendering deep check rows.
        assert_eq!(
            hypervisor_status_icon(innerwarden_hypervisor::CheckStatus::Secure),
            ("✓", "\x1b[32m")
        );
        assert_eq!(
            hypervisor_status_icon(innerwarden_hypervisor::CheckStatus::Warning),
            ("⚠", "\x1b[33m")
        );
        assert_eq!(
            hypervisor_status_icon(innerwarden_hypervisor::CheckStatus::Critical),
            ("✗", "\x1b[31m")
        );
        assert_eq!(
            hypervisor_status_icon(innerwarden_hypervisor::CheckStatus::Unavailable),
            ("–", "\x1b[90m")
        );
    }

    #[test]
    fn confidence_suffix_only_renders_for_positive_values() {
        // Verifies confidence rendering is omitted at 0 and shown for positive confidence values.
        assert_eq!(confidence_suffix(0.0), "");
        assert!(confidence_suffix(0.42).contains("42%"));
    }

    #[test]
    fn trust_bucket_classifies_threshold_ranges() {
        // Covers all trust threshold bands so risk labels do not drift during refactors.
        assert_eq!(trust_bucket(95), ("\x1b[32m", "TRUSTED"));
        assert_eq!(trust_bucket(70), ("\x1b[33m", "DEGRADED"));
        assert_eq!(trust_bucket(45), ("\x1b[31m", "AT RISK"));
        assert_eq!(trust_bucket(10), ("\x1b[31;1m", "COMPROMISED"));
    }

    #[test]
    fn format_trust_includes_percentage_and_label() {
        // Ensures final trust string carries both numeric percentage and severity label.
        let trusted = format_trust(0.97);
        assert!(trusted.contains("97%"));
        assert!(trusted.contains("TRUSTED"));

        let compromised = format_trust(0.05);
        assert!(compromised.contains("5%"));
        assert!(compromised.contains("COMPROMISED"));
    }

    #[test]
    fn smm_status_icon_maps_each_status() {
        // Confirms SMM check rendering keeps stable icons for every CheckStatus variant.
        assert_eq!(
            smm_check(innerwarden_smm::CheckStatus::Secure).status_icon(),
            ("✓", "\x1b[32m")
        );
        assert_eq!(
            smm_check(innerwarden_smm::CheckStatus::Warning).status_icon(),
            ("⚠", "\x1b[33m")
        );
        assert_eq!(
            smm_check(innerwarden_smm::CheckStatus::Critical).status_icon(),
            ("✗", "\x1b[31m")
        );
        assert_eq!(
            smm_check(innerwarden_smm::CheckStatus::Unavailable).status_icon(),
            ("–", "\x1b[90m")
        );
    }
}
