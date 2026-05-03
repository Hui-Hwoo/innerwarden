use super::env::HardenEnv;
use super::types::{CheckResult, Finding, Severity};

pub(super) fn evaluate_kernel_sysctl_values(
    aslr: Option<&str>,
    syncookies: Option<&str>,
    ip_forward: Option<&str>,
    accept_redirects: Option<&str>,
    accept_source_route: Option<&str>,
    category: &'static str,
) -> (Vec<String>, Vec<Finding>) {
    let mut passed = Vec::new();
    let mut findings = Vec::new();

    match aslr {
        Some("2") => passed.push("ASLR fully enabled".into()),
        _ => findings.push(Finding {
            category,
            severity: Severity::High,
            title: "ASLR not fully enabled".into(),
            fix: "Run: sudo sysctl -w kernel.randomize_va_space=2".into(),
        }),
    }

    match syncookies {
        Some("1") => passed.push("SYN cookies enabled".into()),
        _ => findings.push(Finding {
            category,
            severity: Severity::Medium,
            title: "SYN cookies not enabled (SYN flood risk)".into(),
            fix: "Run: sudo sysctl -w net.ipv4.tcp_syncookies=1".into(),
        }),
    }

    match ip_forward {
        Some("0") => passed.push("IP forwarding disabled".into()),
        Some("1") => findings.push(Finding {
            category,
            severity: Severity::Low,
            title: "IP forwarding is enabled".into(),
            fix: "If not needed: sudo sysctl -w net.ipv4.ip_forward=0".into(),
        }),
        _ => {}
    }

    match accept_redirects {
        Some("0") => passed.push("ICMP redirects rejected".into()),
        _ => findings.push(Finding {
            category,
            severity: Severity::Medium,
            title: "ICMP redirects accepted (MITM risk)".into(),
            fix: "Run: sudo sysctl -w net.ipv4.conf.all.accept_redirects=0".into(),
        }),
    }

    match accept_source_route {
        Some("0") => passed.push("Source routing disabled".into()),
        _ => findings.push(Finding {
            category,
            severity: Severity::Medium,
            title: "Source routing accepted".into(),
            fix: "Run: sudo sysctl -w net.ipv4.conf.all.accept_source_route=0".into(),
        }),
    }

    (passed, findings)
}

pub(super) fn check_kernel(env: &impl HardenEnv) -> CheckResult {
    let cat = "Kernel";

    let read_sysctl =
        |path: &str| -> Option<String> { env.read_to_string(path).map(|s| s.trim().to_string()) };

    let (passed, findings) = evaluate_kernel_sysctl_values(
        read_sysctl("/proc/sys/kernel/randomize_va_space").as_deref(),
        read_sysctl("/proc/sys/net/ipv4/tcp_syncookies").as_deref(),
        read_sysctl("/proc/sys/net/ipv4/ip_forward").as_deref(),
        read_sysctl("/proc/sys/net/ipv4/conf/all/accept_redirects").as_deref(),
        read_sysctl("/proc/sys/net/ipv4/conf/all/accept_source_route").as_deref(),
        cat,
    );

    CheckResult {
        category: cat,
        passed,
        findings,
    }
}
