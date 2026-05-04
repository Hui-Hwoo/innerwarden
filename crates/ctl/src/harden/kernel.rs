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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evaluate_kernel_sysctl_values_all_secure() {
        let (passed, findings) = evaluate_kernel_sysctl_values(
            Some("2"),
            Some("1"),
            Some("0"),
            Some("0"),
            Some("0"),
            "Kernel",
        );
        assert_eq!(findings.len(), 0);
        assert_eq!(passed.len(), 5);
        assert!(passed.iter().any(|p| p.contains("ASLR fully enabled")));
    }

    #[test]
    fn test_evaluate_kernel_sysctl_values_all_insecure() {
        let (passed, findings) = evaluate_kernel_sysctl_values(
            Some("1"),
            Some("0"),
            Some("1"),
            Some("1"),
            Some("1"),
            "Kernel",
        );
        assert_eq!(passed.len(), 0);
        assert_eq!(findings.len(), 5);
        assert!(findings
            .iter()
            .any(|f| f.title.contains("ASLR not fully enabled")));
        assert!(findings
            .iter()
            .any(|f| f.title.contains("SYN cookies not enabled")));
        assert!(findings
            .iter()
            .any(|f| f.title.contains("IP forwarding is enabled")));
        assert!(findings
            .iter()
            .any(|f| f.title.contains("ICMP redirects accepted")));
        assert!(findings
            .iter()
            .any(|f| f.title.contains("Source routing accepted")));
    }

    #[test]
    fn test_evaluate_kernel_sysctl_values_none() {
        let (passed, findings) =
            evaluate_kernel_sysctl_values(None, None, None, None, None, "Kernel");
        // None means it couldn't be read, which is generally considered insecure or needs fixing
        // ASLR (1), SYN (1), IP forward (0 - not checked if None), ICMP (1), Source routing (1) = 4 findings
        assert_eq!(findings.len(), 4);
        assert_eq!(passed.len(), 0);
    }
}
