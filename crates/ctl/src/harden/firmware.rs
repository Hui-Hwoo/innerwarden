use super::env::HardenEnv;
use super::types::{CheckResult, Finding, Severity};

pub(super) fn check_firmware(env: &impl HardenEnv) -> CheckResult {
    let cat = "Firmware & Boot";
    let mut passed = Vec::new();
    let mut findings = Vec::new();

    // Secure Boot
    let secure_boot_path =
        "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c";
    if env.path_exists("/sys/firmware/efi") {
        if let Some(data) = env.read_bytes(secure_boot_path) {
            if data.last() == Some(&1) {
                passed.push("UEFI Secure Boot is enabled".into());
            } else {
                findings.push(Finding {
                    category: cat,
                    severity: Severity::High,
                    title: "UEFI Secure Boot is disabled".into(),
                    fix: "Enable Secure Boot in BIOS/UEFI settings to prevent boot-level rootkits"
                        .into(),
                });
            }
        } else {
            findings.push(Finding {
                category: cat,
                severity: Severity::Medium,
                title: "UEFI Secure Boot status unreadable".into(),
                fix: "Check BIOS settings - Secure Boot may be disabled or misconfigured".into(),
            });
        }
    } else {
        passed.push("Legacy BIOS (no UEFI - Secure Boot not applicable)".into());
    }

    // Kernel tainted flag
    if let Some(tainted) = env.read_to_string("/proc/sys/kernel/tainted") {
        let val: u64 = tainted.trim().parse().unwrap_or(0);
        if val == 0 {
            passed.push("Kernel is not tainted (no unsigned modules or errors)".into());
        } else {
            let mut reasons = Vec::new();
            if val & 1 != 0 {
                reasons.push("proprietary module");
            }
            if val & 2 != 0 {
                reasons.push("force-loaded module");
            }
            if val & 8 != 0 {
                reasons.push("force-unloaded module");
            }
            if val & 128 != 0 {
                reasons.push("kernel OOPS");
            }
            if val & 256 != 0 {
                reasons.push("ACPI table overridden");
            }
            if val & 4096 != 0 {
                reasons.push("out-of-tree module");
            }
            if val & 8192 != 0 {
                reasons.push("unsigned module");
            }
            let severity = if val & (8192 | 128 | 256) != 0 {
                Severity::High
            } else {
                Severity::Medium
            };
            findings.push(Finding {
                category: cat,
                severity,
                title: format!("Kernel is tainted (flags={val}): {}", reasons.join(", ")),
                fix: "Investigate tainted kernel - unsigned or out-of-tree modules detected. Run: cat /proc/sys/kernel/tainted".into(),
            });
        }
    }

    // TPM presence
    if env.path_exists("/dev/tpm0") || env.path_exists("/dev/tpmrm0") {
        passed.push("TPM device present (/dev/tpm0 or /dev/tpmrm0)".into());
    } else if env.path_exists("/sys/firmware/efi") {
        findings.push(Finding {
            category: cat,
            severity: Severity::Low,
            title: "No TPM device detected".into(),
            fix: "TPM provides hardware-backed attestation. Enable in BIOS if available.".into(),
        });
    }

    // Boot loader integrity
    if let Some(writable) = env.command_stdout("find", &["/boot", "-perm", "-o+w", "-type", "f"]) {
        let count = writable.trim().lines().filter(|l| !l.is_empty()).count();
        if count == 0 {
            passed.push("No world-writable files in /boot".into());
        } else {
            findings.push(Finding {
                category: cat,
                severity: Severity::Critical,
                title: format!("{count} world-writable file(s) in /boot"),
                fix: "Fix permissions: sudo chmod o-w /boot/* - world-writable boot files allow kernel tampering".into(),
            });
        }
    }

    // IOMMU (DMA protection)
    if let Some(cmdline) = env.read_to_string("/proc/cmdline") {
        if cmdline.contains("iommu=")
            || cmdline.contains("intel_iommu=on")
            || cmdline.contains("amd_iommu=on")
        {
            passed.push("IOMMU enabled (DMA attack protection)".into());
        } else {
            findings.push(Finding {
                category: cat,
                severity: Severity::Low,
                title: "IOMMU not enabled in kernel cmdline".into(),
                fix: "Add intel_iommu=on (Intel) or amd_iommu=on (AMD) to kernel cmdline for DMA protection".into(),
            });
        }
    }

    // Kernel lockdown mode
    if let Some(lockdown) = env.read_to_string("/sys/kernel/security/lockdown") {
        let mode = lockdown.trim();
        if mode.contains("[integrity]") || mode.contains("[confidentiality]") {
            passed.push(format!("Kernel lockdown active: {mode}"));
        } else if mode.contains("[none]") {
            findings.push(Finding {
                category: cat,
                severity: Severity::Medium,
                title: "Kernel lockdown is disabled".into(),
                fix: "Enable kernel lockdown: add lockdown=integrity to kernel cmdline".into(),
            });
        }
    }

    CheckResult {
        category: cat,
        passed,
        findings,
    }
}
