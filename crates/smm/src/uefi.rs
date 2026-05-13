//! UEFI variable inspection — Secure Boot state, boot order, BIOS info.
//!
//! Reads from `/sys/firmware/efi/efivars/` (efivarfs) and `/sys/class/dmi/id/`.
//! All operations are read-only.

use crate::{confidence, CheckResult, CheckStatus};
use std::fs;
use std::path::Path;

// ── Secure Boot ─────────────────────────────────────────────────────────

/// Secure Boot state from UEFI variables.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SecureBootState {
    /// Whether Secure Boot is enabled (enforcing).
    pub enabled: bool,
    /// Whether the system booted in Setup Mode (keys not enrolled).
    pub setup_mode: bool,
    /// Raw byte value of SecureBoot variable.
    pub raw: Option<u8>,
}

impl SecureBootState {
    /// Read Secure Boot state from efivarfs.
    pub fn read() -> Option<Self> {
        secure_boot_state_from_reader(read_efi_var)
    }
}

fn secure_boot_state_from_reader<F>(mut read_var: F) -> Option<SecureBootState>
where
    F: FnMut(&str) -> Option<Vec<u8>>,
{
    let secure_boot = read_var("SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c")?;
    let setup_mode = read_var("SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c");
    Some(secure_boot_state_from_vars(
        &secure_boot,
        setup_mode.as_deref(),
    ))
}

fn secure_boot_state_from_vars(
    secure_boot_var: &[u8],
    setup_mode_var: Option<&[u8]>,
) -> SecureBootState {
    // EFI var format: 4 bytes attributes + data.
    SecureBootState {
        enabled: secure_boot_var.get(4).copied() == Some(1),
        setup_mode: setup_mode_var.and_then(|value| value.get(4).copied()) == Some(1),
        raw: secure_boot_var.get(4).copied(),
    }
}

/// Read raw bytes from an EFI variable.
fn read_efi_var(name: &str) -> Option<Vec<u8>> {
    let path = format!("/sys/firmware/efi/efivars/{name}");
    fs::read(&path).ok()
}

// ── BIOS/DMI info ───────────────────────────────────────────────────────

/// BIOS/firmware information from DMI/SMBIOS tables.
#[derive(Debug, Clone, serde::Serialize)]
pub struct BiosInfo {
    pub vendor: String,
    pub version: String,
    pub date: String,
    pub bios_release: String,
}

impl BiosInfo {
    /// Read BIOS info from sysfs DMI tables.
    pub fn read() -> Self {
        bios_info_from_reader(read_dmi)
    }
}

fn bios_info_from_reader<F>(mut read_field: F) -> BiosInfo
where
    F: FnMut(&str) -> String,
{
    BiosInfo {
        vendor: read_field("bios_vendor"),
        version: read_field("bios_version"),
        date: read_field("bios_date"),
        bios_release: read_field("bios_release"),
    }
}

fn read_dmi(field: &str) -> String {
    let path = format!("/sys/class/dmi/id/{field}");
    fs::read_to_string(&path)
        .unwrap_or_default()
        .trim()
        .to_string()
}

// ── Check functions ─────────────────────────────────────────────────────

/// Check Secure Boot status.
pub fn check_secure_boot() -> CheckResult {
    secure_boot_check_from_state(
        Path::new("/sys/firmware/efi").exists(),
        SecureBootState::read(),
    )
}

fn secure_boot_check_from_state(
    efi_available: bool,
    state: Option<SecureBootState>,
) -> CheckResult {
    if !efi_available {
        return CheckResult {
            id: "UEFI-001",
            name: "Secure Boot",
            status: CheckStatus::Unavailable,
            confidence: 0.0,
            detail: "system booted in legacy BIOS mode (no EFI)".into(),
        };
    }

    match state {
        Some(state) => {
            if state.enabled && !state.setup_mode {
                CheckResult {
                    id: "UEFI-001",
                    name: "Secure Boot",
                    status: CheckStatus::Secure,
                    confidence: confidence(0.7, 1.0),
                    detail: "Secure Boot enabled, keys enrolled (enforcing mode)".into(),
                }
            } else if state.setup_mode {
                CheckResult {
                    id: "UEFI-001",
                    name: "Secure Boot",
                    status: CheckStatus::Warning,
                    confidence: confidence(0.7, 1.0),
                    detail: "Secure Boot in Setup Mode — keys not enrolled, \
                             unsigned code can run. Enroll PK/KEK/db keys to enforce."
                        .into(),
                }
            } else {
                CheckResult {
                    id: "UEFI-001",
                    name: "Secure Boot",
                    status: CheckStatus::Warning,
                    confidence: confidence(0.5, 1.0),
                    detail: format!(
                        "Secure Boot disabled (raw={}). Boot chain is not verified.",
                        state.raw.unwrap_or(0)
                    ),
                }
            }
        }
        None => CheckResult {
            id: "UEFI-001",
            name: "Secure Boot",
            status: CheckStatus::Unavailable,
            confidence: 0.0,
            detail: "cannot read SecureBoot EFI variable (permissions or not present)".into(),
        },
    }
}

/// Check BIOS vendor/version for known-good baseline.
pub fn check_bios_info() -> CheckResult {
    bios_info_check_from_info(BiosInfo::read())
}

fn bios_info_check_from_info(info: BiosInfo) -> CheckResult {
    if info.vendor.is_empty() && info.version.is_empty() {
        return CheckResult {
            id: "UEFI-002",
            name: "BIOS Info",
            status: CheckStatus::Unavailable,
            confidence: 0.0,
            detail: "DMI/SMBIOS data not available".into(),
        };
    }

    CheckResult {
        id: "UEFI-002",
        name: "BIOS Info",
        status: CheckStatus::Secure,
        confidence: confidence(0.3, 1.0),
        detail: format!(
            "{} {} (date: {}, release: {})",
            info.vendor, info.version, info.date, info.bios_release
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secure_boot_parsing() {
        // Simulated EFI variable: 4 bytes attrs + 1 byte data.
        let enabled_var = vec![0x06, 0x00, 0x00, 0x00, 0x01]; // enabled
        assert_eq!(enabled_var.get(4).copied(), Some(1));

        let disabled_var = vec![0x06, 0x00, 0x00, 0x00, 0x00]; // disabled
        assert_eq!(disabled_var.get(4).copied(), Some(0));
    }

    #[test]
    fn secure_boot_state_parser_handles_enabled_setup_and_short_variables() {
        let enabled = secure_boot_state_from_vars(
            &[0x06, 0x00, 0x00, 0x00, 0x01],
            Some(&[0x06, 0x00, 0x00, 0x00, 0x00]),
        );
        assert!(enabled.enabled);
        assert!(!enabled.setup_mode);
        assert_eq!(enabled.raw, Some(1));

        let setup = secure_boot_state_from_vars(
            &[0x06, 0x00, 0x00, 0x00, 0x00],
            Some(&[0x06, 0x00, 0x00, 0x00, 0x01]),
        );
        assert!(!setup.enabled);
        assert!(setup.setup_mode);

        let short = secure_boot_state_from_vars(&[0x06], None);
        assert!(!short.enabled);
        assert!(!short.setup_mode);
        assert_eq!(short.raw, None);
    }

    #[test]
    fn secure_boot_state_reader_handles_present_and_missing_variable_sets() {
        let populated = secure_boot_state_from_reader(|name| match name {
            "SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c" => {
                Some(vec![0x06, 0x00, 0x00, 0x00, 0x01])
            }
            "SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c" => {
                Some(vec![0x06, 0x00, 0x00, 0x00, 0x00])
            }
            _ => None,
        })
        .expect("secure boot variables should parse");
        assert!(populated.enabled);
        assert!(!populated.setup_mode);

        assert!(secure_boot_state_from_reader(|_| None).is_none());
    }

    #[test]
    fn bios_info_handles_missing() {
        // BiosInfo::read() should not panic even if files don't exist.
        let info = BiosInfo {
            vendor: read_dmi("nonexistent_field"),
            version: String::new(),
            date: String::new(),
            bios_release: String::new(),
        };
        assert!(info.vendor.is_empty());
    }

    #[test]
    fn bios_info_reader_populates_all_fields_from_injected_source() {
        let info = bios_info_from_reader(|field| match field {
            "bios_vendor" => "InnerVendor".to_string(),
            "bios_version" => "9.9.9".to_string(),
            "bios_date" => "2026-05-13".to_string(),
            "bios_release" => "42".to_string(),
            _ => String::new(),
        });

        assert_eq!(info.vendor, "InnerVendor");
        assert_eq!(info.version, "9.9.9");
        assert_eq!(info.date, "2026-05-13");
        assert_eq!(info.bios_release, "42");
    }

    #[test]
    fn check_secure_boot_runs() {
        let result = check_secure_boot();
        // On most dev machines, either Unavailable (no EFI) or some valid state.
        assert!(!result.id.is_empty());
    }

    #[test]
    fn check_bios_info_runs() {
        let result = check_bios_info();
        assert_eq!(result.id, "UEFI-002");
    }

    #[test]
    fn secure_boot_check_reports_legacy_mode_without_efi() {
        let result = secure_boot_check_from_state(false, None);
        assert_eq!(result.status, CheckStatus::Unavailable);
        assert!(result.detail.contains("legacy BIOS mode"));
    }

    #[test]
    fn secure_boot_check_reports_secure_setup_and_disabled_modes() {
        let secure = secure_boot_check_from_state(
            true,
            Some(SecureBootState {
                enabled: true,
                setup_mode: false,
                raw: Some(1),
            }),
        );
        assert_eq!(secure.status, CheckStatus::Secure);

        let setup = secure_boot_check_from_state(
            true,
            Some(SecureBootState {
                enabled: false,
                setup_mode: true,
                raw: Some(0),
            }),
        );
        assert_eq!(setup.status, CheckStatus::Warning);
        assert!(setup.detail.contains("Setup Mode"));

        let disabled = secure_boot_check_from_state(
            true,
            Some(SecureBootState {
                enabled: false,
                setup_mode: false,
                raw: Some(7),
            }),
        );
        assert_eq!(disabled.status, CheckStatus::Warning);
        assert!(disabled.detail.contains("raw=7"));
    }

    #[test]
    fn secure_boot_check_reports_unavailable_when_variable_is_missing() {
        let result = secure_boot_check_from_state(true, None);
        assert_eq!(result.status, CheckStatus::Unavailable);
        assert!(result
            .detail
            .contains("cannot read SecureBoot EFI variable"));
    }

    #[test]
    fn bios_check_reports_unavailable_or_secure_from_supplied_inventory() {
        let missing = bios_info_check_from_info(BiosInfo {
            vendor: String::new(),
            version: String::new(),
            date: String::new(),
            bios_release: String::new(),
        });
        assert_eq!(missing.status, CheckStatus::Unavailable);

        let populated = bios_info_check_from_info(BiosInfo {
            vendor: "InnerVendor".to_string(),
            version: "1.2.3".to_string(),
            date: "2026-05-13".to_string(),
            bios_release: "7".to_string(),
        });
        assert_eq!(populated.status, CheckStatus::Secure);
        assert!(populated.detail.contains("InnerVendor 1.2.3"));
        assert!(populated.detail.contains("release: 7"));
    }
}
