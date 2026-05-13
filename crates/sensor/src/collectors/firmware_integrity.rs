//! Firmware & boot integrity collector - detects firmware-level threats.
//!
//! Monitors signals that indicate BIOS/UEFI compromise, bootkit installation,
//! or firmware tampering. Runs periodically (default: every 5 minutes).
//!
//! Detection techniques from:
//!   - Peacock (arxiv:2601.07402, Jan 2025) - UEFI runtime observability
//!   - UEFI Memory Forensics (arxiv:2501.16962, Jan 2025)
//!   - SoK: Security Below the OS (arxiv:2311.03809)
//!   - ESET: BlackLotus, LoJax, MosaicRegressor analysis
//!
//! No hardware dependency - all checks read /sys/, /proc/, /boot/efi/.

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::time::Duration;

use chrono::Utc;
use innerwarden_core::event::{Event, Severity};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tracing::info;

/// EFI System Partition paths to monitor for unauthorized binaries.
const ESP_PATHS: &[&str] = &[
    "/boot/efi/EFI/BOOT",
    "/boot/efi/EFI/ubuntu",
    "/boot/efi/EFI/debian",
    "/boot/efi/EFI/centos",
    "/boot/efi/EFI/fedora",
    "/boot/efi/EFI/Microsoft/Boot",
];

/// UEFI variables that bootkits commonly tamper with.
const WATCHED_EFIVARS: &[&str] = &[
    "SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c",
    "SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c",
    "dbx-d719b2cb-3d3a-4596-a3bc-dad00e67656f",
    "PK-8be4df61-93ca-11d2-aa0d-00e098032b8c",
    "KEK-8be4df61-93ca-11d2-aa0d-00e098032b8c",
];

const ACPI_TABLE_NAMES: &[&str] = &["DSDT", "SSDT", "FACP", "APIC", "MCFG", "HPET"];

pub async fn run(tx: mpsc::Sender<Event>, host: String) {
    // Only run on systems with EFI or /boot
    if !Path::new("/sys/firmware").exists() && !Path::new("/boot").exists() {
        info!("firmware_integrity: no firmware paths found, skipping");
        return;
    }

    info!("firmware_integrity collector starting (5-minute interval)");

    // Build initial baselines
    let mut esp_hashes = scan_esp_hashes();
    let mut efivar_hashes = scan_efivar_hashes();
    let mut dmi_baseline = read_dmi_info();
    let mut kernel_tainted_baseline = read_tainted();
    let mut acpi_hashes = scan_acpi_hashes();

    let hash_count = esp_hashes.len() + efivar_hashes.len() + acpi_hashes.len();
    info!(
        esp = esp_hashes.len(),
        efivars = efivar_hashes.len(),
        acpi = acpi_hashes.len(),
        "firmware_integrity: baseline established ({hash_count} items)"
    );

    let mut interval = tokio::time::interval(Duration::from_secs(300)); // 5 minutes
    interval.tick().await; // skip first immediate tick

    loop {
        interval.tick().await;

        // 1. ESP integrity - detect new/modified .efi binaries
        let new_esp = scan_esp_hashes();
        for (path, hash) in &new_esp {
            match esp_hashes.get(path) {
                None => {
                    // New file appeared - possible bootkit installation
                    let ev = esp_new_binary_event(&host, path, hash);
                    let _ = tx.send(ev).await;
                }
                Some(old_hash) if old_hash != hash => {
                    // File modified - possible bootkit or unauthorized update
                    let ev = esp_modified_event(&host, path, old_hash, hash);
                    let _ = tx.send(ev).await;
                }
                _ => {} // unchanged
            }
        }
        // Detect deleted EFI files (bootkit cleaning up)
        for path in esp_hashes.keys() {
            if !new_esp.contains_key(path) {
                let ev = esp_removed_event(&host, path);
                let _ = tx.send(ev).await;
            }
        }
        esp_hashes = new_esp;

        // 2. UEFI variable monitoring - detect SecureBoot/DBX tampering
        let new_efivars = scan_efivar_hashes();
        for (name, hash) in &new_efivars {
            if let Some(old_hash) = efivar_hashes.get(name) {
                if old_hash != hash {
                    let ev = efivar_changed_event(&host, name, old_hash, hash);
                    let _ = tx.send(ev).await;
                }
            }
        }
        efivar_hashes = new_efivars;

        // 3. ACPI table integrity - detect malicious AML injection
        let new_acpi = scan_acpi_hashes();
        for (table, hash) in &new_acpi {
            if let Some(old_hash) = acpi_hashes.get(table) {
                if old_hash != hash {
                    let ev = acpi_modified_event(&host, table);
                    let _ = tx.send(ev).await;
                }
            }
        }
        acpi_hashes = new_acpi;

        // 4. Firmware version - detect BIOS downgrade/replacement
        let new_dmi = read_dmi_info();
        if !dmi_baseline.is_empty() && new_dmi != dmi_baseline {
            let ev = dmi_changed_event(&host, &dmi_baseline, &new_dmi);
            let _ = tx.send(ev).await;
            dmi_baseline = new_dmi;
        }

        // 5. Kernel tainted flag - detect new taint (unsigned module loaded)
        let new_tainted = read_tainted();
        if new_tainted != kernel_tainted_baseline && new_tainted > kernel_tainted_baseline {
            let added = new_tainted & !kernel_tainted_baseline;
            let ev = kernel_tainted_event(&host, added, new_tainted);
            let _ = tx.send(ev).await;
            kernel_tainted_baseline = new_tainted;
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn sha256_file(path: &Path) -> Option<String> {
    let data = fs::read(path).ok()?;
    let hash = Sha256::digest(&data);
    Some(format!("{hash:x}"))
}

fn scan_esp_hashes() -> HashMap<String, String> {
    let mut hashes = HashMap::new();
    for dir in ESP_PATHS {
        let dir_path = Path::new(dir);
        if !dir_path.exists() {
            continue;
        }
        if let Ok(entries) = fs::read_dir(dir_path) {
            for entry in entries.flatten() {
                let path = entry.path();
                if should_hash_esp_entry(&path) {
                    if let Some(hash) = sha256_file(&path) {
                        hashes.insert(path.display().to_string(), hash);
                    }
                }
            }
        }
    }
    hashes
}

fn scan_efivar_hashes() -> HashMap<String, String> {
    scan_named_hashes(Path::new("/sys/firmware/efi/efivars"), WATCHED_EFIVARS)
}

fn scan_acpi_hashes() -> HashMap<String, String> {
    scan_named_hashes(Path::new("/sys/firmware/acpi/tables"), ACPI_TABLE_NAMES)
}

fn scan_named_hashes(dir: &Path, names: &[&str]) -> HashMap<String, String> {
    let mut hashes = HashMap::new();
    if !dir.exists() {
        return hashes;
    }
    for name in names {
        let path = dir.join(name);
        if let Some(hash) = sha256_file(&path) {
            hashes.insert((*name).to_string(), hash);
        }
    }
    hashes
}

fn read_dmi_info() -> String {
    dmi_info_from_reader(
        &[
            "/sys/firmware/dmi/tables/smbios_entry_point",
            "/sys/class/dmi/id/bios_vendor",
            "/sys/class/dmi/id/bios_version",
            "/sys/class/dmi/id/bios_date",
        ],
        |file| fs::read_to_string(file).ok(),
    )
}

fn dmi_info_from_reader<F>(files: &[&str], mut read_to_string: F) -> String
where
    F: FnMut(&str) -> Option<String>,
{
    let mut info = String::new();
    for file in files {
        if let Some(content) = read_to_string(file) {
            info.push_str(&content.trim().replace('\n', " "));
            info.push('|');
        }
    }
    info
}

fn read_tainted() -> u64 {
    let content = fs::read_to_string("/proc/sys/kernel/tainted").ok();
    tainted_value_from_content(content.as_deref())
}

fn tainted_value_from_content(content: Option<&str>) -> u64 {
    content
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or(0)
}

fn make_event(
    host: &str,
    severity: Severity,
    summary: &str,
    kind: &str,
    details: &[(&str, &str)],
    tags: &[&str],
) -> Event {
    let mut detail_map = serde_json::Map::new();
    for (k, v) in details {
        detail_map.insert(k.to_string(), serde_json::Value::String(v.to_string()));
    }
    Event {
        ts: Utc::now(),
        host: host.to_string(),
        source: "firmware_integrity".to_string(),
        kind: kind.to_string(),
        severity,
        summary: summary.to_string(),
        details: serde_json::Value::Object(detail_map),
        tags: tags.iter().map(|t| t.to_string()).collect(),
        entities: vec![],
    }
}

fn esp_new_binary_event(host: &str, path: &str, hash: &str) -> Event {
    make_event(
        host,
        Severity::Critical,
        &format!("New EFI binary detected: {path}"),
        "firmware.esp_new_binary",
        &[("path", path), ("hash", hash)],
        &["firmware", "bootkit", "esp"],
    )
}

fn esp_modified_event(host: &str, path: &str, old_hash: &str, new_hash: &str) -> Event {
    make_event(
        host,
        Severity::Critical,
        &format!("EFI binary modified: {path}"),
        "firmware.esp_modified",
        &[
            ("path", path),
            ("old_hash", old_hash),
            ("new_hash", new_hash),
        ],
        &["firmware", "bootkit", "esp"],
    )
}

fn esp_removed_event(host: &str, path: &str) -> Event {
    make_event(
        host,
        Severity::High,
        &format!("EFI binary removed: {path}"),
        "firmware.esp_removed",
        &[("path", path)],
        &["firmware", "esp"],
    )
}

fn efivar_changed_event(host: &str, name: &str, old_hash: &str, new_hash: &str) -> Event {
    make_event(
        host,
        classify_efivar_change(name),
        &format!("UEFI variable changed: {name}"),
        "firmware.efivar_changed",
        &[
            ("variable", name),
            ("old_hash", old_hash),
            ("new_hash", new_hash),
        ],
        &["firmware", "uefi", "bootkit"],
    )
}

fn acpi_modified_event(host: &str, table: &str) -> Event {
    make_event(
        host,
        Severity::Critical,
        &format!("ACPI table modified at runtime: {table}"),
        "firmware.acpi_modified",
        &[("table", table)],
        &["firmware", "acpi", "rootkit"],
    )
}

fn dmi_changed_event(host: &str, old: &str, new: &str) -> Event {
    make_event(
        host,
        Severity::Critical,
        "DMI/SMBIOS firmware info changed at runtime",
        "firmware.dmi_changed",
        &[("old", old), ("new", new)],
        &["firmware", "bios"],
    )
}

fn kernel_tainted_event(host: &str, added: u64, total: u64) -> Event {
    let added_string = added.to_string();
    let total_string = total.to_string();
    let reasons = kernel_taint_reasons(added);
    make_event(
        host,
        classify_kernel_taint_severity(added),
        &format!(
            "Kernel tainted flag changed: +{added} ({})",
            reasons.join(", ")
        ),
        "firmware.kernel_tainted",
        &[
            ("flags_added", added_string.as_str()),
            ("total", total_string.as_str()),
        ],
        &["kernel", "tainted", "firmware"],
    )
}

fn should_hash_esp_entry(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|e| e.to_str()),
        Some("efi" | "EFI")
    )
}

fn classify_efivar_change(name: &str) -> Severity {
    if name.starts_with("SecureBoot") || name.starts_with("dbx") {
        Severity::Critical
    } else {
        Severity::High
    }
}

fn kernel_taint_reasons(added: u64) -> Vec<&'static str> {
    let mut reasons = Vec::new();
    if added & 1 != 0 {
        reasons.push("proprietary module");
    }
    if added & 4096 != 0 {
        reasons.push("out-of-tree module");
    }
    if added & 8192 != 0 {
        reasons.push("unsigned module");
    }
    if added & 256 != 0 {
        reasons.push("ACPI table overridden");
    }
    if added & 128 != 0 {
        reasons.push("kernel OOPS");
    }
    reasons
}

fn classify_kernel_taint_severity(added: u64) -> Severity {
    if added & (8192 | 128 | 256) != 0 {
        Severity::Critical
    } else {
        Severity::High
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_hash_esp_entry_accepts_efi_extensions_only() {
        // Validates ESP scanner filtering so only EFI binaries are tracked for integrity drift.
        assert!(should_hash_esp_entry(Path::new(
            "/boot/efi/EFI/BOOT/BOOTX64.EFI"
        )));
        assert!(should_hash_esp_entry(Path::new(
            "/boot/efi/EFI/BOOT/shimx64.efi"
        )));
        assert!(!should_hash_esp_entry(Path::new(
            "/boot/efi/EFI/BOOT/readme.txt"
        )));
    }

    #[test]
    fn classify_efivar_change_elevates_secure_boot_related_variables() {
        // Ensures tampering on high-risk UEFI variables is always classified as critical.
        assert!(matches!(
            classify_efivar_change("SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"),
            Severity::Critical
        ));
        assert!(matches!(
            classify_efivar_change("dbx-d719b2cb-3d3a-4596-a3bc-dad00e67656f"),
            Severity::Critical
        ));
    }

    #[test]
    fn classify_efivar_change_marks_other_watched_variables_as_high() {
        // Covers non-critical UEFI variable branch to preserve existing alert severity.
        assert!(matches!(
            classify_efivar_change("KEK-8be4df61-93ca-11d2-aa0d-00e098032b8c"),
            Severity::High
        ));
    }

    #[test]
    fn kernel_taint_reasons_reports_all_matching_bits() {
        // Guards reason rendering so analysts see complete context for taint-bit changes.
        let reasons = kernel_taint_reasons(1 | 4096 | 128);
        assert!(reasons.contains(&"proprietary module"));
        assert!(reasons.contains(&"out-of-tree module"));
        assert!(reasons.contains(&"kernel OOPS"));
    }

    #[test]
    fn classify_kernel_taint_severity_is_critical_for_high_risk_bits() {
        // Ensures unsigned modules, OOPS, and ACPI override bits stay in critical severity path.
        assert!(matches!(
            classify_kernel_taint_severity(8192),
            Severity::Critical
        ));
        assert!(matches!(
            classify_kernel_taint_severity(128),
            Severity::Critical
        ));
        assert!(matches!(
            classify_kernel_taint_severity(256),
            Severity::Critical
        ));
    }

    #[test]
    fn classify_kernel_taint_severity_is_high_for_low_risk_bits() {
        // Verifies non-critical taint additions retain high severity instead of being over-promoted.
        assert!(matches!(classify_kernel_taint_severity(1), Severity::High));
    }

    #[test]
    fn should_hash_esp_entry_rejects_no_extension() {
        assert!(!should_hash_esp_entry(Path::new(
            "/boot/efi/EFI/BOOT/README"
        )));
    }

    #[test]
    fn kernel_taint_reasons_empty() {
        let reasons = kernel_taint_reasons(0);
        assert!(reasons.is_empty());
    }

    #[test]
    fn make_event_creates_expected_structure() {
        let ev = make_event(
            "test-host",
            Severity::High,
            "summary text",
            "test.kind",
            &[("key", "value")],
            &["tag1"],
        );
        assert_eq!(ev.host, "test-host");
        assert_eq!(ev.severity, Severity::High);
        assert_eq!(ev.summary, "summary text");
        assert_eq!(ev.kind, "test.kind");
        assert_eq!(ev.details["key"].as_str().unwrap(), "value");
        assert_eq!(ev.tags.len(), 1);
        assert_eq!(ev.tags[0], "tag1");
    }

    #[test]
    fn sha256_file_hashes_existing_paths_and_skips_missing_files() {
        let dir = tempfile::TempDir::new().expect("temporary directory should be created");
        let path = dir.path().join("bootx64.efi");
        std::fs::write(&path, b"firmware").expect("fixture should be written");

        let hash = sha256_file(&path).expect("digest should be computed");
        assert_eq!(hash, format!("{:x}", Sha256::digest(b"firmware")));
        assert!(sha256_file(&dir.path().join("missing.efi")).is_none());
    }

    #[test]
    fn esp_and_efivar_event_builders_preserve_detection_context() {
        let created = esp_new_binary_event("sensor-a", "/boot/EFI/new.efi", "abc");
        assert_eq!(created.kind, "firmware.esp_new_binary");
        assert_eq!(created.severity, Severity::Critical);
        assert_eq!(created.details["hash"], "abc");

        let modified = esp_modified_event("sensor-b", "/boot/EFI/shim.efi", "old", "new");
        assert_eq!(modified.kind, "firmware.esp_modified");
        assert_eq!(modified.details["old_hash"], "old");
        assert_eq!(modified.details["new_hash"], "new");

        let removed = esp_removed_event("sensor-c", "/boot/EFI/removed.efi");
        assert_eq!(removed.severity, Severity::High);
        assert_eq!(removed.details["path"], "/boot/EFI/removed.efi");

        let changed = efivar_changed_event(
            "sensor-d",
            "SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c",
            "before",
            "after",
        );
        assert_eq!(changed.kind, "firmware.efivar_changed");
        assert_eq!(changed.severity, Severity::Critical);
        assert_eq!(
            changed.details["variable"],
            "SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
        );
    }

    #[test]
    fn runtime_event_builders_render_firmware_and_taint_changes() {
        let acpi = acpi_modified_event("sensor-a", "DSDT");
        assert_eq!(acpi.kind, "firmware.acpi_modified");
        assert_eq!(acpi.details["table"], "DSDT");

        let dmi = dmi_changed_event("sensor-b", "old-info", "new-info");
        assert_eq!(dmi.kind, "firmware.dmi_changed");
        assert_eq!(dmi.details["old"], "old-info");
        assert_eq!(dmi.details["new"], "new-info");

        let tainted = kernel_tainted_event("sensor-c", 8192 | 256, 8448);
        assert_eq!(tainted.kind, "firmware.kernel_tainted");
        assert_eq!(tainted.severity, Severity::Critical);
        assert_eq!(tainted.details["flags_added"], "8448");
        assert!(tainted.summary.contains("unsigned module"));
        assert!(tainted.summary.contains("ACPI table overridden"));
    }

    #[test]
    fn named_hash_scans_and_tainted_parsing_cover_present_missing_and_invalid_data() {
        let dir = tempfile::TempDir::new().expect("temporary directory should be created");
        std::fs::write(dir.path().join("DSDT"), b"table").expect("table fixture should be written");

        let hashes = scan_named_hashes(dir.path(), &["DSDT", "missing"]);
        assert_eq!(hashes.len(), 1);
        assert_eq!(
            hashes.get("DSDT"),
            Some(&format!("{:x}", Sha256::digest(b"table")))
        );
        assert!(scan_named_hashes(&dir.path().join("absent"), &["DSDT"]).is_empty());

        assert_eq!(tainted_value_from_content(Some("8192\n")), 8192);
        assert_eq!(tainted_value_from_content(Some("invalid")), 0);
        assert_eq!(tainted_value_from_content(None), 0);
    }

    #[test]
    fn dmi_info_composition_normalizes_multiline_fields_and_skips_missing_entries() {
        let info = dmi_info_from_reader(&["vendor", "version", "missing"], |field| match field {
            "vendor" => Some("Inner\nVendor\n".to_string()),
            "version" => Some(" 1.2.3 ".to_string()),
            _ => None,
        });

        assert_eq!(info, "Inner Vendor|1.2.3|");
    }
}
