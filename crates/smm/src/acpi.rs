//! ACPI table integrity — hash DSDT/SSDT tables for tamper detection.
//!
//! Reads from `/sys/firmware/acpi/tables/`. Read-only.
//! Modified ACPI tables can execute arbitrary AML code on the OS.

use crate::{confidence, CheckResult, CheckStatus};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

const ACPI_TABLES_DIR: &str = "/sys/firmware/acpi/tables";

/// Hashed ACPI table for integrity verification.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AcpiTableHash {
    pub name: String,
    pub size: usize,
    pub sha256: String,
}

/// Read and hash all ACPI tables.
pub fn hash_tables() -> Vec<AcpiTableHash> {
    hash_tables_in_dir(Path::new(ACPI_TABLES_DIR))
}

fn hash_tables_in_dir(dir: &Path) -> Vec<AcpiTableHash> {
    if !dir.exists() {
        return Vec::new();
    }

    let mut tables = Vec::new();
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return tables,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        if let Ok(data) = fs::read(&path) {
            let hash = hex::encode(Sha256::digest(&data));
            tables.push(AcpiTableHash {
                name,
                size: data.len(),
                sha256: hash,
            });
        }
    }

    tables.sort_by(|a, b| a.name.cmp(&b.name));
    tables
}

// ── Check functions ─────────────────────────────────────────────────────

/// Hash ACPI tables for baseline / drift detection.
pub fn check_table_integrity() -> CheckResult {
    table_integrity_from_tables(hash_tables())
}

fn table_integrity_from_tables(tables: Vec<AcpiTableHash>) -> CheckResult {
    if tables.is_empty() {
        return CheckResult {
            id: "ACPI-001",
            name: "ACPI Tables",
            status: CheckStatus::Unavailable,
            confidence: 0.0,
            detail: "cannot read /sys/firmware/acpi/tables/ (permissions or not present)".into(),
        };
    }

    let dsdt = tables.iter().find(|t| t.name == "DSDT");
    let ssdt_count = tables.iter().filter(|t| t.name.starts_with("SSDT")).count();

    let dsdt_info = dsdt
        .map(|d| format!("DSDT: {} bytes sha256:{:.16}…", d.size, d.sha256))
        .unwrap_or_else(|| "DSDT: not found".into());

    CheckResult {
        id: "ACPI-001",
        name: "ACPI Tables",
        status: CheckStatus::Secure,
        confidence: confidence(0.6, 0.8),
        detail: format!(
            "{} tables hashed ({}). {dsdt_info}. Compare against known-good baseline.",
            tables.len(),
            if ssdt_count > 0 {
                format!("{ssdt_count} SSDTs")
            } else {
                "no SSDTs".into()
            },
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_consistency() {
        // Same data should produce same hash.
        let data = b"test ACPI table data";
        let h1 = hex::encode(Sha256::digest(data));
        let h2 = hex::encode(Sha256::digest(data));
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64); // SHA-256 hex = 64 chars
    }

    #[test]
    fn check_tables_runs() {
        let result = check_table_integrity();
        assert!(!result.id.is_empty());
    }

    #[test]
    fn hash_tables_in_dir_collects_files_sorts_names_and_skips_directories() {
        let dir = tempfile::TempDir::new().expect("temporary directory should be created");
        std::fs::write(dir.path().join("SSDT2"), b"second").expect("fixture should be written");
        std::fs::write(dir.path().join("DSDT"), b"primary").expect("fixture should be written");
        std::fs::create_dir(dir.path().join("nested")).expect("nested directory should exist");

        let tables = hash_tables_in_dir(dir.path());
        assert_eq!(tables.len(), 2);
        assert_eq!(tables[0].name, "DSDT");
        assert_eq!(tables[1].name, "SSDT2");
        assert_eq!(tables[0].size, 7);
        assert_eq!(tables[0].sha256, hex::encode(Sha256::digest(b"primary")));
    }

    #[test]
    fn hash_tables_in_dir_returns_empty_for_missing_or_non_directory_paths() {
        let dir = tempfile::TempDir::new().expect("temporary directory should be created");
        let file_path = dir.path().join("not-a-dir");
        std::fs::write(&file_path, b"plain file").expect("fixture should be written");

        assert!(hash_tables_in_dir(&dir.path().join("missing")).is_empty());
        assert!(hash_tables_in_dir(&file_path).is_empty());
    }

    #[test]
    fn table_integrity_summary_handles_empty_dsdt_and_ssdt_variants() {
        let unavailable = table_integrity_from_tables(Vec::new());
        assert_eq!(unavailable.status, CheckStatus::Unavailable);

        let with_dsdt = table_integrity_from_tables(vec![
            AcpiTableHash {
                name: "SSDT1".to_string(),
                size: 12,
                sha256: "a".repeat(64),
            },
            AcpiTableHash {
                name: "DSDT".to_string(),
                size: 99,
                sha256: "b".repeat(64),
            },
        ]);
        assert_eq!(with_dsdt.status, CheckStatus::Secure);
        assert!(with_dsdt.detail.contains("2 tables hashed (1 SSDTs)"));
        assert!(with_dsdt.detail.contains("DSDT: 99 bytes"));

        let without_dsdt = table_integrity_from_tables(vec![AcpiTableHash {
            name: "FACP".to_string(),
            size: 7,
            sha256: "c".repeat(64),
        }]);
        assert!(without_dsdt.detail.contains("no SSDTs"));
        assert!(without_dsdt.detail.contains("DSDT: not found"));
    }

    #[test]
    fn table_integrity_summary_counts_multiple_ssdts_and_preserves_hash_prefix() {
        let result = table_integrity_from_tables(vec![
            AcpiTableHash {
                name: "DSDT".to_string(),
                size: 128,
                sha256: "0123456789abcdef".repeat(4),
            },
            AcpiTableHash {
                name: "SSDT1".to_string(),
                size: 32,
                sha256: "a".repeat(64),
            },
            AcpiTableHash {
                name: "SSDT2".to_string(),
                size: 48,
                sha256: "b".repeat(64),
            },
        ]);

        assert_eq!(result.status, CheckStatus::Secure);
        assert!(result.detail.contains("3 tables hashed (2 SSDTs)"));
        assert!(result.detail.contains("sha256:0123456789abcdef"));
    }
}
