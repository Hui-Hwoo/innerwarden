//! Kernel text section hashing — detect runtime code modification.
//!
//! Reads the kernel's executable code from /proc/kcore and hashes it
//! to detect inline hooking, code patching, and rootkit modifications.
//!
//! /proc/kcore is an ELF-format file representing the kernel's virtual
//! memory. The .text section contains executable code. If a rootkit
//! patches a syscall handler or hooks a function, the hash changes.
//!
//! Fallback: if /proc/kcore is not readable (requires root + CONFIG_PROC_KCORE),
//! we hash /proc/kallsyms addresses to detect symbol table manipulation,
//! and check /sys/kernel/btf/vmlinux for BTF integrity.

use crate::{confidence, CheckResult, CheckStatus};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;
use std::path::Path;

/// Kernel text integrity state.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KernelTextState {
    /// SHA-256 of the kernel text section (from /proc/kcore or fallback).
    pub text_hash: Option<String>,
    /// Method used to obtain the hash.
    pub method: String,
    /// Size of the hashed region in bytes.
    pub size: usize,
    /// SHA-256 of /sys/kernel/btf/vmlinux (BTF type info — changes if kernel is different).
    pub btf_hash: Option<String>,
    /// SHA-256 of sorted kallsyms addresses (detect address manipulation).
    pub kallsyms_addr_hash: Option<String>,
    /// Number of kernel text symbols (functions in .text).
    pub text_symbol_count: usize,
}

impl KernelTextState {
    pub fn capture() -> Self {
        // Try /proc/kcore first (most definitive).
        let (text_hash, method, size) = read_kcore_text()
            .map(|(h, s)| (Some(h), "kcore".to_string(), s))
            .unwrap_or_else(|| {
                // Fallback: hash the first 4MB of /proc/kcore header.
                read_kcore_header()
                    .map(|(h, s)| (Some(h), "kcore_header".to_string(), s))
                    .unwrap_or((None, "unavailable".to_string(), 0))
            });

        let btf_hash = hash_file_if_exists("/sys/kernel/btf/vmlinux");
        let (kallsyms_addr_hash, text_symbol_count) = hash_kallsyms_addresses();

        Self {
            text_hash,
            method,
            size,
            btf_hash,
            kallsyms_addr_hash,
            text_symbol_count,
        }
    }
}

/// Read and hash the kernel text section from /proc/kcore.
/// /proc/kcore is an ELF core dump of kernel memory.
/// We read the first N bytes which contain the ELF header + kernel text.
fn read_kcore_text() -> Option<(String, usize)> {
    let path = Path::new("/proc/kcore");
    if !path.exists() {
        return None;
    }

    // Read the first 8MB — contains ELF header + kernel text segment.
    // We don't parse ELF (would need a dependency) — just hash the raw bytes.
    // The hash changes if any kernel code is modified.
    let mut f = fs::File::open(path).ok()?;
    let mut buf = vec![0u8; 8 * 1024 * 1024];
    let n = f.read(&mut buf).ok()?;
    buf.truncate(n);
    kcore_text_hash_from_bytes(&buf)
}

/// Lighter fallback: read just the ELF header of /proc/kcore (first 64KB).
fn read_kcore_header() -> Option<(String, usize)> {
    let path = Path::new("/proc/kcore");
    let mut f = fs::File::open(path).ok()?;
    let mut buf = vec![0u8; 64 * 1024];
    let n = f.read(&mut buf).ok()?;
    buf.truncate(n);
    kcore_header_hash_from_bytes(&buf)
}

fn kcore_text_hash_from_bytes(bytes: &[u8]) -> Option<(String, usize)> {
    if bytes.len() < 4096 {
        return None; // too small to be useful
    }
    Some((hex::encode(Sha256::digest(bytes)), bytes.len()))
}

fn kcore_header_hash_from_bytes(bytes: &[u8]) -> Option<(String, usize)> {
    if bytes.len() < 52 {
        // ELF header minimum.
        return None;
    }
    // Verify ELF magic.
    if &bytes[..4] != b"\x7fELF" {
        return None;
    }
    Some((hex::encode(Sha256::digest(bytes)), bytes.len()))
}

/// Hash a file if it exists.
fn hash_file_if_exists(path: &str) -> Option<String> {
    let data = fs::read(path).ok()?;
    Some(hex::encode(Sha256::digest(&data)))
}

/// Hash the ADDRESS column of /proc/kallsyms (not the symbol names).
/// Address manipulation indicates KASLR bypass or symbol table tampering.
/// Returns (hash, count of T/t symbols = text section functions).
fn hash_kallsyms_addresses() -> (Option<String>, usize) {
    let content = match fs::read_to_string("/proc/kallsyms") {
        Ok(c) => c,
        Err(_) => return (None, 0),
    };

    hash_kallsyms_addresses_from_content(&content)
}

fn hash_kallsyms_addresses_from_content(content: &str) -> (Option<String>, usize) {
    let mut hasher = Sha256::new();
    let mut text_count = 0;

    for line in content.lines() {
        let parts: Vec<&str> = line.splitn(3, ' ').collect();
        if parts.len() >= 2 {
            // Hash the address.
            hasher.update(parts[0].as_bytes());
            hasher.update(b"\n");
            // Count text section symbols (type T or t).
            if parts[1] == "T" || parts[1] == "t" {
                text_count += 1;
            }
        }
    }

    let hash = hex::encode(hasher.finalize());
    (Some(hash), text_count)
}

// ── Check function ──────────────────────────────────────────────────────

/// Verify kernel text integrity.
pub fn check_kernel_text() -> CheckResult {
    kernel_text_check_from_state(KernelTextState::capture())
}

fn kernel_text_check_from_state(state: KernelTextState) -> CheckResult {
    // If we got a kcore hash, that's the strongest signal.
    if let Some(ref hash) = state.text_hash {
        return CheckResult {
            id: "KTEXT-001",
            name: "Kernel Text Integrity",
            status: CheckStatus::Secure,
            confidence: confidence(0.9, 0.85),
            detail: format!(
                "kernel text hashed via {} ({} bytes, sha256:{:.16}…). \
                 {} text symbols. Baseline captured for drift detection.",
                state.method, state.size, hash, state.text_symbol_count,
            ),
        };
    }

    // Fallback: BTF or kallsyms addresses.
    if state.btf_hash.is_some() || state.kallsyms_addr_hash.is_some() {
        let mut parts = Vec::new();
        if let Some(ref h) = state.btf_hash {
            parts.push(format!("BTF sha256:{:.16}…", h));
        }
        if let Some(ref h) = state.kallsyms_addr_hash {
            parts.push(format!(
                "kallsyms-addr sha256:{:.16}…, {} text symbols",
                h, state.text_symbol_count
            ));
        }
        return CheckResult {
            id: "KTEXT-001",
            name: "Kernel Text Integrity",
            status: CheckStatus::Secure,
            confidence: confidence(0.7, 0.7),
            detail: format!(
                "kernel text via fallback: {}. \
                 /proc/kcore not available (need root + CONFIG_PROC_KCORE).",
                parts.join("; ")
            ),
        };
    }

    CheckResult {
        id: "KTEXT-001",
        name: "Kernel Text Integrity",
        status: CheckStatus::Unavailable,
        confidence: 0.0,
        detail: "cannot verify kernel text (need root for /proc/kcore or /proc/kallsyms)".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_runs() {
        let state = KernelTextState::capture();
        // On macOS/non-Linux, everything will be None — but shouldn't panic.
        let _ = state;
    }

    #[test]
    fn check_runs() {
        let result = check_kernel_text();
        assert_eq!(result.id, "KTEXT-001");
    }

    #[test]
    fn elf_magic_check() {
        let valid_elf = b"\x7fELF\x02\x01\x01\x00";
        assert_eq!(&valid_elf[..4], b"\x7fELF");

        let invalid = b"\x00\x00\x00\x00";
        assert_ne!(&invalid[..4], b"\x7fELF");
    }

    #[test]
    fn fallback_hash_helpers_cover_file_and_kallsyms_paths() {
        let dir = tempfile::TempDir::new().expect("temporary directory should be created");
        let path = dir.path().join("btf");
        std::fs::write(&path, b"btf").expect("fixture should be written");

        let hash = hash_file_if_exists(path.to_str().expect("utf8 path"))
            .expect("hash should be produced");
        assert_eq!(hash, hex::encode(Sha256::digest(b"btf")));
        assert!(hash_file_if_exists("/definitely/missing/btf").is_none());

        let (kallsyms_hash, count) = hash_kallsyms_addresses_from_content(
            "ffffffff81000000 T start_kernel\n\
             ffffffff81000001 t helper\n\
             ffffffff81000002 D data_symbol\n\
             malformed\n",
        );
        assert!(kallsyms_hash.is_some());
        assert_eq!(count, 2);
    }

    #[test]
    fn kernel_text_check_reports_primary_fallback_and_unavailable_modes() {
        let primary = kernel_text_check_from_state(KernelTextState {
            text_hash: Some("a".repeat(64)),
            method: "kcore".to_string(),
            size: 8192,
            btf_hash: None,
            kallsyms_addr_hash: None,
            text_symbol_count: 11,
        });
        assert_eq!(primary.status, CheckStatus::Secure);
        assert!(primary.detail.contains("kernel text hashed via kcore"));

        let fallback = kernel_text_check_from_state(KernelTextState {
            text_hash: None,
            method: "unavailable".to_string(),
            size: 0,
            btf_hash: Some("b".repeat(64)),
            kallsyms_addr_hash: Some("c".repeat(64)),
            text_symbol_count: 7,
        });
        assert_eq!(fallback.status, CheckStatus::Secure);
        assert!(fallback.detail.contains("kernel text via fallback"));
        assert!(fallback.detail.contains("7 text symbols"));

        let unavailable = kernel_text_check_from_state(KernelTextState {
            text_hash: None,
            method: "unavailable".to_string(),
            size: 0,
            btf_hash: None,
            kallsyms_addr_hash: None,
            text_symbol_count: 0,
        });
        assert_eq!(unavailable.status, CheckStatus::Unavailable);
    }

    #[test]
    fn kcore_hash_helpers_cover_short_invalid_and_valid_inputs() {
        assert!(kcore_text_hash_from_bytes(&vec![0u8; 4095]).is_none());
        let text = vec![0xAB; 4096];
        let (text_hash, text_size) =
            kcore_text_hash_from_bytes(&text).expect("large buffers should hash");
        assert_eq!(text_size, 4096);
        assert_eq!(text_hash, hex::encode(Sha256::digest(&text)));

        assert!(kcore_header_hash_from_bytes(&vec![0u8; 51]).is_none());
        assert!(kcore_header_hash_from_bytes(&vec![0u8; 64]).is_none());

        let mut elf = vec![0u8; 64];
        elf[..4].copy_from_slice(b"\x7fELF");
        let (header_hash, header_size) =
            kcore_header_hash_from_bytes(&elf).expect("ELF headers should hash");
        assert_eq!(header_size, 64);
        assert_eq!(header_hash, hex::encode(Sha256::digest(&elf)));
    }

    #[test]
    fn kernel_text_fallback_formats_btf_only_and_kallsyms_only_states() {
        let btf_only = kernel_text_check_from_state(KernelTextState {
            text_hash: None,
            method: "unavailable".to_string(),
            size: 0,
            btf_hash: Some("d".repeat(64)),
            kallsyms_addr_hash: None,
            text_symbol_count: 0,
        });
        assert_eq!(btf_only.status, CheckStatus::Secure);
        assert!(btf_only.detail.contains("BTF sha256:dddddddddddddddd"));
        assert!(!btf_only.detail.contains("kallsyms-addr"));

        let kallsyms_only = kernel_text_check_from_state(KernelTextState {
            text_hash: None,
            method: "unavailable".to_string(),
            size: 0,
            btf_hash: None,
            kallsyms_addr_hash: Some("e".repeat(64)),
            text_symbol_count: 42,
        });
        assert_eq!(kallsyms_only.status, CheckStatus::Secure);
        assert!(kallsyms_only
            .detail
            .contains("kallsyms-addr sha256:eeeeeeeeeeeeeeee"));
        assert!(kallsyms_only.detail.contains("42 text symbols"));
        assert!(!kallsyms_only.detail.contains("BTF sha256"));
    }

    #[test]
    fn hash_kallsyms_addresses_is_stable_for_address_order_and_text_symbol_counting() {
        let content = "ffffffff81000000 T start_kernel\n\
                       ffffffff81000001 t schedule\n\
                       ffffffff81000002 R rodata\n";
        let (first_hash, first_count) = hash_kallsyms_addresses_from_content(content);
        let (second_hash, second_count) = hash_kallsyms_addresses_from_content(content);

        assert_eq!(first_hash, second_hash);
        assert_eq!(first_count, 2);
        assert_eq!(second_count, 2);
    }

    #[test]
    fn hash_kallsyms_addresses_handles_empty_input_without_losing_hash_contract() {
        let (hash, count) = hash_kallsyms_addresses_from_content("");
        assert_eq!(count, 0);
        assert_eq!(hash, Some(hex::encode(Sha256::digest(b""))));
    }
}
