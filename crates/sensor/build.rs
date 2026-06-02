//! Sensor build script.
//!
//! ## Spec 069 follow-up #3 — re-embed the eBPF object automatically
//!
//! With `--features ebpf-embedded` the sensor `include_bytes!`s the compiled
//! eBPF object (`sensor-ebpf/target/bpfel-unknown-none/release/innerwarden-ebpf`)
//! into the binary. Cargo does **not** track `include_bytes!` paths for
//! rebuild, so rebuilding only the `.o` left a **stale object embedded** — the
//! workaround was to `touch crates/sensor/src/collectors/ebpf_syscall.rs` by
//! hand before every sensor rebuild (a documented foot-gun that shipped the
//! wrong bytecode more than once).
//!
//! Fix: copy the object into `OUT_DIR` and emit `rerun-if-changed` on the
//! source object. The source then `include_bytes!`s from `OUT_DIR`, which Cargo
//! *does* track — so a fresh `.o` re-runs this script, re-copies, and forces
//! the crate to recompile with the new bytecode. No manual `touch` needed.

use std::path::PathBuf;

fn main() {
    // Only the `ebpf-embedded` feature embeds the object; otherwise there is
    // nothing to copy and the source's `include_bytes!` is `#[cfg]`-ed out.
    if std::env::var_os("CARGO_FEATURE_EBPF_EMBEDDED").is_none() {
        return;
    }

    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let obj =
        manifest_dir.join("../sensor-ebpf/target/bpfel-unknown-none/release/innerwarden-ebpf");
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("innerwarden-ebpf");

    // Track the source object: any rebuild of the `.o` re-runs this script.
    println!("cargo:rerun-if-changed={}", obj.display());

    if obj.exists() {
        std::fs::copy(&obj, &out).unwrap_or_else(|e| {
            panic!(
                "failed to copy eBPF object {} -> OUT_DIR: {e}",
                obj.display()
            )
        });
    } else {
        // Don't hard-fail here: emit a clear warning. The source's
        // `include_bytes!` from OUT_DIR will then fail with a precise
        // "missing object" error pointing the operator at the build order.
        println!(
            "cargo:warning=eBPF object not found at {} — build `sensor-ebpf` (the bpfel object) before the sensor with --features ebpf-embedded",
            obj.display()
        );
    }
}
