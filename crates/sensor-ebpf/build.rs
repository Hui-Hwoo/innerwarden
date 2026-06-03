//! Build script — compiles `src/shim/shim.c` into a BPF `.o` with BTF
//! debug info, then passes it to `bpf-linker` so the final eBPF
//! artefact's BTF section is non-empty.
//!
//! ## Why this exists
//!
//! See `src/shim/shim.c` for the full rationale. tl;dr: kernel ≥ 6.4
//! rejects LSM programs whose `.o` has no BTF section; Rust's BPF
//! target does not emit one; clang's BPF target does. The Bombini
//! project (aya-based, kernel 6.8) uses the same pattern. We follow
//! it.
//!
//! ## Operator host requirement
//!
//! `clang` (≥ 15 recommended, BPF target enabled by default in
//! mainstream distributions) must be on `$PATH` at sensor build
//! time. `scripts/deploy-prod.sh` ensures it on Oracle prod; CI
//! runners have it via the existing rust toolchain image.

use std::path::Path;
use std::process::Command;

fn main() {
    // Spec 069: select the eBPF syscall-arg `pt_regs` offsets (the `__sc_off!`
    // macro in main.rs) for the DEPLOY arch. The object is built for the
    // arch-neutral `bpfel` target, so `CARGO_CFG_TARGET_ARCH` is "bpf" and
    // useless. The deploy arch is normally the build-host arch
    // (`std::env::consts::ARCH`) — correct for from-source builds where
    // build-host == deploy-host.
    //
    // CROSS builds MUST override via `IW_EBPF_DEPLOY_ARCH`: the release builds
    // BOTH x86_64 and aarch64 sensors on a single x86_64 runner, so without the
    // override the aarch64 binary embedded an x86_64-offset object and read
    // syscall args at the wrong `pt_regs` offsets — silently breaking aarch64
    // kill/openat/connect/setuid/ptrace/execve capture in 0.15.1-0.15.3.
    println!("cargo:rerun-if-env-changed=IW_EBPF_DEPLOY_ARCH");
    println!("cargo:rustc-check-cfg=cfg(iw_arch_x86_64)");
    println!("cargo:rustc-check-cfg=cfg(iw_arch_aarch64)");
    let deploy_arch =
        std::env::var("IW_EBPF_DEPLOY_ARCH").unwrap_or_else(|_| std::env::consts::ARCH.to_string());
    match deploy_arch.as_str() {
        "x86_64" => println!("cargo:rustc-cfg=iw_arch_x86_64"),
        "aarch64" => println!("cargo:rustc-cfg=iw_arch_aarch64"),
        other => println!(
            "cargo:warning=IW_EBPF_DEPLOY_ARCH='{other}' unsupported; eBPF syscall-arg offsets not configured"
        ),
    }

    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();

    // The shim only needs to participate when we're cross-compiling
    // for the BPF target. On host builds (cargo test on x86, etc.)
    // we skip the clang step so the build host doesn't need clang
    // for `cargo check` / IDE feedback loops.
    if target_arch != "bpf" {
        return;
    }

    let shim_dir = Path::new("src/shim");
    let shim_c = shim_dir.join("shim.c");
    let types_h = shim_dir.join("types.h");
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR set by cargo");
    let shim_o = format!("{out_dir}/shim.o");

    println!("cargo:rerun-if-changed={}", shim_c.display());
    println!("cargo:rerun-if-changed={}", types_h.display());

    // -g is the load-bearing flag — it emits DWARF which clang's BPF
    // backend converts to BTF in the resulting `.o`. The kernel
    // verifier looks at that BTF section when validating LSM type
    // signatures.
    //
    // -O2 keeps the shim small (no unused symbol bloat) without
    // collapsing the anchor reference, which is `volatile`.
    //
    // -emit-llvm + -c stops at the LLVM bitcode stage so bpf-linker
    // (aya's custom linker that runs after rustc) can ingest it
    // alongside the Rust crate's bitcode.
    let status = Command::new("clang")
        .args(["-O2", "-emit-llvm", "-target", "bpf", "-c", "-g"])
        .arg(&shim_c)
        .arg("-o")
        .arg(&shim_o)
        .status()
        .expect("clang failed to start; install clang on the build host");

    if !status.success() {
        panic!("clang failed to compile {}", shim_c.display());
    }

    // Tell rustc to add the shim's `.o` as a linker argument so
    // bpf-linker merges its BTF section into the final eBPF binary.
    // The `link-arg=` form lets us pass an absolute path that
    // bpf-linker accepts as input alongside the Rust bitcode.
    println!("cargo:rustc-link-search=native={out_dir}");
    println!("cargo:rustc-link-arg={shim_o}");
}
