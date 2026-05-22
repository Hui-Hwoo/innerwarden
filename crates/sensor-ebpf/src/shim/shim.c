// shim.c — emits kernel struct BTF for the sensor's LSM programs.
//
// # Why this file exists
//
// The kernel BPF verifier on Linux ≥ 6.4 rejects LSM programs whose
// first-argument BTF type does not match the hook's kernel signature
// (`bpf_lsm_<hook>` expects `*const struct linux_binprm` for
// `bprm_check_security`, `*const struct file` for `file_open`, etc.).
// The Rust eBPF toolchain (`cargo +nightly build --target
// bpfel-unknown-none`) does not emit a BTF section in the resulting
// `.o` at all — so even when aya's `#[lsm(hook = "...")]` macro picks
// up the right `bpf_lsm_*` BTF id from kernel BTF for the *attach*,
// the *program*'s own BTF is empty and the verifier rejects with
// `EINVAL` and a log pointing at the missing arg type.
//
// The Bombini project (aya-based eBPF agent, runs on kernel 6.8)
// solves this with a small `shim.c` compiled by clang's BPF target
// with `-g` (debug info → BTF). clang DOES emit BTF for BPF, and
// `bpf-linker` (aya's custom linker) merges the shim's `.o`
// (including its BTF section) into the final eBPF artefact. The
// kernel verifier then sees the typed struct definitions and
// accepts the LSM program.
//
// We do the minimum here: declare each kernel struct we hook with
// `__attribute__((preserve_access_index))` so clang emits CO-RE
// BTF for it, then keep a single `__attribute__((used))` reference
// so LTO does not strip the type out.
//
// Adding new LSM hooks (`file_open`, `bpf`) means appending their
// struct + an anchor here. Field accesses themselves stay in the
// Rust side (`crates/sensor-ebpf/src/main.rs::check_overlay_drift`)
// via `bpf_probe_read_kernel` with hard-coded offsets. CO-RE
// relocations through the shim are deliberately out of scope for
// this commit — see follow-up work to migrate the offsets.

#include "types.h"

// License must be GPL for the kernel verifier to accept programs
// that use GPL-only helpers (bpf_probe_read_kernel, etc.). The
// sensor's main.rs already declares one; this duplicate would
// collide at link, so we omit it here.

// ── linux_binprm (bprm_check_security) ──────────────────────────────
//
// Only the fields the existing Rust code path touches; clang still
// emits the full type because of preserve_access_index, but the
// field set we list pins what we promise to read.
struct file;
struct cred;

struct linux_binprm {
    struct file *file;
    struct cred *cred;
} __attribute__((preserve_access_index));

// Anchor: keep the type alive through LTO so clang emits its BTF
// into the final `.o`. Never read at runtime — purely a compile-time
// pin. `volatile` blocks LLVM from constant-folding the address into
// the assertion that the symbol is unused.
__attribute__((used))
volatile struct linux_binprm *_innerwarden_anchor_binprm = 0;
