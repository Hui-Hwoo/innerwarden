//! Capture git build provenance into compile-time env vars consumed by
//! `loops/boot.rs` startup log + the agent's `--version` output.
//!
//! # Why this exists
//!
//! 2026-05-04 prod outage: a fix that had been merged to `main` for hours
//! ("Wave 8a CL-008 package-manager suppression") was not in the binary
//! actually running on prod. The operator ran `cargo build --release` from
//! a stale source tree (HEAD on a feature branch from 2 days earlier) and
//! deployed; the agent restarted "clean" but the fix was never compiled in.
//! 1000+ false-positive correlation chains continued firing and the
//! operator believed the fix was live for two days.
//!
//! With the build commit hash baked into the binary (and surfaced in the
//! startup log + `--version`) the operator can `cat /usr/local/bin/...` |
//! `strings | grep INNERWARDEN_BUILD_COMMIT=` to verify the deployed
//! binary's source vs `git rev-parse HEAD`. The deploy script
//! (`scripts/deploy-prod.sh`) refuses to build when the source tree is
//! behind `origin/main` so the broken state cannot be reproduced.
//!
//! # Behaviour
//!
//! `INNERWARDEN_BUILD_COMMIT`: 12-char short SHA from `git rev-parse
//! --short=12 HEAD`. Falls back to `"unknown"` when git is missing or the
//! build runs outside a checkout (vendored sources, source tarball, CI
//! image without `.git`). Tests only assert the env var IS set; they
//! accept both real SHAs and the `"unknown"` fallback so vendored builds
//! do not break.
//!
//! `INNERWARDEN_BUILD_DIRTY`: `"true"` if `git status --porcelain` reports
//! any working-tree change at build time, `"false"` otherwise (including
//! the `"unknown"` git-missing case). A dirty build is allowed but flagged
//! so an operator who deployed from `cargo build` mid-edit knows.
//!
//! `cargo:rerun-if-changed` triggers cover the typical commit-bump path
//! (`.git/HEAD` for branch switches, `.git/refs/heads/...` for new
//! commits). They do not cover stash / dirty edits; those are reflected
//! by the dirty flag, not by re-running this build script.

use std::process::Command;

fn git_short_sha() -> String {
    Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

fn git_dirty() -> bool {
    Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| !o.stdout.is_empty())
        .unwrap_or(false)
}

fn main() {
    let sha = git_short_sha();
    let dirty = git_dirty();

    println!("cargo:rustc-env=INNERWARDEN_BUILD_COMMIT={sha}");
    println!(
        "cargo:rustc-env=INNERWARDEN_BUILD_DIRTY={}",
        if dirty { "true" } else { "false" }
    );

    // Re-run when the checkout's HEAD or the local refs change. Dirty
    // working-tree changes are NOT covered here (they are reflected via
    // the dirty flag, not by re-running the build script).
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/refs");
}
