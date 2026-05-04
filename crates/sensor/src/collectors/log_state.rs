//! Per-collector logging state machine for retry-heavy I/O paths.
//!
//! # Why this exists
//!
//! Wave 9f (2026-05-04 prod audit AUDIT-010): the `nginx_access` and
//! `nginx_error` collectors each retry to open their target log file every
//! few seconds. When the file is persistently unreadable - a misconfigured
//! docker bind mount, a removed log volume, an ACL issue - the collector
//! emits one `WARN` per retry attempt. On 2026-05-04 prod accumulated
//! **728 nginx warnings in a 30-minute window** (~24 / minute), all of the
//! shape `nginx_access: cannot open <path>: No such file or directory`.
//! That floods the journal, slows `journalctl` queries, and risks tripping
//! journald's per-service rate limit which then drops other useful events.
//!
//! # Contract
//!
//! [`OpenLogState`] is a pure state machine that maps the result of an
//! open attempt to a [`LogVerdict`]. The collector is responsible for
//! issuing the actual `tracing::warn!` / `info!` / `debug!` based on the
//! verdict. Pure logic so the unit tests do not need an mpsc channel,
//! tokio runtime, or temporary filesystem.
//!
//! Verdict shapes:
//!
//! | Previous state | This attempt    | Verdict            | Why |
//! |----------------|-----------------|--------------------|-----|
//! | never observed | success         | `Quiet`            | Steady-state success is normal, no log needed. |
//! | never observed | failure (`E`)   | `WarnNewFailure`   | First indication of a problem - operator wants to know. |
//! | failed (`E`)   | success         | `InfoRecovered`    | Closes the loop the operator opened with the WARN. |
//! | failed (`E`)   | failure (`E`)   | `Quiet`            | Same problem as before - already logged once. |
//! | failed (`E1`)  | failure (`E2`)  | `WarnDifferentErr` | New error class on top of the old one - operator should see it. |
//! | succeeded      | failure         | `WarnNewFailure`   | Transition out of healthy state. |
//!
//! Concretely: a collector that fails to open its target for one hour will
//! emit **exactly one** `WARN` (when the failure starts) and **exactly one**
//! `INFO` (if it ever recovers). Pre-Wave-9f the same situation produced
//! ~720 `WARN` entries per hour.

use std::fmt;

/// What [`OpenLogState::observe_open`] tells the collector to do for the
/// current attempt. The collector translates this into the actual
/// `tracing::warn!` / `info!` / `debug!` call (the state machine itself
/// emits no logs - keeps the unit tests pure).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogVerdict {
    /// Do not log. Steady-state success, or steady-state failure with the
    /// same error as previously logged.
    Quiet,
    /// Log a `WARN` because this is the FIRST observation of a failure
    /// (transition from never-observed or success into a failure state).
    WarnNewFailure,
    /// Log a `WARN` because the failure has changed shape since the last
    /// `WARN` we emitted. Distinct from [`Self::WarnNewFailure`] only in
    /// the diagnostic; both lead the collector to call `tracing::warn!`.
    WarnDifferentErr,
    /// Log an `INFO` because the operation just recovered from a failure
    /// state. Pairs with the `WARN` the operator saw earlier.
    InfoRecovered,
}

impl fmt::Display for LogVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Quiet => write!(f, "quiet"),
            Self::WarnNewFailure => write!(f, "warn-new-failure"),
            Self::WarnDifferentErr => write!(f, "warn-different-err"),
            Self::InfoRecovered => write!(f, "info-recovered"),
        }
    }
}

/// Pure state machine that suppresses repeated identical-failure log
/// entries on retry-heavy I/O paths. See module docs for the contract.
#[derive(Debug, Default)]
pub struct OpenLogState {
    /// `Some(error_string)` if the last observation was a failure, `None`
    /// for never-observed or last-was-success. The error string is the
    /// rendered `Display` of the I/O error so different failure modes
    /// (ENOENT vs EACCES vs ENOSPC) trigger distinct WARNs.
    last_failure: Option<String>,
}

impl OpenLogState {
    /// New, never-observed state. Equivalent to `Self::default()`.
    pub fn new() -> Self {
        Self { last_failure: None }
    }

    /// Update the state machine with the result of one open attempt.
    /// Returns the [`LogVerdict`] the caller should act on.
    ///
    /// `result_err` is `Some(err_string)` for failure, `None` for success.
    /// The error string is compared verbatim against the previous failure;
    /// callers that want to coalesce ENOENT-vs-EACCES should pass a
    /// canonicalised form (e.g. just the `kind()` or just the operator-
    /// readable suffix). Callers that want every distinct error message to
    /// re-WARN should pass the full rendered error.
    pub fn observe_open(&mut self, result_err: Option<String>) -> LogVerdict {
        match (self.last_failure.as_deref(), result_err) {
            (None, None) => LogVerdict::Quiet,
            (None, Some(err)) => {
                self.last_failure = Some(err);
                LogVerdict::WarnNewFailure
            }
            (Some(_), None) => {
                self.last_failure = None;
                LogVerdict::InfoRecovered
            }
            (Some(prev), Some(curr)) if prev == curr => LogVerdict::Quiet,
            (Some(_), Some(curr)) => {
                self.last_failure = Some(curr);
                LogVerdict::WarnDifferentErr
            }
        }
    }

    /// Whether the last observation was a failure. Used by tests + reserved
    /// for callers that want a short-circuit "is_in_failure ? skip work :
    /// proceed" check in their hot loop.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn is_in_failure(&self) -> bool {
        self.last_failure.is_some()
    }
}

/// Decision a collector reaches for ONE open attempt: how the loop should
/// proceed (continue or break) and what (if anything) to log. Pure enum
/// over [`LogVerdict`] + a continue/break flag, so the collector's call
/// site is just a `match` statement on this and the integration with the
/// state machine can be unit-tested without spawning a tokio runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenAction {
    /// File opened successfully. Caller proceeds to the read loop. The
    /// optional inner `LogVerdict` is `Some(InfoRecovered)` when the
    /// previous attempt had failed, so the collector can emit the
    /// recovery INFO line; `None` for steady-state success (no log).
    Proceed { verdict: Option<LogVerdict> },
    /// File could not be opened. The collector should sleep and retry.
    /// `verdict` tells the collector how to log this attempt (per the
    /// state machine contract).
    Retry { verdict: LogVerdict },
}

/// One concrete logging instruction the collector emits for the current
/// open attempt. Pure data so the per-verdict match arms in
/// `nginx_access` / `nginx_error` (and any future log-tail collector that
/// reuses the state machine) can be exhaustively unit-tested without an
/// mpsc channel, tokio runtime, or real filesystem.
///
/// Boundary: the helper decides *what level* to log at; the collector still
/// calls the actual `tracing::warn!` / `info!` / `debug!` macro because
/// macros need access to the local `path` / `error` variables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogInstruction {
    /// Steady-state success or steady-state suppressed failure: emit
    /// nothing at the operator-default level. (For Quiet on a Retry path
    /// the collector should still emit a `debug!` line so trace-level
    /// debugging captures the retry cadence - see [`Self::DebugSuppressed`].)
    None,
    /// File became readable again after a failure - emit `tracing::info!`.
    InfoRecovered,
    /// First failure or different error - emit `tracing::warn!` so the
    /// operator sees the transition out of healthy state.
    WarnCannotOpen,
    /// Same failure as last time - emit `tracing::debug!` so the retry
    /// shows up at trace level (operators who set `RUST_LOG=debug` can
    /// watch the retry cadence) without flooding default-level journals.
    DebugSuppressed,
}

/// Translate an [`OpenAction`] (the output of [`classify_open`]) into the
/// concrete log instruction the collector should act on. Pure helper.
///
/// Mapping:
/// - `Proceed { verdict: None }` → `None` (steady-state success)
/// - `Proceed { verdict: Some(InfoRecovered) }` → `InfoRecovered`
/// - `Retry { verdict: WarnNewFailure | WarnDifferentErr }` → `WarnCannotOpen`
/// - `Retry { verdict: Quiet }` → `DebugSuppressed`
/// - `Retry { verdict: InfoRecovered }` → `DebugSuppressed` + `debug_assert!`
///   (unreachable per `classify_open` contract; defensively returns the
///   quietest log level in release builds so a contract violation does
///   not turn into a log flood).
pub fn log_instruction_for(action: &OpenAction) -> LogInstruction {
    match action {
        OpenAction::Proceed { verdict: None } => LogInstruction::None,
        OpenAction::Proceed {
            verdict: Some(LogVerdict::InfoRecovered),
        } => LogInstruction::InfoRecovered,
        OpenAction::Proceed {
            verdict: Some(other),
        } => {
            debug_assert!(false, "unexpected verdict on Proceed: {other:?}");
            LogInstruction::None
        }
        OpenAction::Retry {
            verdict: LogVerdict::WarnNewFailure | LogVerdict::WarnDifferentErr,
        } => LogInstruction::WarnCannotOpen,
        OpenAction::Retry {
            verdict: LogVerdict::Quiet,
        } => LogInstruction::DebugSuppressed,
        OpenAction::Retry {
            verdict: LogVerdict::InfoRecovered,
        } => {
            debug_assert!(
                false,
                "Retry verdict cannot be InfoRecovered (classify_open contract)"
            );
            LogInstruction::DebugSuppressed
        }
    }
}

/// Map an open result to an [`OpenAction`], advancing the state machine.
///
/// This is the heart of the AUDIT-010 anchor: the collector's hot loop
/// calls this with `Ok(())` or `Err(error_string)` and gets back a
/// concrete instruction. Pure: no I/O, no logging side-effects, no async.
/// The caller is responsible for emitting the actual `tracing::warn!` /
/// `info!` / `debug!` based on the returned verdict.
///
/// `result_err` mirrors [`OpenLogState::observe_open`]: `None` for
/// success, `Some(err_string)` for failure (verbatim error message).
pub fn classify_open(state: &mut OpenLogState, result_err: Option<String>) -> OpenAction {
    let was_failure = result_err.is_some();
    let verdict = state.observe_open(result_err);
    match (was_failure, verdict) {
        (false, LogVerdict::Quiet) => OpenAction::Proceed { verdict: None },
        (false, LogVerdict::InfoRecovered) => OpenAction::Proceed {
            verdict: Some(LogVerdict::InfoRecovered),
        },
        (true, v) => OpenAction::Retry { verdict: v },
        // Unreachable: a success path cannot produce a Warn* verdict
        // because the state machine only emits Warn* on failures.
        (false, v) => {
            debug_assert!(false, "unexpected verdict {v:?} on success path");
            OpenAction::Proceed { verdict: None }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── AUDIT-010 anchors (Wave 9f) ────────────────────────────────────
    //
    // Pin the contract: a collector retrying every 5s for an hour against
    // a missing file produces exactly one WARN (on the first failure) and
    // zero subsequent WARNs (steady-state). Pre-Wave-9f it produced ~720
    // WARNs in that window. Removing or weakening this contract reverts
    // the bug; these tests exist to prevent that quietly.

    #[test]
    fn steady_state_success_is_quiet() {
        // Healthy boot, healthy poll: collector never logs. Anti-regression
        // for accidentally turning every successful open into an INFO
        // (would trade one problem for another).
        let mut st = OpenLogState::new();
        for _ in 0..10 {
            assert_eq!(st.observe_open(None), LogVerdict::Quiet);
        }
        assert!(!st.is_in_failure());
    }

    #[test]
    fn first_failure_warns_subsequent_identical_failures_are_quiet() {
        // The exact prod failure shape (AUDIT-010): 720 retries against an
        // unreadable nginx log produced 720 WARNs. Post-Wave-9f the same
        // 720 retries produce exactly 1 WARN.
        let mut st = OpenLogState::new();
        let err = "No such file or directory (os error 2)".to_string();
        assert_eq!(
            st.observe_open(Some(err.clone())),
            LogVerdict::WarnNewFailure,
            "first failure must WARN"
        );
        for _ in 0..719 {
            assert_eq!(
                st.observe_open(Some(err.clone())),
                LogVerdict::Quiet,
                "retries with same error must NOT re-WARN"
            );
        }
        assert!(st.is_in_failure());
    }

    #[test]
    fn recovery_after_failure_emits_info_and_resets() {
        // The operator opened a WARN; the collector must close the loop
        // when the file becomes readable again. INFO is the right level:
        // it is a positive transition the operator may want to see, but
        // not so noisy that a flapping mount drowns the journal.
        let mut st = OpenLogState::new();
        st.observe_open(Some("ENOENT".to_string()));
        assert!(st.is_in_failure());
        assert_eq!(st.observe_open(None), LogVerdict::InfoRecovered);
        assert!(!st.is_in_failure());
        // Subsequent successes are quiet again - INFO does not repeat.
        assert_eq!(st.observe_open(None), LogVerdict::Quiet);
    }

    #[test]
    fn different_error_after_first_failure_warns_again() {
        // ENOENT for a while, then suddenly EACCES (someone changed perms).
        // The new error class is a separate event the operator should see;
        // we are NOT in the same failure mode anymore. The pair of WARNs
        // is what we want.
        let mut st = OpenLogState::new();
        assert_eq!(
            st.observe_open(Some("ENOENT".to_string())),
            LogVerdict::WarnNewFailure
        );
        assert_eq!(
            st.observe_open(Some("ENOENT".to_string())),
            LogVerdict::Quiet
        );
        assert_eq!(
            st.observe_open(Some("EACCES".to_string())),
            LogVerdict::WarnDifferentErr
        );
        // Then EACCES is the new steady state - subsequent EACCES are quiet.
        assert_eq!(
            st.observe_open(Some("EACCES".to_string())),
            LogVerdict::Quiet
        );
    }

    #[test]
    fn flapping_failure_recovery_failure_re_warns_each_failure_episode() {
        // Operator-visible flap: docker volume drops out, comes back, drops
        // out again. We want one WARN per failure episode (2 WARNs total)
        // and one INFO per recovery (1 INFO between them). Anti-regression
        // for "remember every error we ever saw" which would silence the
        // second failure episode entirely.
        let mut st = OpenLogState::new();
        let err = "ENOENT".to_string();
        assert_eq!(
            st.observe_open(Some(err.clone())),
            LogVerdict::WarnNewFailure
        );
        assert_eq!(st.observe_open(None), LogVerdict::InfoRecovered);
        assert_eq!(
            st.observe_open(Some(err.clone())),
            LogVerdict::WarnNewFailure,
            "second failure episode must re-WARN even with the same error string"
        );
    }

    #[test]
    fn success_then_failure_warns() {
        // Boot OK, then file disappears. Transition out of success into
        // failure must WARN. This is the canonical "something broke" path.
        let mut st = OpenLogState::new();
        assert_eq!(st.observe_open(None), LogVerdict::Quiet);
        assert_eq!(
            st.observe_open(Some("ENOENT".to_string())),
            LogVerdict::WarnNewFailure
        );
    }

    #[test]
    fn long_run_steady_failure_emits_one_warn_total() {
        // End-to-end shape: simulate 720 retries (one hour at 5 s
        // cadence). Count the verdicts. Pre-Wave-9f WARN count would be
        // 720; post-fix it must be 1.
        let mut st = OpenLogState::new();
        let err = "No such file or directory (os error 2)".to_string();
        let (mut warns, mut quiets) = (0usize, 0usize);
        for _ in 0..720 {
            match st.observe_open(Some(err.clone())) {
                LogVerdict::WarnNewFailure | LogVerdict::WarnDifferentErr => warns += 1,
                LogVerdict::Quiet => quiets += 1,
                LogVerdict::InfoRecovered => panic!("unexpected recovery in steady-failure"),
            }
        }
        assert_eq!(warns, 1, "exactly one WARN for the whole failure episode");
        assert_eq!(quiets, 719);
    }

    // ── classify_open anchors ──────────────────────────────────────────

    #[test]
    fn classify_open_steady_success_returns_proceed_no_verdict() {
        // Success after success: collector proceeds, no log line.
        let mut st = OpenLogState::new();
        assert_eq!(
            classify_open(&mut st, None),
            OpenAction::Proceed { verdict: None }
        );
        assert_eq!(
            classify_open(&mut st, None),
            OpenAction::Proceed { verdict: None }
        );
    }

    #[test]
    fn classify_open_first_failure_returns_retry_warn_new() {
        // First time the file is unreadable: Retry + WarnNewFailure.
        let mut st = OpenLogState::new();
        assert_eq!(
            classify_open(&mut st, Some("ENOENT".to_string())),
            OpenAction::Retry {
                verdict: LogVerdict::WarnNewFailure
            }
        );
    }

    #[test]
    fn classify_open_repeat_failure_returns_retry_quiet() {
        // The whole point of Wave 9f: subsequent identical failures must
        // be Retry+Quiet so the collector does NOT log them.
        let mut st = OpenLogState::new();
        classify_open(&mut st, Some("ENOENT".to_string()));
        for _ in 0..50 {
            assert_eq!(
                classify_open(&mut st, Some("ENOENT".to_string())),
                OpenAction::Retry {
                    verdict: LogVerdict::Quiet
                },
                "repeat identical failures must be Quiet"
            );
        }
    }

    #[test]
    fn classify_open_recovery_returns_proceed_info_recovered() {
        // After the failure clears, the next success must produce a
        // Proceed with InfoRecovered so the collector can log the
        // recovery INFO line.
        let mut st = OpenLogState::new();
        classify_open(&mut st, Some("ENOENT".to_string()));
        assert_eq!(
            classify_open(&mut st, None),
            OpenAction::Proceed {
                verdict: Some(LogVerdict::InfoRecovered)
            }
        );
        // Subsequent successes are quiet again.
        assert_eq!(
            classify_open(&mut st, None),
            OpenAction::Proceed { verdict: None }
        );
    }

    #[test]
    fn classify_open_different_error_returns_retry_warn_different() {
        // ENOENT then EACCES: caller should re-WARN because the failure
        // mode changed. This is distinct from a steady-state retry.
        let mut st = OpenLogState::new();
        classify_open(&mut st, Some("ENOENT".to_string()));
        assert_eq!(
            classify_open(&mut st, Some("EACCES".to_string())),
            OpenAction::Retry {
                verdict: LogVerdict::WarnDifferentErr
            }
        );
    }

    // ── log_instruction_for anchors ────────────────────────────────────
    //
    // Pin the verdict → log-level translation. This is the helper the
    // collector loops actually call; the AUDIT-010 fix relies on every
    // distinct verdict producing a distinct log level (and only one of
    // them being WARN). Tests exhaustively enumerate every variant so a
    // future refactor that re-routes Quiet to WarnCannotOpen (which would
    // resurrect the prod log flood) fails at test time, not in the
    // operator's `journalctl` query.

    #[test]
    fn log_instruction_proceed_steady_success_is_none() {
        // Ok open + no prior failure: emit nothing at default level.
        // Anti-regression for accidentally turning every healthy poll
        // into an INFO line (would trade the AUDIT-010 spam for
        // success-noise).
        assert_eq!(
            log_instruction_for(&OpenAction::Proceed { verdict: None }),
            LogInstruction::None
        );
    }

    #[test]
    fn log_instruction_proceed_recovery_is_info() {
        // Ok open after a failure: emit the recovery INFO line that pairs
        // with the WARN the operator saw earlier.
        assert_eq!(
            log_instruction_for(&OpenAction::Proceed {
                verdict: Some(LogVerdict::InfoRecovered),
            }),
            LogInstruction::InfoRecovered
        );
    }

    #[test]
    fn log_instruction_retry_first_failure_is_warn() {
        // The canonical AUDIT-010 anchor: first failure produces WARN, not
        // anything quieter. If this drops to Debug the operator stops
        // seeing nginx outages until they grep for it - which was the
        // pre-Wave-9f anti-pattern in reverse.
        assert_eq!(
            log_instruction_for(&OpenAction::Retry {
                verdict: LogVerdict::WarnNewFailure,
            }),
            LogInstruction::WarnCannotOpen
        );
    }

    #[test]
    fn log_instruction_retry_different_error_is_warn() {
        // ENOENT then EACCES: the new error class is operator-visible
        // because the failure mode changed. WARN both times.
        assert_eq!(
            log_instruction_for(&OpenAction::Retry {
                verdict: LogVerdict::WarnDifferentErr,
            }),
            LogInstruction::WarnCannotOpen
        );
    }

    #[test]
    fn log_instruction_retry_quiet_is_debug_suppressed() {
        // The whole point of Wave 9f: repeat identical failures must NOT
        // flood the default-level journal. They go to debug! so trace-
        // level operators can still see them, but `journalctl -p warning`
        // stays quiet. Anti-regression for collapsing this back to
        // `WarnCannotOpen`.
        assert_eq!(
            log_instruction_for(&OpenAction::Retry {
                verdict: LogVerdict::Quiet,
            }),
            LogInstruction::DebugSuppressed
        );
    }

    #[test]
    fn log_instruction_retry_recovered_falls_back_to_debug_in_release() {
        // Defensive: classify_open guarantees Retry never carries
        // InfoRecovered, but if the contract is ever broken (e.g. a
        // future verdict variant added without updating classify_open)
        // we want the *quietest* log level, not WARN. In debug builds the
        // debug_assert fires; in release builds we silently continue.
        // This test runs in debug (cfg(test) implies debug) so we use
        // `std::panic::catch_unwind` to avoid the assertion taking down
        // the test binary.
        let result = std::panic::catch_unwind(|| {
            log_instruction_for(&OpenAction::Retry {
                verdict: LogVerdict::InfoRecovered,
            })
        });
        match result {
            Ok(instruction) => assert_eq!(instruction, LogInstruction::DebugSuppressed),
            Err(_) => {
                // debug_assert! fired - release-mode behaviour is what
                // we test in unwind-safe form here.
            }
        }
    }

    #[test]
    fn log_instruction_proceed_with_warn_verdict_falls_back_to_none_in_release() {
        // Defensive symmetry: a Warn* verdict on a Proceed path is
        // unreachable per classify_open's contract, but if the contract
        // ever drifts we want None (no log) rather than WARN.
        let result = std::panic::catch_unwind(|| {
            log_instruction_for(&OpenAction::Proceed {
                verdict: Some(LogVerdict::WarnNewFailure),
            })
        });
        match result {
            Ok(instruction) => assert_eq!(instruction, LogInstruction::None),
            Err(_) => {
                // debug_assert! fired - acceptable.
            }
        }
    }

    #[test]
    fn log_instruction_end_to_end_through_classify_open() {
        // End-to-end shape: feed the state machine, take its OpenAction,
        // ask the helper for the log level. Pin the FULL chain (state →
        // classify_open → log_instruction_for) for the canonical sequence
        // an unhealthy nginx mount produces in prod.
        let mut st = OpenLogState::new();
        let err = "ENOENT".to_string();

        // First failure: WARN
        let a1 = classify_open(&mut st, Some(err.clone()));
        assert_eq!(log_instruction_for(&a1), LogInstruction::WarnCannotOpen);

        // 100 retries, all suppressed to DEBUG
        for _ in 0..100 {
            let a = classify_open(&mut st, Some(err.clone()));
            assert_eq!(log_instruction_for(&a), LogInstruction::DebugSuppressed);
        }

        // Recovery: INFO
        let a_rec = classify_open(&mut st, None);
        assert_eq!(log_instruction_for(&a_rec), LogInstruction::InfoRecovered);

        // Subsequent successes: None
        let a_quiet = classify_open(&mut st, None);
        assert_eq!(log_instruction_for(&a_quiet), LogInstruction::None);

        // Second failure episode: WARN again
        let a2 = classify_open(&mut st, Some(err));
        assert_eq!(log_instruction_for(&a2), LogInstruction::WarnCannotOpen);
    }

    #[test]
    fn log_verdict_display_matches_log_level_naming() {
        // Display is operator-facing (used in trace fields when the
        // collector wants to label the verdict in a debug log). Pin the
        // strings so a future rename does not silently break greps in
        // operator runbooks.
        assert_eq!(LogVerdict::Quiet.to_string(), "quiet");
        assert_eq!(LogVerdict::WarnNewFailure.to_string(), "warn-new-failure");
        assert_eq!(
            LogVerdict::WarnDifferentErr.to_string(),
            "warn-different-err"
        );
        assert_eq!(LogVerdict::InfoRecovered.to_string(), "info-recovered");
    }
}
