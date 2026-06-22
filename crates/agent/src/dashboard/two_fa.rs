// Dashboard 2FA approval endpoints (Issue #71)
//
// Three REST endpoints that mirror the Telegram TOTP approval flow so
// operators can approve or deny sensitive-action requests directly from
// the dashboard without relying on the Telegram bot.
//
// Endpoints:
//   GET  /api/2fa/pending                   — list pending requests + deadlines
//   POST /api/2fa/approve/:approval_id      — approve (session token + TOTP)
//   POST /api/2fa/deny/:approval_id         — reject approval (no TOTP needed)
//
// Security model:
//   All three endpoints sit behind the standard `auth_layer` (Basic / Bearer
//   session token) and the `csrf_protection` middleware (requires the
//   `X-Requested-With: XMLHttpRequest` header on state-changing requests).
//
//   The approve endpoint additionally requires a valid TOTP code when
//   `[security].method = "totp"` — same gate as orphan-resolution and
//   trust-exec. The deny endpoint does NOT require TOTP: refusing a guarded
//   action can never cause harm.
//
// Shared state:
//   `DashboardState.pending_approvals` is an `Arc<Mutex<HashMap>>` that the
//   main agent loop populates when a sensitive operation needs confirmation.
//   Handlers remove entries on approve/deny; a background task in `serve()`
//   prunes entries whose deadline has passed.
//
// Design considerations:
//   - We intentionally do NOT validate the TOTP code before confirming the
//     approval_id exists (see `api_2fa_approve`). TOTP validation against
//     a non-existent ID is a wasted computation but not a security issue
//     because the endpoints are already auth-gated. The order chosen here
//     (validate ID → validate TOTP → remove) avoids silent discard of a
//     valid entry if the caller sends a wrong ID.
//   - `DashboardApprovalOutcome.totp_verified` is a boolean, not the raw
//     code, to comply with CWE-532 (no credentials in log/struct fields).
//   - The deny body (`reason`) is optional — clients that send no body at
//     all still receive a 200, preventing brittle API contract violations.

use super::*;

/// Maximum length for an `approval_id` path segment (mirrors orphan-id limit).
const MAX_APPROVAL_ID_LEN: usize = 128;

// ---------------------------------------------------------------------------
// GET /api/2fa/pending
// ---------------------------------------------------------------------------

/// Response body for `GET /api/2fa/pending`.
#[derive(Serialize)]
struct PendingApprovalsResponse {
    total: usize,
    pending: Vec<TwoFaPendingRequest>,
}

/// List all non-expired pending 2FA approval requests.
///
/// Returns an empty list when there are no pending items or when the map has
/// not been populated (e.g. standalone dashboard without the agent loop).
/// Expired entries are filtered in the response; they are lazily pruned from
/// the map by the background cleanup task in `serve()`.
pub(super) async fn api_2fa_pending(State(state): State<DashboardState>) -> impl IntoResponse {
    let map = state
        .pending_approvals
        .lock()
        .unwrap_or_else(|e| e.into_inner());

    let mut active: Vec<TwoFaPendingRequest> = map
        .values()
        .filter(|r| !r.is_expired())
        .cloned()
        .collect();

    // Sort by deadline ascending so the most time-critical request is first.
    active.sort_by_key(|r| r.deadline);

    let total = active.len();
    Json(PendingApprovalsResponse {
        total,
        pending: active,
    })
}

// ---------------------------------------------------------------------------
// POST /api/2fa/approve/:approval_id
// ---------------------------------------------------------------------------

/// Approve a pending 2FA request.
///
/// Order of operations (important for correctness and auditability):
///   1. Validate `approval_id` format.
///   2. Peek at the map to confirm the entry exists and is not yet expired
///      **before** validating the TOTP code — prevents silent discard of a
///      valid entry caused by a caller typo in the ID.
///   3. Validate TOTP code (when enforcement is on).
///   4. Remove the entry atomically so a second concurrent approve cannot
///      double-fire.
///   5. Write audit row.
///   6. Notify agent loop via `approval_outcome_tx` (best-effort).
pub(super) async fn api_2fa_approve(
    State(state): State<DashboardState>,
    axum::extract::Path(approval_id): axum::extract::Path<String>,
    user: Option<axum::Extension<crate::dashboard::auth::AuthenticatedUser>>,
    Json(body): Json<TwoFaActionRequest>,
) -> Response {
    // ── 1. Validate approval_id format ──────────────────────────────────
    if approval_id.is_empty() || approval_id.len() > MAX_APPROVAL_ID_LEN {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid approval_id" })),
        )
            .into_response();
    }

    // ── 2. Peek — confirm entry exists and is not yet expired ────────────
    // We hold the lock only long enough to clone what we need, then release
    // it before the TOTP verification (which can be slow on the argon2 path).
    let peek = {
        let map = state
            .pending_approvals
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        map.get(&approval_id).cloned()
    };

    let Some(request) = peek else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "approval request not found or already resolved"
            })),
        )
            .into_response();
    };

    if request.is_expired() {
        // Remove the stale entry while we have the chance.
        state
            .pending_approvals
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&approval_id);
        return (
            StatusCode::GONE,
            Json(serde_json::json!({ "error": "approval request has expired" })),
        )
            .into_response();
    }

    // ── 3. Validate TOTP ────────────────────────────────────────────────
    if let Err(e) = crate::dashboard::agent_api::verify_dashboard_totp(&state, &body.totp) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": e })),
        )
            .into_response();
    }

    // ── 4. Remove atomically (second caller gets NOT_FOUND) ─────────────
    let removed = state
        .pending_approvals
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&approval_id);

    // Guard against a TOCTOU race where another request removed it between
    // our peek and this remove (extremely unlikely but handled for safety).
    if removed.is_none() {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": "approval request was resolved concurrently"
            })),
        )
            .into_response();
    }

    let operator = user
        .map(|axum::Extension(u)| u.0)
        .unwrap_or_else(|| crate::dashboard::auth::AuthenticatedUser::ANONYMOUS.to_string());

    // ── 5. Audit trail ───────────────────────────────────────────────────
    let _ = innerwarden_core::audit::append_admin_action(
        &state.data_dir,
        &mut innerwarden_core::audit::AdminActionEntry {
            ts: Utc::now(),
            operator: operator.clone(),
            source: "dashboard".into(),
            action: "2fa_approve".into(),
            target: approval_id.clone(),
            parameters: serde_json::json!({
                "incident_id": request.incident_id,
                "action_description": request.action_description,
                "detector": request.detector,
                "two_factor": if state.two_factor.is_enforced() { "enforced" } else { "none" },
            }),
            result: "success".into(),
            prev_hash: None,
        },
    );

    info!(
        operator = %operator,
        approval_id = %approval_id,
        incident_id = %request.incident_id,
        detector = %request.detector,
        "2FA approval granted via dashboard",
    );

    // ── 6. Notify agent loop ─────────────────────────────────────────────
    // `try_send` is intentionally fire-and-forget: the agent loop drains
    // this channel on its next tick. A full channel means the loop is busy;
    // the operator can retry if needed (the request is already removed so a
    // retry will get NOT_FOUND and know the decision was recorded).
    if let Some(tx) = &state.approval_outcome_tx {
        let _ = tx.try_send(DashboardApprovalOutcome {
            approval_id: approval_id.clone(),
            incident_id: request.incident_id.clone(),
            approved: true,
            operator,
            totp_verified: true,
        });
    }

    Json(serde_json::json!({
        "approved": true,
        "approval_id": approval_id,
        "incident_id": request.incident_id,
        "action_description": request.action_description,
    }))
    .into_response()
}

// ---------------------------------------------------------------------------
// POST /api/2fa/deny/:approval_id
// ---------------------------------------------------------------------------

/// Deny a pending 2FA request.
///
/// Does NOT require a TOTP code — refusing a guarded action can never cause
/// harm. The request body is entirely optional: a deny with no JSON body is
/// valid and records an empty reason in the audit row.
///
/// Returns 410 Gone (rather than silently succeeding) when the entry has
/// already expired so operators know the deadline passed.
pub(super) async fn api_2fa_deny(
    State(state): State<DashboardState>,
    axum::extract::Path(approval_id): axum::extract::Path<String>,
    user: Option<axum::Extension<crate::dashboard::auth::AuthenticatedUser>>,
    // Body is optional: `None` when the client sends no body at all.
    body: Option<Json<TwoFaActionRequest>>,
) -> Response {
    // ── 1. Validate approval_id format ──────────────────────────────────
    if approval_id.is_empty() || approval_id.len() > MAX_APPROVAL_ID_LEN {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid approval_id" })),
        )
            .into_response();
    }

    let reason = body
        .map(|Json(b)| b.reason)
        .unwrap_or_default();

    // ── 2. Remove atomically ────────────────────────────────────────────
    let entry = {
        let mut map = state
            .pending_approvals
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        map.remove(&approval_id)
    };

    let Some(request) = entry else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "approval request not found or already resolved"
            })),
        )
            .into_response();
    };

    if request.is_expired() {
        return (
            StatusCode::GONE,
            Json(serde_json::json!({ "error": "approval request has expired" })),
        )
            .into_response();
    }

    let operator = user
        .map(|axum::Extension(u)| u.0)
        .unwrap_or_else(|| crate::dashboard::auth::AuthenticatedUser::ANONYMOUS.to_string());

    // ── 3. Audit trail ───────────────────────────────────────────────────
    let _ = innerwarden_core::audit::append_admin_action(
        &state.data_dir,
        &mut innerwarden_core::audit::AdminActionEntry {
            ts: Utc::now(),
            operator: operator.clone(),
            source: "dashboard".into(),
            action: "2fa_deny".into(),
            target: approval_id.clone(),
            parameters: serde_json::json!({
                "incident_id": request.incident_id,
                "action_description": request.action_description,
                "detector": request.detector,
                "reason": reason,
            }),
            result: "denied".into(),
            prev_hash: None,
        },
    );

    info!(
        operator = %operator,
        approval_id = %approval_id,
        incident_id = %request.incident_id,
        detector = %request.detector,
        "2FA approval denied via dashboard",
    );

    // ── 4. Notify agent loop ─────────────────────────────────────────────
    if let Some(tx) = &state.approval_outcome_tx {
        let _ = tx.try_send(DashboardApprovalOutcome {
            approval_id: approval_id.clone(),
            incident_id: request.incident_id.clone(),
            approved: false,
            operator,
            totp_verified: false,
        });
    }

    Json(serde_json::json!({
        "approved": false,
        "approval_id": approval_id,
        "incident_id": request.incident_id,
        "action_description": request.action_description,
    }))
    .into_response()
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_request(id: &str, expired: bool) -> TwoFaPendingRequest {
        let now = Utc::now();
        let deadline = if expired {
            now - chrono::Duration::minutes(10)
        } else {
            now + chrono::Duration::minutes(30)
        };
        TwoFaPendingRequest {
            id: id.to_string(),
            incident_id: format!("inc-{id}"),
            action_description: format!("block IP for incident {id}"),
            detector: "ssh_brute_force".to_string(),
            created_at: now - chrono::Duration::minutes(5),
            deadline,
        }
    }

    // ── TwoFaPendingRequest::is_expired ──────────────────────────────────

    #[test]
    fn is_expired_returns_true_past_deadline() {
        assert!(make_request("test", true).is_expired());
    }

    #[test]
    fn is_expired_returns_false_before_deadline() {
        assert!(!make_request("test", false).is_expired());
    }

    // ── pending_approvals map mechanics ──────────────────────────────────

    #[test]
    fn pending_approvals_map_insert_and_remove() {
        let store: std::sync::Arc<
            std::sync::Mutex<std::collections::HashMap<String, TwoFaPendingRequest>>,
        > = std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));

        let req = make_request("abc", false);
        store.lock().unwrap().insert("abc".to_string(), req);

        {
            let map = store.lock().unwrap();
            assert!(map.contains_key("abc"));
            assert_eq!(map["abc"].incident_id, "inc-abc");
        }

        store.lock().unwrap().remove("abc");
        assert!(store.lock().unwrap().is_empty());
    }

    // ── GET /api/2fa/pending ─────────────────────────────────────────────

    #[tokio::test]
    async fn api_2fa_pending_returns_empty_when_no_requests() {
        let dir = tempfile::tempdir().unwrap();
        let state = crate::dashboard::state::test_dashboard_state(dir.path());
        let resp = api_2fa_pending(State(state)).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["total"], 0);
        assert!(json["pending"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn api_2fa_pending_filters_expired_requests() {
        let dir = tempfile::tempdir().unwrap();
        let state = crate::dashboard::state::test_dashboard_state(dir.path());

        {
            let mut map = state.pending_approvals.lock().unwrap();
            map.insert("active".to_string(), make_request("active", false));
            map.insert("expired".to_string(), make_request("expired", true));
        }

        let resp = api_2fa_pending(State(state)).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["total"], 1);
        assert_eq!(json["pending"][0]["id"], "active");
    }

    #[tokio::test]
    async fn api_2fa_pending_sorts_by_deadline_ascending() {
        let dir = tempfile::tempdir().unwrap();
        let state = crate::dashboard::state::test_dashboard_state(dir.path());
        let now = Utc::now();

        {
            let mut map = state.pending_approvals.lock().unwrap();
            // "later" has a deadline further in the future than "sooner".
            let mut sooner = make_request("sooner", false);
            sooner.deadline = now + chrono::Duration::minutes(10);
            let mut later = make_request("later", false);
            later.deadline = now + chrono::Duration::minutes(60);
            map.insert("later".to_string(), later);
            map.insert("sooner".to_string(), sooner);
        }

        let resp = api_2fa_pending(State(state)).await.into_response();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["pending"][0]["id"], "sooner");
        assert_eq!(json["pending"][1]["id"], "later");
    }

    // ── approve: approval_id validation ──────────────────────────────────

    #[tokio::test]
    async fn api_2fa_approve_rejects_empty_approval_id() {
        let dir = tempfile::tempdir().unwrap();
        let state = crate::dashboard::state::test_dashboard_state(dir.path());

        let resp = api_2fa_approve(
            State(state),
            axum::extract::Path(String::new()),
            None,
            Json(TwoFaActionRequest::default()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn api_2fa_approve_rejects_oversized_approval_id() {
        let dir = tempfile::tempdir().unwrap();
        let state = crate::dashboard::state::test_dashboard_state(dir.path());
        let long_id = "x".repeat(MAX_APPROVAL_ID_LEN + 1);

        let resp = api_2fa_approve(
            State(state),
            axum::extract::Path(long_id),
            None,
            Json(TwoFaActionRequest::default()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn api_2fa_approve_returns_not_found_for_unknown_id() {
        let dir = tempfile::tempdir().unwrap();
        let state = crate::dashboard::state::test_dashboard_state(dir.path());

        let resp = api_2fa_approve(
            State(state),
            axum::extract::Path("no-such-id".to_string()),
            None,
            Json(TwoFaActionRequest::default()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn api_2fa_approve_returns_gone_for_expired_entry() {
        let dir = tempfile::tempdir().unwrap();
        let state = crate::dashboard::state::test_dashboard_state(dir.path());
        state
            .pending_approvals
            .lock()
            .unwrap()
            .insert("exp".to_string(), make_request("exp", true));

        let resp = api_2fa_approve(
            State(state),
            axum::extract::Path("exp".to_string()),
            None,
            Json(TwoFaActionRequest::default()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::GONE);
    }

    // ── deny: validation and optional body ───────────────────────────────

    #[tokio::test]
    async fn api_2fa_deny_rejects_empty_approval_id() {
        let dir = tempfile::tempdir().unwrap();
        let state = crate::dashboard::state::test_dashboard_state(dir.path());

        let resp = api_2fa_deny(
            State(state),
            axum::extract::Path(String::new()),
            None,
            None,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn api_2fa_deny_accepts_no_body() {
        let dir = tempfile::tempdir().unwrap();
        let state = crate::dashboard::state::test_dashboard_state(dir.path());
        state
            .pending_approvals
            .lock()
            .unwrap()
            .insert("d1".to_string(), make_request("d1", false));

        // body = None — simulates a client that sends no JSON body
        let resp = api_2fa_deny(
            State(state),
            axum::extract::Path("d1".to_string()),
            None,
            None,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["approved"], false);
    }

    #[tokio::test]
    async fn api_2fa_deny_returns_not_found_for_unknown_id() {
        let dir = tempfile::tempdir().unwrap();
        let state = crate::dashboard::state::test_dashboard_state(dir.path());

        let resp = api_2fa_deny(
            State(state),
            axum::extract::Path("ghost".to_string()),
            None,
            None,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn api_2fa_deny_removes_entry_from_map() {
        let dir = tempfile::tempdir().unwrap();
        let state = crate::dashboard::state::test_dashboard_state(dir.path());
        state
            .pending_approvals
            .lock()
            .unwrap()
            .insert("rem".to_string(), make_request("rem", false));

        let resp = api_2fa_deny(
            State(state.clone()),
            axum::extract::Path("rem".to_string()),
            None,
            None,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        // Entry must be gone after deny
        assert!(state
            .pending_approvals
            .lock()
            .unwrap()
            .get("rem")
            .is_none());
    }
}
