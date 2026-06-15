// Dashboard 2FA approval endpoints (Issue #71)
//
// Three REST endpoints that mirror the Telegram TOTP approval flow so
// operators can approve or deny sensitive-action requests directly from
// the dashboard without relying on the Telegram bot.
//
// Endpoints:
//   GET  /api/2fa/pending                   — list pending requests + deadlines
//   POST /api/2fa/approve/{approval_id}     — approve (session token + TOTP)
//   POST /api/2fa/deny/{approval_id}        — reject approval
//
// Security model:
//   All three endpoints sit behind the standard `auth_layer` (Basic / Bearer
//   session token). The approve endpoint additionally requires a valid TOTP
//   code when `[security].method = "totp"` — same gate as orphan-resolution
//   and trust-exec. The deny endpoint does NOT require TOTP (refusing an
//   action is never dangerous).
//
// Shared state:
//   `DashboardState.pending_approvals` is an `Arc<Mutex<HashMap>>` populated
//   by the main agent loop (via the Telegram flow or a future push path) and
//   consumed here. After approve/deny the entry is removed so the pending list
//   stays clean. A background cleanup task in `serve()` reaps expired entries.

use super::*;

// ---------------------------------------------------------------------------
// GET /api/2fa/pending
// ---------------------------------------------------------------------------

/// Response body for GET /api/2fa/pending.
#[derive(Serialize)]
struct PendingApprovalsResponse {
    total: usize,
    pending: Vec<TwoFaPendingRequest>,
}

/// List all pending 2FA approval requests that have not yet expired.
///
/// Returns an empty list when 2FA is disabled or there are no pending items.
/// Expired entries are filtered out in the response (and lazily pruned from
/// the shared map on the next write).
pub(super) async fn api_2fa_pending(State(state): State<DashboardState>) -> impl IntoResponse {
    let map = state
        .pending_approvals
        .lock()
        .unwrap_or_else(|e| e.into_inner());

    let active: Vec<TwoFaPendingRequest> = map
        .values()
        .filter(|r| !r.is_expired())
        .cloned()
        .collect();

    let total = active.len();
    Json(PendingApprovalsResponse {
        total,
        pending: active,
    })
}

// ---------------------------------------------------------------------------
// POST /api/2fa/approve/{approval_id}
// ---------------------------------------------------------------------------

/// Approve a pending 2FA request.
///
/// Verifies the TOTP code (when 2FA is enforced), removes the entry from the
/// pending map, writes an audit row, and sends the outcome on the result
/// channel so the agent loop can proceed with the guarded action.
pub(super) async fn api_2fa_approve(
    State(state): State<DashboardState>,
    axum::extract::Path(approval_id): axum::extract::Path<String>,
    user: Option<axum::Extension<crate::dashboard::auth::AuthenticatedUser>>,
    Json(body): Json<TwoFaActionRequest>,
) -> Response {
    let operator = user
        .map(|axum::Extension(u)| u.0)
        .unwrap_or_else(|| crate::dashboard::auth::AuthenticatedUser::ANONYMOUS.to_string());
    // Validate TOTP before touching the pending map.
    if let Err(e) = crate::dashboard::agent_api::verify_dashboard_totp(&state, &body.totp) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": e })),
        )
            .into_response();
    }

    // Remove the entry atomically — only proceed if it exists and is not expired.
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

    // Audit trail.
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
        "2FA approval granted via dashboard"
    );

    // Notify the agent loop (best-effort; `try_send` is fire-and-forget).
    if let Some(tx) = &state.approval_outcome_tx {
        let _ = tx.try_send(DashboardApprovalOutcome {
            approval_id: approval_id.clone(),
            incident_id: request.incident_id.clone(),
            approved: true,
            operator,
            totp_supplied: body.totp,
        });
    }

    Json(serde_json::json!({
        "approved": true,
        "approval_id": approval_id,
        "incident_id": request.incident_id,
    }))
    .into_response()
}

// ---------------------------------------------------------------------------
// POST /api/2fa/deny/{approval_id}
// ---------------------------------------------------------------------------

/// Deny a pending 2FA request.
///
/// Does NOT require a TOTP code — refusing an action is never dangerous.
/// Removes the entry from the pending map, writes an audit row, and sends
/// the deny outcome on the result channel.
pub(super) async fn api_2fa_deny(
    State(state): State<DashboardState>,
    axum::extract::Path(approval_id): axum::extract::Path<String>,
    user: Option<axum::Extension<crate::dashboard::auth::AuthenticatedUser>>,
    Json(body): Json<TwoFaActionRequest>,
) -> Response {
    let operator = user
        .map(|axum::Extension(u)| u.0)
        .unwrap_or_else(|| crate::dashboard::auth::AuthenticatedUser::ANONYMOUS.to_string());
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

    // Audit trail.
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
                "reason": body.reason,
            }),
            result: "denied".into(),
            prev_hash: None,
        },
    );

    info!(
        operator = %operator,
        approval_id = %approval_id,
        incident_id = %request.incident_id,
        "2FA approval denied via dashboard"
    );

    if let Some(tx) = &state.approval_outcome_tx {
        let _ = tx.try_send(DashboardApprovalOutcome {
            approval_id: approval_id.clone(),
            incident_id: request.incident_id.clone(),
            approved: false,
            operator,
            totp_supplied: String::new(),
        });
    }

    Json(serde_json::json!({
        "approved": false,
        "approval_id": approval_id,
        "incident_id": request.incident_id,
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

    #[test]
    fn is_expired_returns_true_past_deadline() {
        let r = make_request("test", true);
        assert!(r.is_expired());
    }

    #[test]
    fn is_expired_returns_false_before_deadline() {
        let r = make_request("test", false);
        assert!(!r.is_expired());
    }

    #[test]
    fn pending_approvals_map_insert_and_remove() {
        let store: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, TwoFaPendingRequest>>> =
            std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));

        let req = make_request("abc", false);
        store.lock().unwrap().insert("abc".to_string(), req.clone());

        {
            let map = store.lock().unwrap();
            assert!(map.contains_key("abc"));
            assert_eq!(map["abc"].incident_id, "inc-abc");
        }

        store.lock().unwrap().remove("abc");
        assert!(store.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn api_2fa_pending_returns_empty_when_no_requests() {
        let dir = tempfile::tempdir().unwrap();
        let state = crate::dashboard::state::test_dashboard_state(dir.path());
        let resp = api_2fa_pending(State(state)).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
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
}
