# Dashboard Threat Model

**Scope.** The InnerWarden agent's HTTP dashboard (`crates/agent/src/dashboard/`) — what it defends against, what it does not, and where each control fires. Last updated 2026-05-03 with PR #422 (Wave 4a telemetry + operator-field polish). This doc is meant to ground reviewers, future maintainers, and Scorecard auditors. It is intentionally short and concrete; everything here is verifiable in source.

---

## Surfaces

| Router | Auth | CSRF | Body limit | Bind |
|--------|------|------|------------|------|
| `dashboard` (operator UI + state-changing endpoints) | required (Basic + Bearer) | yes | 1 MiB | configurable, defaults to 127.0.0.1 |
| `agent_api` (`/api/agent/*` for autonomous AI agents) | configurable per `should_require_api_auth` | n/a | 1 MiB | same |
| `auth_login` (`POST /api/auth/login`) | none (this *is* the auth endpoint) | n/a | 1 MiB | same |
| `live_api` (`/api/live-feed/*` public read-only) | none | n/a | 1 MiB | same |

Layers are stacked at `serve()` in `mod.rs`. Order at construction time: `auth_layer` → `csrf_protection` → router merge → `build_body_limit_layer` → `security_headers` → `activity_layer` → `rate_limit_layer`.

---

## Adversaries we defend against

### 1. Network attacker (no credentials)

- Reaches the bind address but has no Basic Auth secret and no session token.
- Read attempts on the dashboard router → `require_auth` → `unauthorized_response()` (401).
- Any rate of attempts → `rate_limit_layer` (300 req/min/IP, see `GLOBAL_RATE_LIMIT_PER_MIN`) → 429.
- Failed-login storm → `is_rate_limited` (per-IP failed-login window) → 429 even before argon2 runs.

**Not defended:** the public `live_api` is intentionally open. Sanitisation in `live_feed.rs` strips `host`, `evidence`, `recommended_checks`, and filters `is_internal` / `research_only` incidents. If the operator ever adds a field that leaks internal state, this assumption breaks.

### 2. Authenticated browser victim (CSRF)

- Operator logged in to dashboard. Visits a malicious site that submits a hidden `<form action="https://dashboard/api/action/...">`.
- Browser auto-attaches Basic Auth credentials → request would otherwise succeed.
- **Defence:** `csrf_protection` middleware on the dashboard router rejects POST/PUT/PATCH/DELETE without `X-Requested-With: XMLHttpRequest`. Cross-origin forms cannot set this header without a CORS preflight, and the dashboard rejects preflights (no `Access-Control-Allow-Origin` configured for state-changing routes).
- **Test anchor:** `csrf_protection_rejects_post_without_header` in `dashboard/mod.rs`.

**Not defended:** GET endpoints are exempt from CSRF (read-only, idempotent). If a future GET endpoint changes state, this assumption breaks — keep new state-mutation routes on POST.

### 3. Hijacked PR / malicious commit (last-push approval)

- Reviewer approves the PR. Attacker (or compromised contributor) pushes a follow-up commit just before merge.
- Without `require_last_push_approval`, the PR still shows green and merges with the new commit.
- **Defence:** Repository ruleset `Branch protection for protected branches` (after `scripts/update-branch-protection.sh` runs) sets `require_last_push_approval = true` and `dismiss_stale_reviews_on_push = true`.
- **Defence (CODEOWNERS):** `require_code_owner_review = true` on critical paths (`crates/agent/src/dashboard/`, `crates/agent/src/skills/`, `crates/sensor/src/detectors/`, `.github/workflows/`, `scripts/deploy-prod.sh`).

### 4. Privileged operator action without 2FA (account compromise replay)

- Attacker replays a leaked Basic Auth credential to clear orphan responses or block IPs.
- **Defence:** when `[security].method = "totp"` and `totp_secret` is set, the orphan-resolution endpoints call `verify_dashboard_totp` which gates on a fresh 6-digit TOTP. The other action endpoints (`block-ip`, `suspend-user`, etc.) currently rely only on auth + dry-run config — extending 2FA to those is a follow-up.
- **Test anchor:** `verify_dashboard_totp_*` tests in `dashboard/agent_api.rs`.

**Not defended:** if the attacker also captures a fresh TOTP code (e.g. operator phished into typing it on a fake login page), the protection lapses. We do not bind TOTP to the session origin — this is a classic limitation of plain TOTP without WebAuthn.

### 5. Exhaustion via large request bodies (DoS)

- `DefaultBodyLimit::max(MAX_BODY_BYTES)` = 1 MiB on every route.
- Test anchor: `body_limit_layer_rejects_oversized_post` in `dashboard/mod.rs`.

### 6. Path injection / canonical-path escape (CWE-22)

- Every disk-touching dashboard helper canonicalises the data dir and asserts the joined path stays inside before reading or writing. Applied in:
  - `append_orphan_resolution` / `read_orphan_resolutions` (PR #420 Wave 3 + PR #420 follow-up).
  - `enumerate_orphans_from_responses_json` consumers (PR #419 Wave 2).
  - `append_admin_action` in `crates/core/src/audit.rs`.
- **Defence intent:** even if a future feature accepts a partially user-controlled filename, the canonical-prefix check stops the read.

---

## Audit + observability

| Surface | Source | Format |
|---------|--------|--------|
| Operator actions | `admin-actions-YYYY-MM-DD.jsonl` | hash-chained, viewable on Compliance tab |
| Orphan resolutions | `orphan_resolutions.jsonl` (sidecar) | append-only, last-wins per id |
| AI / auto decisions | `decisions-YYYY-MM-DD.jsonl` | hash-chained |
| Prometheus metrics | `GET /metrics` | text exposition |

PR #422 added `innerwarden_orphan_resolutions_total{kind}` — a non-zero rate against a flat orphaned counter signals "operator is keeping up with maintenance debt" (good); flat both = "drift accumulating" (bad).

---

## What is *not* in the threat model

- **Side-channel attacks on argon2 verify** — we use a 5-minute hot-path cache (`VerifiedCache`) to skip the 64 MiB working buffer; an attacker with sub-second timing access to the bind socket could in theory measure cache hit/miss and learn whether a credential is currently valid. Mitigated by rate limiting per IP.
- **TLS termination** — the dashboard speaks plaintext HTTP if no reverse proxy is in front. Operators on non-loopback binds are warned at boot. `--insecure-no-tls` is required to skip TLS bootstrap.
- **Kernel-level rootkit reading the agent process memory** — the agent's eBPF self-defence detects unauthorised attach-to-self attempts but cannot defend against a kernel that's already been replaced.

---

## How to extend this

When adding a new state-changing dashboard endpoint:

1. Register the route on the auth-protected `dashboard` router. The CSRF middleware fires automatically.
2. If the action affects production state (block, kill, deny, dismiss), gate it on `verify_dashboard_totp(&state, &body.totp)` and write an `AdminActionEntry` to the audit chain.
3. Extract the operator name via `Option<axum::Extension<AuthenticatedUser>>` rather than hardcoding a string. The newtype is in `dashboard/auth.rs`.
4. Add a Prometheus counter so alerting can see the rate of operator decisions of this kind.
5. Add a source-grep anchor test in `dashboard::tests` that pins the route + middleware so a future refactor that drops the middleware fails CI.

When adding a new GET endpoint that may eventually change state, keep it on POST from the start to avoid retrofitting CSRF.
