# 0001 — Orphan resolution sidecar JSONL

**Status**: Accepted
**Date**: 2026-05-03
**Author**: @esteves-uk
**PR**: #420 (Wave 3)

## Context

The agent's `ResponseLifecycle` (in `crates/agent/src/response_lifecycle.rs`) tracks every active response action (block_ip, suspend_user, etc.) plus a bounded history of completed entries. When a revert command exhausts retries, the lifecycle marks the entry as `orphaned` and the dashboard surfaces it for operator review.

Wave 3 needed an action endpoint where the operator could resolve an orphan (clear it, or mark it as "already gone in the kernel"). The natural-looking design — mutate the same `ResponseLifecycle` instance the agent loop owns — has a hard problem: the agent loop holds the lifecycle mutably and persists it to `responses.json` on every slow tick (~30s). If the dashboard handler mutated the same struct, either:

1. The dashboard would need a `Arc<RwLock<ResponseLifecycle>>` that the agent loop also holds, requiring touching every existing call site (large blast radius).
2. The dashboard would mutate `responses.json` on disk directly, but the agent loop would overwrite that change on the next persist tick — race window of 30 seconds.
3. The dashboard would send an `mpsc` command to the agent loop, which applies the mutation. Adds a new channel, new event loop arm, new error handling per command type.

None of these were proportional to "let the operator click 'mark this orphan resolved' on the dashboard."

## Decision

Resolutions live in a separate file, `<data_dir>/orphan_resolutions.jsonl`, owned exclusively by the dashboard. Append-only JSONL: one line per resolution, last-wins per `orphan_id` if the operator changes their mind. The dashboard's `GET /api/responses/orphans` reads both `responses.json` (orphans) and `orphan_resolutions.jsonl` (resolutions) and joins them at read time, surfacing each orphan with a `resolution: null | { kind, reason, operator, resolved_at }` field. The agent loop never reads this sidecar — it does not need to.

Append uses POSIX `O_APPEND` atomicity for short writes (one resolution line is ~250 B, well under `PIPE_BUF=4096`), so concurrent dashboard clicks cannot interleave half-written JSON. No `flock` ceremony.

## Alternatives considered

**`Arc<RwLock<ResponseLifecycle>>`**: cleaner state model. Rejected because the agent loop's existing `&mut state.response_lifecycle` borrows are deep — adding a write lock at every call site changes the function signatures across `loops/boot.rs`, `killchain_inline.rs`, and 6 other files. Wave 3 was already a large PR.

**Mutate `responses.json` directly + skip the next agent persist tick**: rejected because it requires the dashboard to know about the agent's persist cadence, and "skip the next persist" is a coordination signal (tokio mpsc, atomic flag) that adds the complexity we were trying to avoid.

**Add a column to the SQLite `decisions` table for "operator resolution"**: SQLite is the canonical store for `incidents` and `decisions`; mirroring orphan resolutions there is consistent. Rejected for now because it would require a schema migration and the resolutions are conceptually a separate audit artifact (operator decision about a dashboard surface, not an AI decision about an incident). Reconsider if Wave 4d-discipline grows.

## Consequences

**Easier**:
- Wave 3 PR was small and easy to review (no shared state model changes).
- Resolutions are independently auditable — `cat orphan_resolutions.jsonl` shows the full operator decision history without parsing the lifecycle JSON.
- The agent loop is unchanged. No risk of regression in the hot path.

**Harder**:
- Two sources of truth for "what's the state of orphan X?" — `responses.json` for the entry, `orphan_resolutions.jsonl` for the operator decision. Read paths must always join. The Wave 4d-banner work showed how this kind of split causes drift if any consumer reads only one source.
- Backup / disaster-recovery scripts must include the sidecar. Documented in `THREAT_MODEL.md`.

**Committed**:
- Operator-visible orphan resolution flow runs entirely in the dashboard process; the agent loop is not in the critical path. If the agent crashes, resolutions persist.
- Future "graph-aware orphan replay" (re-run revert from the dashboard) would need to coordinate with the agent — likely via the channel pattern we deferred. ADR will be amended at that time.
