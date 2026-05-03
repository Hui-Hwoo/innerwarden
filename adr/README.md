# Architecture Decision Records

Short, dated rationales for non-obvious design choices. Read these before reverting or "simplifying" an unusual pattern — there is almost always a buried reason. Format mirrors [Michael Nygard's classic ADR template](https://github.com/joelparkerhenderson/architecture-decision-record).

The point of an ADR is not to document what the code does — read the code for that. The point is to capture **why** and **what alternatives were considered**, so the next person (often future-you) does not undo the decision without understanding the cost.

## Index

- [0001 — Orphan resolution sidecar JSONL](0001-orphan-resolution-sidecar-jsonl.md) — why dashboard mutations of orphan state live in a sidecar file rather than mutating `responses.json` directly.
- [0002 — Threat contract layer for cross-surface consistency](0002-threat-contract-layer.md) — why every operator-visible number routes through `dashboard/threat_contract.rs` instead of being computed at each surface.
- [0003 — Knowledge Graph TTL eviction](0003-kg-ttl-eviction.md) — why the in-memory graph caps memory by ageing nodes/edges out instead of growing unbounded or persisting everything.

## When to write a new ADR

- A reviewer asks "why did you do it this way instead of X?" and the answer is non-trivial → write the ADR.
- You override a default behavior (config flag, library convention, common pattern).
- You pick storage / threading / locking / serialization in a way that surprises the next reader.
- You document a deliberately-not-fixed bug class (rate limit not perfect because Y is more painful).

## When NOT to write an ADR

- Documenting what a function does — that belongs in the function's doc comment.
- Recording a date-bound state ("we shipped X today") — that's `.claude-local/SESSION_LOG.md`.
- Capturing a recurring bug class — that's `.claude-local/RECURRING_BUGS.md`.
- A small style or naming choice — that's a code review comment.

## Format

```markdown
# NNNN — Short title

**Status**: Accepted | Superseded by NNNN | Deprecated
**Date**: YYYY-MM-DD
**Author**: <handle>

## Context

What forces are at play. What we observed in production. What the operator
asked for. Numbers if they exist. No solution yet — just the problem.

## Decision

What we're going to do. One paragraph. Specific.

## Alternatives considered

Each alt: one paragraph. Why rejected. Don't strawman — the operator
will read this and decide if your "rejected" alternative is actually
better in their context.

## Consequences

What gets easier. What gets harder. What this commits us to.
What is now hard to revert.
```
