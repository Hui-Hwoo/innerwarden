# 0002 — Threat contract layer for cross-surface consistency

**Status**: Accepted
**Date**: 2026-05-03
**Author**: @esteves-uk
**Files**: `crates/agent/src/dashboard/threat_contract.rs`, `consistency_block_counts.rs`, `consistency_incidents_today.rs`

## Context

The dashboard surfaces operator-visible numbers in many places: Home tile ("blocks today"), Threats tab list (per-IP outcome verb), Briefing summary ("N needing action"), Compliance audit, Prometheus `/metrics`, the public `/api/live-feed` for the marketing site. Every surface used to compute its own number from raw data (incidents JSONL, decisions JSONL, knowledge graph walk, SQLite query). Result: divergence.

Real prod observations:

- 2026-04-11: dashboard live feed showed N blocks, marketing site `/live` showed N+3.
- 2026-04-22: Home tile said "21 incidents today", Threats list summed 10. User: "ja teve PR pra corrigir isso, porque nao corrigiu?".
- 2026-05-02: Briefing said "0 needing action", Home tile said "2 awaiting". Auditor flagged this as the #1 release blocker.
- 2026-05-03: Banner said "17 orphaned (rule may still be active)" while JSON had zero entries with `reason: orphaned:`.

Each of these was a different surface computing a similar concept slightly differently. The fix per incident was always to align the two specific surfaces — but the next refactor reintroduced drift because nothing structural prevented it.

## Decision

Every operator-visible number that can be derived from the canonical state goes through `dashboard/threat_contract.rs`. Each conceptual quantity has exactly one function that produces it:

- `classify_decision(action, result) -> &'static str` — canonical mapping of `(decision.action_type, decision.execution_result)` to one of `blocked` / `dismissed` / `monitoring` / `honeypot` / `unknown`. Used by Home, Threats, Briefing, Compliance.
- `aggregate_outcomes(outcomes: Vec<&str>) -> &'static str` — given a multi-event journey, the single outcome the operator sees.
- `OverviewSnapshot` (in `dashboard/types.rs`) — frozen-in-time aggregate counts. Built once in `compute_overview_counts_from_sqlite`. Every Home/Briefing/Threats consumer reads from this snapshot, never recomputes.
- The new Wave 4d split between `gauges.*` (current) and `totals.*` (lifetime) in `response_lifecycle::to_json` extends the same idea to gauge-vs-counter semantics.

Anchor tests sit in `consistency_block_counts.rs` and `consistency_incidents_today.rs`. Each instantiates a fixture KG + SQLite store and asserts every named consumer returns the same number. CI failure here means a refactor reintroduced drift; the standing rule is to fix by routing through the contract, never by silencing the assertion.

## Alternatives considered

**Each surface computes from raw data, with code review catching drift**: how it was before. Did not work — drift slipped through every refactor. Code review cannot reliably notice "this query returns 1 less than that other query for fixture Y."

**Macro-generated query templates**: a single SQL macro that every surface invokes with parameters. Rejected because the surfaces actually need different shapes (some need timeline grouping, some need per-attacker rollup), and a macro that handles all shapes is harder to read than a small helper module.

**Force every surface to call the snapshot only**: stricter than current decision. Some surfaces legitimately need fresh-from-disk data (Briefing reads a snapshot but augments with KG narrative walk; Threats list filters by severity threshold). Allowing those surfaces to read raw data + classifier helpers is the pragmatic middle.

## Consequences

**Easier**:
- Adding a new operator-visible surface is mechanical: import from `threat_contract`, write the surface-specific layout, rely on the contract for the numbers.
- Bug reports of the form "X disagrees with Y" have a known fix shape: the contract layer should already resolve them; if it does not, extend the contract.
- Anchor tests catch drift the moment a PR introduces it.

**Harder**:
- Anyone who genuinely needs a number that is NOT in the contract has friction. They must extend the contract (with a test) instead of computing inline. That's the point but it's friction.
- The contract module grows over time. Each new function has cognitive cost for new contributors.

**Committed**:
- Operator-visible numbers are a controlled surface. Any future "AI hallucinates a count" or "feed shows different N from list" goes here first.
- Wave 4d's `gauges` vs `totals` split is now a precedent — future state-vs-counter distinctions follow the same pattern.
