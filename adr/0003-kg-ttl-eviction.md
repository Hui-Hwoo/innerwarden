# 0003 — Knowledge Graph TTL eviction

**Status**: Accepted
**Date**: 2026-05-03
**Author**: @esteves-uk
**Files**: `crates/agent/src/knowledge_graph/graph.rs`, `crates/agent/src/knowledge_graph/persistence.rs`

## Context

The agent's in-memory `KnowledgeGraph` ingests every sensor event (auth, network, file, exec, sigma, yara, etc.) and incident as nodes + edges. On a moderately-busy host, that is 10k–50k events/day, 100–500 incidents/day, 50–200 unique attacker IPs/day. Without bounds, the graph would grow until OOM-killed.

Three uses depend on the graph:
1. **Dashboard journey view** — operator clicks an IP in the Threats tab → walk the graph to assemble the story (incidents, decisions, related events).
2. **Cross-layer correlation** — `correlation_engine` walks the graph for multi-stage attack chain detection.
3. **Detector logic** — some graph-based detectors (e.g. `graph_data_exfil`, `graph_discovery_burst`) walk the graph for pattern matching.

All three need recent data quickly. None of them need three-month-old data in the in-memory representation — that's what JSONL + SQLite are for. The cost of keeping older data in RAM is real (audit RC-2 found `enforce_memory_limit` allocating O(N×E) under memory pressure when called late), and the operator-visible benefit is approximately zero.

## Decision

The graph evicts nodes and edges by age. Default thresholds:

- **Edges**: 24h since last touch. Older edges are dropped on the next `enforce_memory_limit` sweep.
- **Nodes**: 7 days since last touch, AND no remaining edges. Both conditions required so a node mentioned by a recent edge stays even if it's old itself.
- **Memory cap**: configurable upper bound, sweep runs proactively when crossed.

The lifecycle's `total_*` counters live OUTSIDE the graph and are not subject to TTL — they're audit numbers, not graph state.

## Alternatives considered

**Persist everything to disk, no in-memory cap**: would solve OOM but make every dashboard journey query a SQLite walk. Audit measured this: cold journey query on a 90-day store was 3+ seconds, vs <50ms on the in-memory graph. The operator clicks journey rows often during incident triage; latency matters.

**LRU instead of TTL**: more uniform memory bound, but harder to reason about ("this node is old, will it be there?"). TTL gives the operator a deterministic answer: "anything in the last 24h is in the graph; older than that, look at JSONL or SQLite." The Phase-8 SQLite fallback in `build_journey_from_graph` handles the post-TTL case.

**Persist a graph snapshot to disk, replay on boot**: the existing `to_snapshot` / `from_snapshot` pattern. Used at boot but not as a primary cap mechanism — replay is slow (>5s on busy hosts) and we don't want to pay that on every memory-pressure sweep.

## Consequences

**Easier**:
- Memory bounded predictably. Operator can plan capacity.
- Hot path queries (journey view, correlation engine) stay fast.
- Code that needs older data has a clear escalation path: check graph first, fall back to SQLite (`build_journey_from_graph` is the canonical example).

**Harder**:
- The graph is NOT a complete history. Anyone reading graph snapshots in isolation and assuming "if it's not here, it didn't happen" is wrong. Documented in `dashboard/data_api.rs` (Phase 8 audit fix RC-2).
- Counts derived from the graph are gauges (current state), not counters (lifetime). Anyone expecting "how many X total?" must read the lifetime counters or SQLite. PR #425 Wave 4d codified this distinction in the JSON shape.
- Node IDs are not stable across the graph's lifetime. A Process node evicted yesterday and re-encountered today gets a fresh NodeId. Code that caches NodeIds across long durations must validate them on use.

**Committed**:
- The two-tier design (graph hot, SQLite cold) is now a defining pattern. Future graph features that "need this node forever" must either bump the TTL knob or accept that long-term data lives in SQLite.
- The Phase-8 SQLite fallback in `build_journey_from_graph` is the contract for any new graph-derived dashboard surface — implement the fallback or accept that the surface goes empty for older data.
