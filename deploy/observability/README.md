# Fleet observability (Prometheus + Grafana)

Watch an entire fleet of AI agents in one place. Each host runs an InnerWarden
agent that exposes Prometheus metrics on `https://<host>:8787/metrics`; point
Prometheus at every node and load the Grafana dashboard to see, across the whole
fleet: per-tenant agent activity (each Claude Code = a tenant), decisions and
responses, and the host-level detection underneath.

This is the recommended way to give a team dashboards over many agents —
InnerWarden's built-in dashboard is per-host; Prometheus + Grafana is the
multi-host, multi-tenant view.

## Files

| File | What it is |
|------|------------|
| `grafana-dashboard-fleet.json` | The Grafana dashboard (import it, pick your Prometheus datasource) |
| `prometheus.yml` | Scrape config: a static demo list + a commented Kubernetes SD job |
| `servicemonitor.yaml` | Prometheus Operator `ServiceMonitor` + headless `Service` for a k8s cluster |

## Quick start (single box / demo)

```bash
# 1. Run Prometheus with the scrape config (Docker, or the binary).
docker run -d --name prometheus --network host \
  -v "$PWD/prometheus.yml:/etc/prometheus/prometheus.yml" \
  prom/prometheus

# 2. Run Grafana.
docker run -d --name grafana --network host grafana/grafana

# 3. In Grafana (http://localhost:3000, admin/admin):
#    - add a Prometheus datasource → http://localhost:9090
#    - Dashboards → Import → upload grafana-dashboard-fleet.json → pick the datasource
```

The agent serves `/metrics` over HTTPS with a self-signed cert, so the scrape
config uses `scheme: https` + `insecure_skip_verify`. The agent binds the
dashboard/metrics port to loopback by default; to scrape it from an off-box
Prometheus, expose `:8787` to the monitoring network (or front it with a
metrics reverse-proxy / proper cert).

## Kubernetes (production shape)

Run the InnerWarden agent as a DaemonSet (one per node) exposing a `metrics`
port, then:

```bash
kubectl apply -f servicemonitor.yaml   # requires Prometheus Operator / kube-prometheus-stack
```

`instance` becomes the node name and `tenant` is the per-pod attribution
(spec 084: read from the kernel cgroup, so an agent cannot spoof it). The
dashboard's tenant panels then break down activity per Claude Code pod /
employee automatically as the fleet scales.

## Cost & tokens per agent (optional)

InnerWarden is a **security** layer — it screens what an agent runs, it does
not sit in the agent's LLM request path, so it does not measure token spend.
That data lives in the **LLM gateway** a fleet fronts its agents with (for rate
limits and cost caps). Point the same Prometheus at that gateway and the
dashboard's "Cost & tokens per agent" row lights up next to the security
panels — one pane for **what each agent did, what got blocked, and what it
cost**, per employee.

The panels use LiteLLM's metric names (`litellm_total_tokens`,
`litellm_spend_metric`) and alias the gateway's `team`/`key` label to `tenant`
so cost lines up with the security panels. If the gateway is not LiteLLM, adjust
the two panel queries to that gateway's token/spend metric names. Until a
gateway is scraped, the row shows "No data" (it is deliberately included so the
unified view is ready the moment a gateway is added).

## Metrics the dashboard uses

`innerwarden_incidents_by_tenant{tenant}` · `innerwarden_incidents_total{detector}`
· `innerwarden_decisions_total{action}` · `innerwarden_events_total{collector}`
· `innerwarden_executions_total{mode}` · `innerwarden_ai_latency_avg_ms` ·
`innerwarden_agent_guard_atr_rules_loaded` · `innerwarden_errors_total{component}`
· `innerwarden_responses_active` · `up`.
