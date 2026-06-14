//! `innerwarden agent proxy` — run an inspecting MCP stdio proxy in front of a
//! real MCP server.
//!
//! ctl is otherwise synchronous; this command builds a tokio runtime scoped to
//! itself (so the rest of ctl stays sync) and hands control to the agent-guard
//! proxy. Proxy diagnostics go to stderr — stdout carries only MCP traffic so
//! the wrapping is transparent to the client.
//!
//! The decision logic lives in agent-guard; the glue here (config build, engine
//! load, runtime build, alert formatting, the `serve` loop) is unit-tested. Only
//! `run()`'s `block_on` over real stdin + `process::exit` is not (it would block
//! on the test's stdin / kill the test process).

use anyhow::{Context, Result};
use std::path::Path;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};

use innerwarden_agent_guard::mcp_proxy::enforce::ProxyMode;
use innerwarden_agent_guard::mcp_proxy::router::ProxyDecision;
use innerwarden_agent_guard::mcp_proxy::transport::{run_proxy_with_io, ProxyConfig};
use innerwarden_agent_guard::rules::RuleEngine;

/// On-disk overlay rules dir; the embedded ATR corpus loads regardless of
/// whether this exists (see `RuleEngine::load_with_overlay`).
const RULES_DIR: &str = "/etc/innerwarden/rules";

pub(crate) fn run(
    mode: &str,
    label: Option<&str>,
    error_response: bool,
    server_cmd: &[String],
) -> Result<()> {
    let cfg = build_proxy_config(mode, error_response, server_cmd)?;
    let engine = load_engine();
    let label = label.unwrap_or("mcp-proxy").to_string();

    eprintln!(
        "[innerwarden agent-guard] MCP proxy starting: mode={:?} label={label} \
         atr_rules={} server={:?}",
        cfg.mode,
        engine.rule_count(),
        cfg.server_cmd
    );

    let rt = build_runtime()?;
    let code = rt.block_on(serve(
        cfg,
        engine,
        label,
        tokio::io::stdin(),
        tokio::io::stdout(),
    ))?;

    // Propagate the wrapped server's exit code to the caller.
    std::process::exit(code);
}

/// Validate input and assemble the proxy config. The `--mode` string maps via
/// [`ProxyMode::from_label`] (unknown → advisory).
fn build_proxy_config(
    mode: &str,
    error_response: bool,
    server_cmd: &[String],
) -> Result<ProxyConfig> {
    if server_cmd.is_empty() {
        anyhow::bail!(
            "no MCP server command given — usage: innerwarden agent proxy [--mode guard] -- <server> [args...]"
        );
    }
    Ok(ProxyConfig {
        server_cmd: server_cmd.to_vec(),
        mode: ProxyMode::from_label(mode),
        as_protocol_error: error_response,
    })
}

/// Load the ATR rule engine: embedded corpus + any on-disk overlay rules.
fn load_engine() -> Arc<RuleEngine> {
    Arc::new(RuleEngine::load_with_overlay(Path::new(RULES_DIR)))
}

/// Build the tokio runtime scoped to this subcommand (ctl stays sync elsewhere).
fn build_runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to build tokio runtime for MCP proxy")
}

/// Drive the proxy over the given client streams. Alerts are formatted and
/// written to stderr (the operator snitch channel is wired in the in-agent
/// epic). Generic over the client streams so it is testable with in-memory pipes.
pub(crate) async fn serve<R, W>(
    cfg: ProxyConfig,
    engine: Arc<RuleEngine>,
    label: String,
    client_in: R,
    client_out: W,
) -> Result<i32>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let on_alert = move |d: &ProxyDecision| eprintln!("{}", format_alert(&label, d));
    run_proxy_with_io(client_in, client_out, cfg, Some(engine), on_alert)
        .await
        .context("MCP proxy failed")
}

/// Render one alert as a single stderr line (stdout is reserved for MCP bytes).
fn format_alert(label: &str, d: &ProxyDecision) -> String {
    let rules: Vec<&str> = d.verdict.alerts.iter().map(|a| a.rule.as_str()).collect();
    format!(
        "[innerwarden agent-guard] ALERT label={label} {} method={:?} tool={:?} \
         allowed={} rules={rules:?}",
        d.direction, d.method, d.tool_name, d.verdict.allowed
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use innerwarden_agent_guard::mcp_proxy::jsonrpc::{parse_line, ParsedLine};
    use innerwarden_agent_guard::mcp_proxy::router::{route_message, Direction};
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    #[test]
    fn build_proxy_config_rejects_empty_command() {
        assert!(build_proxy_config("advisory", false, &[]).is_err());
    }

    #[test]
    fn build_proxy_config_maps_mode_and_keeps_command() {
        let cfg =
            build_proxy_config("guard", true, &["npx".to_string(), "srv".to_string()]).unwrap();
        assert_eq!(cfg.mode, ProxyMode::Guard);
        assert!(cfg.as_protocol_error);
        assert_eq!(cfg.server_cmd, vec!["npx", "srv"]);
        // Unknown mode falls back to advisory.
        let cfg2 = build_proxy_config("bogus", false, &["x".to_string()]).unwrap();
        assert_eq!(cfg2.mode, ProxyMode::Advisory);
    }

    #[test]
    fn load_engine_has_the_embedded_corpus() {
        assert!(load_engine().rule_count() >= 62);
    }

    #[test]
    fn build_runtime_succeeds() {
        assert!(build_runtime().is_ok());
    }

    #[test]
    fn format_alert_includes_label_direction_and_rules() {
        let env = match parse_line(
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"save","arguments":{"token":"sk-ant-aaaaaaaaaaaaaaaaaaaaaaaa"}}}"#,
        ) {
            ParsedLine::Message(e) => e,
            _ => panic!("message"),
        };
        let d = route_message(&env, Direction::ClientToServer, None, None);
        let line = format_alert("mylabel", &d);
        assert!(line.contains("label=mylabel"));
        assert!(line.contains("client->server"));
        assert!(line.contains("AG-CRED"));
        assert!(!line.contains('\n'), "alert must be a single line");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn serve_drives_the_proxy_over_pipes() {
        // `cat` echoes input; serve should run the proxy to completion and
        // return the child's exit code, exercising the on_alert closure path.
        let cfg = build_proxy_config("advisory", false, &["cat".to_string()]).unwrap();
        let engine = load_engine();
        let (mut to_proxy, proxy_in) = duplex(16384);
        let (proxy_out, mut from_proxy) = duplex(16384);

        let h = tokio::spawn(serve(cfg, engine, "t".to_string(), proxy_in, proxy_out));

        let creds = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"save","arguments":{"token":"sk-ant-aaaaaaaaaaaaaaaaaaaaaaaa"}}}"#;
        to_proxy
            .write_all(format!("{creds}\n").as_bytes())
            .await
            .unwrap();
        to_proxy.shutdown().await.unwrap();

        // Drain the output CONCURRENTLY with the proxy, not after it. Awaiting
        // `h` first and only then reading `from_proxy` is a duplex race: if the
        // reader isn't draining while the proxy writes/closes, the test can
        // observe an empty/partial buffer (the `out.contains("sk-ant-")` flake,
        // OS-thread/scheduling dependent — same class as the mcp_proxy transport
        // test fix, 2026-06-13). `join!` runs both to completion together.
        let mut out = String::new();
        let (proxy_res, read_res) = tokio::join!(h, from_proxy.read_to_string(&mut out));
        assert_eq!(proxy_res.unwrap().unwrap(), 0);
        read_res.unwrap();
        // Advisory forwards the call (cat echoes it).
        assert!(out.contains("sk-ant-"));
    }

    #[test]
    fn cli_parses_proxy_with_trailing_server_cmd() {
        use clap::Parser;
        let cli = crate::Cli::parse_from([
            "innerwarden",
            "agent",
            "proxy",
            "--mode",
            "guard",
            "--",
            "npx",
            "-y",
            "srv",
            "--flag",
        ]);
        let Some(crate::Command::Agent {
            command:
                Some(crate::AgentCommand::Proxy {
                    mode,
                    server_cmd,
                    error_response,
                    ..
                }),
        }) = cli.command
        else {
            panic!("expected `agent proxy` subcommand");
        };
        assert_eq!(mode, "guard");
        assert_eq!(server_cmd, vec!["npx", "-y", "srv", "--flag"]);
        assert!(!error_response);
    }
}
