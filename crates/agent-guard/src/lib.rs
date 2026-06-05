//! InnerWarden Agent Guard — AI agent protection module.
//!
//! Detects AI agents/tools/runtimes on the host and screens their activity:
//! - Tool-call / argument / response scanning for prompt injection,
//!   credential leaks, dangerous commands, and ATR rule matches. This is
//!   pattern/regex scanning over the serialized call — NOT MCP-protocol-aware
//!   parsing, and there is no inline MCP proxy yet.
//! - Session tracking (rate limiting, sensitive-file access, exfil chains).
//! - Process discovery via `/proc` scanning + MCP config-file discovery.
//!
//! Detection is advisory: matches surface as alerts ("snitch" mode) rather
//! than inline enforcement.
//!
//! Recognized agents/tools/runtimes (see [`signatures`]): Claude Code, Cursor,
//! Aider, Goose, OpenClaw, Codex CLI, Gemini CLI, Cline, Ollama, and more.

pub mod detect;
pub mod mcp;
pub mod mcp_proxy;
pub mod registry;
pub mod rules;
pub mod session;
pub mod signatures;
pub mod threats;
