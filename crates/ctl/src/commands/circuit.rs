use std::path::Path;

use anyhow::{Context, Result};
use chrono::{DateTime, Timelike, Utc};
use innerwarden_store::Store;

const BREAKER_NS: &str = "circuit_breaker";
const RATE_PREFIX: &str = "block_rate";
const TRIPPED_PREFIX: &str = "tripped_at";

pub(crate) fn cmd_circuit_status(agent_config: &Path, data_dir: &Path, json: bool) -> Result<()> {
    let dir = resolve_store_dir(agent_config, data_dir);
    let store =
        Store::open(&dir).with_context(|| format!("open sqlite store at {}", dir.display()))?;
    let now = Utc::now();
    let hour = format_hour(now);
    let count = load_count(&store, &hour);
    let tripped = load_tripped(&store, &hour);

    if json {
        let payload = serde_json::json!({
            "hour": hour,
            "count": count,
            "tripped_at": tripped,
        });
        println!("{}", serde_json::to_string_pretty(&payload)?);
    } else {
        println!("Circuit breaker status");
        println!("  hour (UTC):  {}", hour);
        println!("  blocks:      {}", count);
        match &tripped {
            Some(ts) => {
                println!("  tripped at:  {ts} (refusing further blocks until next hour or reset)")
            }
            None => println!("  tripped at:  not tripped"),
        }
    }
    Ok(())
}

pub(crate) fn cmd_circuit_reset(agent_config: &Path, data_dir: &Path, json: bool) -> Result<()> {
    let dir = resolve_store_dir(agent_config, data_dir);
    let store =
        Store::open(&dir).with_context(|| format!("open sqlite store at {}", dir.display()))?;
    let hour = format_hour(Utc::now());
    let had_count = store
        .kv_delete(BREAKER_NS, &rate_key(&hour))
        .unwrap_or(false);
    let had_trip = store
        .kv_delete(BREAKER_NS, &tripped_key(&hour))
        .unwrap_or(false);

    if json {
        let payload = serde_json::json!({
            "hour": hour,
            "cleared_counter": had_count,
            "cleared_trip_marker": had_trip,
        });
        println!("{}", serde_json::to_string_pretty(&payload)?);
    } else {
        println!("Circuit breaker reset for hour {hour} (UTC)");
        println!("  counter cleared:     {}", had_count);
        println!("  trip marker cleared: {}", had_trip);
        if !had_count && !had_trip {
            println!("  (breaker was already clean)");
        }
    }
    Ok(())
}

fn resolve_store_dir(agent_config: &Path, data_dir: &Path) -> std::path::PathBuf {
    if data_dir == Path::new("/var/lib/innerwarden") && agent_config.exists() {
        if let Some(dir) = std::fs::read_to_string(agent_config)
            .ok()
            .and_then(|s| s.parse::<toml_edit::DocumentMut>().ok())
            .and_then(|doc| {
                doc.get("output")
                    .and_then(|o| o.get("data_dir"))
                    .and_then(|d| d.as_str())
                    .map(std::path::PathBuf::from)
            })
        {
            return dir;
        }
    }
    data_dir.to_path_buf()
}

fn format_hour(now: DateTime<Utc>) -> String {
    let d = now.date_naive();
    format!(
        "{:04}-{:02}-{:02}T{:02}",
        d.format("%Y").to_string().parse::<i32>().unwrap_or(0),
        d.format("%m").to_string().parse::<u32>().unwrap_or(0),
        d.format("%d").to_string().parse::<u32>().unwrap_or(0),
        now.hour(),
    )
}

fn rate_key(hour: &str) -> String {
    format!("{RATE_PREFIX}/{hour}")
}

fn tripped_key(hour: &str) -> String {
    format!("{TRIPPED_PREFIX}/{hour}")
}

fn load_count(store: &Store, hour: &str) -> u64 {
    store
        .kv_get_str(BREAKER_NS, &rate_key(hour))
        .ok()
        .flatten()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0)
}

fn load_tripped(store: &Store, hour: &str) -> Option<String> {
    store
        .kv_get_str(BREAKER_NS, &tripped_key(hour))
        .ok()
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_hour_pads_zero() {
        let t: DateTime<Utc> = "2026-01-02T03:04:05Z".parse().unwrap();
        assert_eq!(format_hour(t), "2026-01-02T03");
    }

    #[test]
    fn load_count_returns_zero_when_missing() {
        let store = Store::open_memory().unwrap();
        assert_eq!(load_count(&store, "2026-04-19T12"), 0);
    }

    #[test]
    fn load_count_parses_stored_value() {
        let store = Store::open_memory().unwrap();
        store
            .kv_set(BREAKER_NS, &rate_key("2026-04-19T12"), b"42")
            .unwrap();
        assert_eq!(load_count(&store, "2026-04-19T12"), 42);
    }

    #[test]
    fn load_tripped_returns_none_when_clean() {
        let store = Store::open_memory().unwrap();
        assert!(load_tripped(&store, "2026-04-19T12").is_none());
    }

    #[test]
    fn load_tripped_returns_timestamp_when_set() {
        let store = Store::open_memory().unwrap();
        store
            .kv_set(
                BREAKER_NS,
                &tripped_key("2026-04-19T12"),
                b"2026-04-19T12:34:56Z",
            )
            .unwrap();
        assert_eq!(
            load_tripped(&store, "2026-04-19T12").as_deref(),
            Some("2026-04-19T12:34:56Z")
        );
    }

    #[test]
    fn reset_clears_counter_and_trip_marker() {
        let store = Store::open_memory().unwrap();
        let hour = "2026-04-19T12";
        store.kv_set(BREAKER_NS, &rate_key(hour), b"150").unwrap();
        store
            .kv_set(BREAKER_NS, &tripped_key(hour), b"2026-04-19T12:00:00Z")
            .unwrap();
        assert!(store.kv_delete(BREAKER_NS, &rate_key(hour)).unwrap());
        assert!(store.kv_delete(BREAKER_NS, &tripped_key(hour)).unwrap());
        assert_eq!(load_count(&store, hour), 0);
        assert!(load_tripped(&store, hour).is_none());
    }
}
