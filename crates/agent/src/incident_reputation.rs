use crate::{abuseipdb, AgentState};

const ABUSEIPDB_CACHE_NS: &str = "abuseipdb_cache";

/// Lookup AbuseIPDB reputation for the incident primary IP.
///
/// Consults the SQLite cache populated by `incident_enrichment::backfill_enrichment`
/// before falling back to the live API. This avoids an unnecessary HTTP round-trip
/// on every incident for IPs we already rated in the last 24h and removes the
/// "no API key → always None" gap — cached entries work regardless of whether
/// the client is currently configured.
pub(crate) async fn lookup_abuseipdb_reputation(
    incident: &innerwarden_core::incident::Incident,
    state: &AgentState,
) -> Option<abuseipdb::IpReputation> {
    let primary_ip = incident
        .entities
        .iter()
        .find(|e| e.r#type == innerwarden_core::entities::EntityType::Ip)
        .map(|e| e.value.as_str())?;

    if let Some(ref sq) = state.sqlite_store {
        if let Ok(Some(json)) = sq.kv_get_str(ABUSEIPDB_CACHE_NS, primary_ip) {
            if let Ok(rep) = serde_json::from_str::<abuseipdb::IpReputation>(&json) {
                return Some(rep);
            }
        }
    }

    let client = state.abuseipdb.as_ref()?;
    client.check(primary_ip).await
}
