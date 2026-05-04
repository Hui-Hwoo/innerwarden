//! Persistent storage for threat DNA fingerprints.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::Result;
use tracing::{info, warn};

use crate::fingerprint::ThreatDna;

/// In-memory store of known threat DNA fingerprints, backed by a JSON file.
pub struct DnaStore {
    /// All known DNA, keyed by exact_hash
    pub dna: HashMap<String, ThreatDna>,
    /// Path to the persistence file
    path: PathBuf,
}

impl DnaStore {
    /// Load from disk or create empty.
    pub fn load(dna_dir: &Path) -> Result<Self> {
        let path = dna_dir.join("threat-dna.json");
        let dna = if path.exists() {
            match std::fs::read_to_string(&path) {
                Ok(content) => {
                    let entries: Vec<ThreatDna> =
                        serde_json::from_str(&content).unwrap_or_default();
                    let map: HashMap<String, ThreatDna> = entries
                        .into_iter()
                        .map(|d| (d.exact_hash.clone(), d))
                        .collect();
                    info!(count = map.len(), "loaded threat DNA from disk");
                    map
                }
                Err(e) => {
                    warn!(error = %e, "failed to read threat DNA file, starting fresh");
                    HashMap::new()
                }
            }
        } else {
            HashMap::new()
        };

        Ok(Self { dna, path })
    }

    /// Maximum number of DNA entries to prevent unbounded memory growth.
    const MAX_DNA: usize = 10_000;

    /// Insert or update a DNA entry. Returns true if this is a new DNA.
    pub fn insert(&mut self, mut dna: ThreatDna) -> bool {
        if let Some(existing) = self.dna.get_mut(&dna.exact_hash) {
            existing.seen_count += 1;
            existing.last_seen = dna.last_seen;
            if dna.classification.is_some() {
                existing.classification = dna.classification;
            }
            false
        } else {
            // Cap DNA entries to prevent unbounded growth
            if self.dna.len() >= Self::MAX_DNA {
                // Evict the oldest entry by last_seen
                if let Some(oldest_hash) = self
                    .dna
                    .iter()
                    .min_by_key(|(_, d)| d.last_seen)
                    .map(|(k, _)| k.clone())
                {
                    self.dna.remove(&oldest_hash);
                }
            }
            dna.seen_count = 1;
            self.dna.insert(dna.exact_hash.clone(), dna);
            true
        }
    }

    /// Check if a DNA hash is known.
    pub fn is_known(&self, exact_hash: &str) -> bool {
        self.dna.contains_key(exact_hash)
    }

    /// Get a DNA entry by exact hash.
    pub fn get(&self, exact_hash: &str) -> Option<&ThreatDna> {
        self.dna.get(exact_hash)
    }

    /// Find similar DNA using fuzzy hash matching.
    pub fn find_similar(&self, fuzzy_hash: &str) -> Vec<&ThreatDna> {
        self.dna
            .values()
            .filter(|d| d.fuzzy_hash == fuzzy_hash)
            .collect()
    }

    /// Total number of known DNA fingerprints.
    pub fn len(&self) -> usize {
        self.dna.len()
    }

    /// Save to disk.
    pub fn save(&self) -> Result<()> {
        let entries: Vec<&ThreatDna> = self.dna.values().collect();
        let json = serde_json::to_string_pretty(&entries)?;
        std::fs::write(&self.path, json)?;
        Ok(())
    }

    /// Get all DNA entries for API responses.
    pub fn all(&self) -> Vec<&ThreatDna> {
        self.dna.values().collect()
    }

    /// Get top threats by seen_count.
    pub fn top_threats(&self, limit: usize) -> Vec<&ThreatDna> {
        let mut entries: Vec<&ThreatDna> = self.dna.values().collect();
        entries.sort_by(|a, b| b.seen_count.cmp(&a.seen_count));
        entries.truncate(limit);
        entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fingerprint::ThreatDna;
    use crate::sequence::Atom;
    use chrono::Utc;

    fn make_dna(hash: &str) -> ThreatDna {
        ThreatDna {
            exact_hash: hash.to_string(),
            fuzzy_hash: "fuzzy123".to_string(),
            length: 3,
            atoms: vec![Atom::Login { success: true }],
            source_ip: "1.2.3.4".to_string(),
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            seen_count: 1,
            classification: None,
        }
    }

    #[test]
    fn insert_new_returns_true() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = DnaStore::load(dir.path()).unwrap();
        assert!(store.insert(make_dna("abc123")));
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn insert_duplicate_increments_count() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = DnaStore::load(dir.path()).unwrap();
        store.insert(make_dna("abc123"));
        assert!(!store.insert(make_dna("abc123")));
        assert_eq!(store.get("abc123").unwrap().seen_count, 2);
    }

    #[test]
    fn save_and_reload() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut store = DnaStore::load(dir.path()).unwrap();
            store.insert(make_dna("hash1"));
            store.insert(make_dna("hash2"));
            store.save().unwrap();
        }
        let store = DnaStore::load(dir.path()).unwrap();
        assert_eq!(store.len(), 2);
        assert!(store.is_known("hash1"));
        assert!(store.is_known("hash2"));
    }

    #[test]
    fn is_known_returns_false_for_unknown() {
        let dir = tempfile::tempdir().unwrap();
        let store = DnaStore::load(dir.path()).unwrap();
        assert!(!store.is_known("nonexistent"));
    }

    #[test]
    fn find_similar_matches_fuzzy_hash() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = DnaStore::load(dir.path()).unwrap();
        store.insert(make_dna("a1"));
        store.insert(make_dna("a2"));
        // Both have fuzzy_hash = "fuzzy123"
        let similar = store.find_similar("fuzzy123");
        assert_eq!(similar.len(), 2);
    }

    #[test]
    fn find_similar_no_match() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = DnaStore::load(dir.path()).unwrap();
        store.insert(make_dna("a1"));
        let similar = store.find_similar("no_match");
        assert!(similar.is_empty());
    }

    #[test]
    fn top_threats_sorted_by_count() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = DnaStore::load(dir.path()).unwrap();
        store.insert(make_dna("low"));

        let mut hot = make_dna("hot");
        store.insert(hot.clone());
        // Insert duplicate to bump seen_count
        hot.exact_hash = "hot".to_string();
        store.insert(hot);
        store.insert(make_dna("hot")); // seen_count now 3

        let top = store.top_threats(1);
        assert_eq!(top.len(), 1);
        assert_eq!(top[0].exact_hash, "hot");
    }

    #[test]
    fn insert_duplicate_updates_classification() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = DnaStore::load(dir.path()).unwrap();
        store.insert(make_dna("c1"));
        assert!(store.get("c1").unwrap().classification.is_none());

        let mut updated = make_dna("c1");
        updated.classification = Some(crate::fingerprint::ThreatClass::BruteForceAndExploit);
        store.insert(updated);
        assert_eq!(
            store.get("c1").unwrap().classification,
            Some(crate::fingerprint::ThreatClass::BruteForceAndExploit)
        );
    }

    #[test]
    fn all_returns_every_entry() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = DnaStore::load(dir.path()).unwrap();
        store.insert(make_dna("x1"));
        store.insert(make_dna("x2"));
        store.insert(make_dna("x3"));
        assert_eq!(store.all().len(), 3);
    }
}
