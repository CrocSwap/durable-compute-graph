// SPDX-License-Identifier: GPL-3.0-only
//! Saved real-flow states (owner decision 2026-10-02). A snapshot holds only
//! accounts a real builder run produced; it is keyed by the stage, its
//! options, the fixture digest, the program identity and the builder
//! version, and `differences` compares a fresh real run byte for byte (the
//! regeneration check). Files live under `target/dcg-test-snapshots/` (or
//! `DCG_TEST_SNAPSHOT_DIR`), which is never committed.

use crate::chain::Chain;
use solana_account::Account;
use solana_pubkey::Pubkey;
use std::path::PathBuf;

/// Bump when a stage's real flow changes in a way its key does not cover.
pub const BUILDER_VERSION: u32 = 4;
const MAGIC: &[u8; 8] = b"DCGSNAP1";

pub struct Snapshot {
    pub key: [u8; 32],
    pub accounts: Vec<(Pubkey, Account)>,
}

/// The key of a stage snapshot.
pub fn key(stage: &str, options: &[u8], fixture: &[u8; 32], program: &[u8; 32]) -> [u8; 32] {
    dcg_program::hash::sha256(&[
        b"dcg-test-support/snapshot/v1\0",
        &BUILDER_VERSION.to_le_bytes(),
        stage.as_bytes(),
        &[0],
        options,
        fixture,
        program,
    ])
}

pub fn dir() -> PathBuf {
    std::env::var_os("DCG_TEST_SNAPSHOT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/dcg-test-snapshots"))
}

fn path(key: &[u8; 32]) -> PathBuf {
    dir().join(format!("{}.snap", key.iter().map(|b| format!("{b:02x}")).collect::<String>()))
}

impl Snapshot {
    /// Read `keys` from the bank (each must exist).
    pub async fn capture(chain: &mut Chain, key: [u8; 32], keys: &[Pubkey]) -> Snapshot {
        let mut accounts = Vec::with_capacity(keys.len());
        for k in keys {
            let a = chain.account(*k).await.unwrap_or_else(|| panic!("snapshot account {k} exists"));
            accounts.push((*k, a));
        }
        Snapshot { key, accounts }
    }

    pub fn load(key: &[u8; 32]) -> Option<Snapshot> {
        let raw = std::fs::read(path(key)).ok()?;
        let mut at = 0usize;
        let mut take = |n: usize| {
            let s = raw.get(at..at + n).map(|s| s.to_vec());
            at += n;
            s
        };
        if take(8)? != MAGIC || take(32)? != key {
            return None;
        }
        let count = u32::from_le_bytes(take(4)?.try_into().ok()?) as usize;
        let mut accounts = Vec::with_capacity(count);
        for _ in 0..count {
            let pk = Pubkey::new_from_array(take(32)?.try_into().ok()?);
            let owner = Pubkey::new_from_array(take(32)?.try_into().ok()?);
            let lamports = u64::from_le_bytes(take(8)?.try_into().ok()?);
            let executable = take(1)?[0] == 1;
            let len = u32::from_le_bytes(take(4)?.try_into().ok()?) as usize;
            let data = take(len)?;
            accounts.push((pk, Account { lamports, data, owner, executable, rent_epoch: 0 }));
        }
        Some(Snapshot { key: *key, accounts })
    }

    pub fn save(&self) {
        let mut raw = Vec::new();
        raw.extend_from_slice(MAGIC);
        raw.extend_from_slice(&self.key);
        raw.extend_from_slice(&(self.accounts.len() as u32).to_le_bytes());
        for (pk, a) in &self.accounts {
            raw.extend_from_slice(pk.as_ref());
            raw.extend_from_slice(a.owner.as_ref());
            raw.extend_from_slice(&a.lamports.to_le_bytes());
            raw.push(a.executable as u8);
            raw.extend_from_slice(&(a.data.len() as u32).to_le_bytes());
            raw.extend_from_slice(&a.data);
        }
        std::fs::create_dir_all(dir()).unwrap();
        // Concurrent tests may save the same key at once: write a private
        // temporary file and rename it (atomic; the content is identical).
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let tmp = path(&self.key).with_extension(format!("tmp.{}.{n}", std::process::id()));
        std::fs::write(&tmp, raw).unwrap();
        std::fs::rename(&tmp, path(&self.key)).unwrap();
    }

    /// Account-level differences from another capture of the same key set:
    /// empty means byte-identical (data, owner, lamports, executable).
    pub fn differences(&self, other: &Snapshot) -> Vec<String> {
        let mut out = Vec::new();
        if self.accounts.len() != other.accounts.len() {
            out.push(format!("account count {} vs {}", self.accounts.len(), other.accounts.len()));
        }
        for ((ka, a), (kb, b)) in self.accounts.iter().zip(&other.accounts) {
            if ka != kb {
                out.push(format!("key {ka} vs {kb}"));
                continue;
            }
            if a.owner != b.owner || a.lamports != b.lamports || a.executable != b.executable {
                out.push(format!("{ka}: owner/lamports/executable differ"));
            }
            if a.data != b.data {
                let first = a.data.iter().zip(&b.data).position(|(x, y)| x != y).unwrap_or(a.data.len().min(b.data.len()));
                out.push(format!("{ka}: data differs (lengths {} vs {}, first at {first})", a.data.len(), b.data.len()));
            }
        }
        out
    }
}
