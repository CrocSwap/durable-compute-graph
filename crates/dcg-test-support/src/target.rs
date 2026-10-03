// SPDX-License-Identifier: GPL-3.0-only
//! The program under test.

use solana_account::Account;
use solana_program_test::ProgramTest;
use solana_pubkey::Pubkey;
use std::path::PathBuf;

/// How the program runs: natively (a constructor that registers the
/// processor, since `processor!`'s type is not exported) or as an SBF image.
pub enum Image {
    Native(fn(Pubkey) -> ProgramTest),
    /// `dir/<so_name>.so`, installed as an upgradeable program whose upgrade
    /// authority is given at `program_test` time.
    Sbf { dir: PathBuf, so_name: String },
}

pub struct Target {
    pub program_id: Pubkey,
    pub image: Image,
    /// Identifies the program build for snapshot keys: the SBF image's
    /// SHA-256, or a caller-supplied digest of the native source.
    pub identity: [u8; 32],
}

impl Target {
    /// A native target identified by the SHA-256 of every file under `sources`
    /// (in path order), so a source change invalidates snapshots.
    pub fn native(program_id: Pubkey, make: fn(Pubkey) -> ProgramTest, sources: &[PathBuf]) -> Target {
        Target { program_id, image: Image::Native(make), identity: source_digest(sources) }
    }

    pub fn sbf(program_id: Pubkey, dir: PathBuf, so_name: &str) -> Target {
        let elf = std::fs::read(dir.join(format!("{so_name}.so")))
            .unwrap_or_else(|e| panic!("read SBF image {so_name}.so in {}: {e}", dir.display()));
        let identity = dcg_program::hash::sha256(&[&elf]);
        Target { program_id, image: Image::Sbf { dir, so_name: so_name.to_string() }, identity }
    }

    /// `sbf(...)` when `env_flag` is set (with `BPF_OUT_DIR` naming the image
    /// directory), otherwise `native(...)`. The suites' existing switch.
    pub fn from_env(
        env_flag: &str,
        program_id: Pubkey,
        make: fn(Pubkey) -> ProgramTest,
        sources: &[PathBuf],
        so_name: &str,
    ) -> Target {
        if std::env::var_os(env_flag).is_some() {
            let dir = std::env::var("BPF_OUT_DIR").expect("BPF_OUT_DIR names the SBF image directory");
            Target::sbf(program_id, PathBuf::from(dir), so_name)
        } else {
            Target::native(program_id, make, sources)
        }
    }

    pub fn is_sbf(&self) -> bool {
        matches!(self.image, Image::Sbf { .. })
    }

    /// A `ProgramTest` with the program installed.
    pub fn program_test(&self, upgrade_authority: Pubkey) -> ProgramTest {
        match &self.image {
            Image::Native(make) => {
                let mut test = make(self.program_id);
                test.prefer_bpf(false);
                test
            }
            Image::Sbf { dir, so_name } => {
                let elf = std::fs::read(dir.join(format!("{so_name}.so"))).unwrap();
                let data_address =
                    solana_program::bpf_loader_upgradeable::get_program_data_address(&self.program_id);
                let mut program_state = 2u32.to_le_bytes().to_vec();
                program_state.extend_from_slice(data_address.as_ref());
                let mut data = 3u32.to_le_bytes().to_vec();
                data.extend_from_slice(&0u64.to_le_bytes());
                data.push(1);
                data.extend_from_slice(upgrade_authority.as_ref());
                data.extend_from_slice(&elf);
                let mut test = ProgramTest::default();
                test.prefer_bpf(true);
                let loader = solana_program::bpf_loader_upgradeable::id();
                test.add_genesis_account(
                    self.program_id,
                    Account { lamports: 1_000_000_000, data: program_state, owner: loader, executable: true, rent_epoch: 0 },
                );
                test.add_genesis_account(
                    data_address,
                    Account { lamports: 1_000_000_000_000, data, owner: loader, executable: false, rent_epoch: 0 },
                );
                test
            }
        }
    }
}

fn source_digest(sources: &[PathBuf]) -> [u8; 32] {
    let mut files = Vec::new();
    for root in sources {
        collect(root, &mut files);
    }
    files.sort();
    let mut parts: Vec<Vec<u8>> = Vec::new();
    for f in &files {
        parts.push(f.to_string_lossy().as_bytes().to_vec());
        parts.push(std::fs::read(f).unwrap_or_default());
    }
    let refs: Vec<&[u8]> = parts.iter().map(|p| p.as_slice()).collect();
    dcg_program::hash::sha256(&refs)
}

fn collect(path: &std::path::Path, out: &mut Vec<PathBuf>) {
    if path.is_dir() {
        if let Ok(entries) = std::fs::read_dir(path) {
            for e in entries.flatten() {
                collect(&e.path(), out);
            }
        }
    } else if path.is_file() {
        out.push(path.to_path_buf());
    }
}
