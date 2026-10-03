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

    /// Mix the enabled feature set into a native identity (an SBF image's
    /// hash already covers its features).
    pub fn with_features(mut self, features: &str) -> Target {
        if !self.is_sbf() {
            self.identity = dcg_program::hash::sha256(&[&self.identity, b"features\0", features.as_bytes()]);
        }
        self
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

/// Every `dcg-program` feature, in Cargo.toml order (`default` excluded).
/// `program_features!` must name each; `tests/feature_list.rs` checks this.
pub const PROGRAM_FEATURES: &[&str] = &[
    "revision-7",
    "revision-8",
    "revision-8-lifecycle",
    "graph-v2",
    "graph-v2-experimental",
    "graph-v2-raw-write",
    "graph-v21",
    "test-rev8-before-payer-alias-fix",
    "no-entrypoint",
    "custom-heap",
    "heap-census",
    "weight-witness-probe",
    "test-weakened-class-rule",
    "test-legacy-unchecked-option-range",
    "v7-cu-probe",
    "a16-kernel-probe",
    "decision-kernel-probe",
    "legacy-basanos-fixtures",
    "legacy-hclosure-handlers",
    "pt2p-seal-profile",
    "test-kernel",
    "sbf-lifecycle-test",
    "sbf-real-lifecycle-test",
    "sbf-unbound-form-test",
    "sbf-attested-admission-test",
];

/// The `dcg-program` features enabled where this expands (a `dcg-program`
/// test), joined by commas. Native snapshot identities include it, since a
/// feature can change program behavior without changing its source.
#[macro_export]
macro_rules! program_features {
    () => {{
        let enabled: &[(&str, bool)] = &[
            ("revision-7", cfg!(feature = "revision-7")),
            ("revision-8", cfg!(feature = "revision-8")),
            ("revision-8-lifecycle", cfg!(feature = "revision-8-lifecycle")),
            ("graph-v2", cfg!(feature = "graph-v2")),
            ("graph-v2-experimental", cfg!(feature = "graph-v2-experimental")),
            ("graph-v2-raw-write", cfg!(feature = "graph-v2-raw-write")),
            ("graph-v21", cfg!(feature = "graph-v21")),
            ("test-rev8-before-payer-alias-fix", cfg!(feature = "test-rev8-before-payer-alias-fix")),
            ("no-entrypoint", cfg!(feature = "no-entrypoint")),
            ("custom-heap", cfg!(feature = "custom-heap")),
            ("heap-census", cfg!(feature = "heap-census")),
            ("weight-witness-probe", cfg!(feature = "weight-witness-probe")),
            ("test-weakened-class-rule", cfg!(feature = "test-weakened-class-rule")),
            ("test-legacy-unchecked-option-range", cfg!(feature = "test-legacy-unchecked-option-range")),
            ("v7-cu-probe", cfg!(feature = "v7-cu-probe")),
            ("a16-kernel-probe", cfg!(feature = "a16-kernel-probe")),
            ("decision-kernel-probe", cfg!(feature = "decision-kernel-probe")),
            ("legacy-basanos-fixtures", cfg!(feature = "legacy-basanos-fixtures")),
            ("legacy-hclosure-handlers", cfg!(feature = "legacy-hclosure-handlers")),
            ("pt2p-seal-profile", cfg!(feature = "pt2p-seal-profile")),
            ("test-kernel", cfg!(feature = "test-kernel")),
            ("sbf-lifecycle-test", cfg!(feature = "sbf-lifecycle-test")),
            ("sbf-real-lifecycle-test", cfg!(feature = "sbf-real-lifecycle-test")),
            ("sbf-unbound-form-test", cfg!(feature = "sbf-unbound-form-test")),
            ("sbf-attested-admission-test", cfg!(feature = "sbf-attested-admission-test")),
        ];
        enabled.iter().filter(|(_, on)| *on).map(|(n, _)| *n).collect::<Vec<_>>().join(",")
    }};
}

/// The program under test in a `dcg-program` integration test: native, or
/// the SBF image when `BASANOS_DCG_V8_SBF` is set (with `BPF_OUT_DIR`), with
/// the enabled features in its identity.
#[macro_export]
macro_rules! dcg_program_target {
    () => {
        $crate::Target::from_env(
            "BASANOS_DCG_V8_SBF",
            ::solana_pubkey::Pubkey::new_from_array([0x80; 32]),
            |id| {
                ::solana_program_test::ProgramTest::new(
                    "dcg_program",
                    id,
                    ::solana_program_test::processor!(dcg_program::process_instruction),
                )
            },
            &[::std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src")],
            "dcg_program",
        )
        .with_features(&$crate::program_features!())
    };
}
