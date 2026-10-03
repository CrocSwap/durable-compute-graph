// SPDX-License-Identifier: GPL-3.0-only
//! The `Template` stage: a sealed, admitted revision-8 template, reached by
//! the real instructions (design `docs/design/test-support-v1.md`).
//!
//! Order, all real: config (tag 174 on SBF), PT1X allocate/init/upload/seal
//! (140-142), PT2S init/hash/seal and PXR1 chunks (143-145, 193), registry
//! create/write/freeze (156-158), template seal (176), admission begin and
//! steps (159-160).

use crate::chain::{Chain, SYSTEM};
use crate::fixtures::{Fixture, FixtureKind};
use crate::target::Target;
use dcg_program::kernels::decision;
use dcg_program::pt2p_onchain as S;
use dcg_program::unified::config::{self, TemplateLimits};
use dcg_program::unified::document::Locator;
use dcg_program::unified::{address, registry};
use dcg_program::unified::{TAG_REGISTRY_CREATE, TAG_REGISTRY_FREEZE, TAG_REGISTRY_WRITE, TAG_TEMPLATE_SEAL};
use solana_instruction::account_meta::AccountMeta;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction_error::TransactionError;

/// The template authority (also the executor) and a second identity (the
/// challenger), with fixed keys so compute-unit census figures compare
/// across revisions.
pub struct Roles {
    pub executor: Keypair,
    pub signer: Keypair,
}

impl Roles {
    pub fn fixed(swapped: bool) -> Roles {
        let (a, b) = (Keypair::new_from_array([0x81; 32]), Keypair::new_from_array([0x82; 32]));
        if swapped { Roles { executor: b, signer: a } } else { Roles { executor: a, signer: b } }
    }
}

/// The five template limits the seal approves.
pub const EXAMPLE_LIMITS: TemplateLimits = TemplateLimits {
    max_challenge_window_slots: 1 << 26,
    max_response_window_slots: 1 << 23,
    max_document_lifetime_slots: 1 << 27,
    max_abandon_after_slots: 1 << 27,
    min_abandon_after_slots: 2_592_000,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admission {
    /// Every class (tag 160 over the whole class range).
    Complete,
    /// Only the Form-48 class (a targeted admission measurement).
    Form48Only,
    /// Admission begun (tag 159) but no class admitted.
    Begun,
}

pub struct TemplateOptions {
    pub kind: FixtureKind,
    pub swap_roles: bool,
    pub admission: Admission,
    /// Print compute units for the setup tags.
    pub trace_cu: bool,
    /// The five limits the template seal (176) approves.
    pub limits: TemplateLimits,
    /// Seal against registry rows whose `execute_cu` is 0 (canonical, but
    /// outside the transaction profile), so real admission (160) refuses.
    pub narrowed_registry: bool,
}

impl TemplateOptions {
    pub fn new(kind: FixtureKind) -> TemplateOptions {
        TemplateOptions { kind, swap_roles: false, admission: Admission::Complete, trace_cu: false, limits: EXAMPLE_LIMITS, narrowed_registry: false }
    }
}

/// A sealed template and the accounts the real instructions created.
pub struct Template {
    pub chain: Chain,
    pub fixture: Fixture,
    pub roles: Roles,
    pub program: Pubkey,
    pub config: Pubkey,
    pub pt1x: Pubkey,
    pub pt2s: Pubkey,
    pub routes: Pubkey,
    pub geometry: Pubkey,
    pub payloads: Pubkey,
    pub drp2: Pubkey,
    pub dta1: Pubkey,
    pub dtu1: Pubkey,
    pub dea2: Pubkey,
    /// The sealed PT2S bytes and their SHA-256 (what downstream records bind).
    pub pt2s_image: Vec<u8>,
    pub pt2s_sha: [u8; 32],
    pub reg_root: [u8; 32],
    pub locator: Locator,
    pub k: u32,
    pub segments: u16,
    pub class_total: u32,
}

/// Keys of the template's resource accounts (fixed, as the census needs).
fn resource_keys() -> [Keypair; 5] {
    [0x83u8, 0x84, 0x85, 0x86, 0x87].map(|b| Keypair::new_from_array([b; 32]))
}

/// The locator the seal writes: Form 47's write for a decision emission, the
/// retained rung-D template's own `(28_037, write 0, width 16)` otherwise.
pub fn locator_for(fixture: &Fixture) -> Locator {
    if fixture.has_pxr1() {
        let view = fixture.view();
        let position = f47_position();
        let entry_index = view.entry_count(position).unwrap() - 1;
        let entry = view.entry(position, entry_index).unwrap();
        assert_eq!(entry.kernel_index, decision::FORM_ID);
        let route = view.route(&entry, entry.read_count).unwrap();
        Locator { base_entry: view.base_entries - 1, write: 0, width: u8::try_from(route.byte_length).unwrap() }
    } else {
        Locator { base_entry: 28_037, write: 0, width: 16 }
    }
}

/// The DCF1 account natively installed in place of ConfigInit (the one
/// environment exception): DCF1, version 1, `authority` in all three roles,
/// created at slot 1, rent-exempt, owned by the program. `tests/test_support_template.rs`
/// checks on SBF that the real ConfigInit writes exactly this account.
pub fn native_config_account(program: Pubkey, authority: Pubkey) -> solana_account::Account {
    let mut dcf1 = vec![0u8; config::CONFIG_BYTES];
    dcf1[..4].copy_from_slice(b"DCF1");
    dcf1[4..6].copy_from_slice(&1u16.to_le_bytes());
    for role in 0..3 {
        dcf1[8 + 32 * role..40 + 32 * role].copy_from_slice(authority.as_ref());
    }
    // created_slot: real ConfigInit stamps its clock slot, which is 1 for the
    // first instruction of a fresh bank (the SBF guard pins this).
    dcf1[104..112].copy_from_slice(&1u64.to_le_bytes());
    let lamports = solana_program::rent::Rent::default().minimum_balance(dcf1.len());
    solana_account::Account { lamports, data: dcf1, owner: program, executable: false, rent_epoch: 0 }
}

/// The typed-decision position (29 by default, as the retained harness;
/// `BASANOS_PT2P_F47_POSITION` overrides it).
pub fn f47_position() -> u32 {
    std::env::var("BASANOS_PT2P_F47_POSITION")
        .ok()
        .map(|v| v.parse().expect("BASANOS_PT2P_F47_POSITION is a u32"))
        .unwrap_or(29)
}

impl Template {
    /// Build the template by real instructions. `None` when the fixture is
    /// absent (the suite skips).
    pub async fn build(target: &Target, options: TemplateOptions) -> Option<Template> {
        let fixture = Fixture::load(options.kind)?;
        let roles = Roles::fixed(options.swap_roles);
        let program = target.program_id;
        let [pt1x_kp, pt2s_kp, routes_kp, geometry_kp, payloads_kp] = resource_keys();
        let (k, segments, base_entries, class_total) = {
            let view = fixture.view();
            (
                view.position_count,
                view.segment_count,
                view.base_entries,
                dcg_program::unified::classes::class_count(&view).unwrap(),
            )
        };
        let locator = locator_for(&fixture);

        let mut test = target.program_test(roles.executor.pubkey());
        let config = address::config(&program).0;
        if !target.is_sbf() {
            // ENVIRONMENT EXCEPTION (documented, design §Crate shape): natively
            // the program id is a builtin, not a loader-v3 program, so
            // ConfigInit (tag 174) cannot run. Install exactly the bytes it
            // would write: DCF1, version 1, the three role keys. On SBF the
            // real instruction runs below.
            test.add_account(config, native_config_account(program, roles.executor.pubkey()));
        }
        let mut chain = Chain::start(test, program, &[roles.executor.pubkey(), roles.signer.pubkey()]).await;
        if options.trace_cu {
            chain.trace_cu_tags = vec![140, 141, 142, 143, 144, 145, 156, 157, 158, 159, 160, 176, 193];
        }
        let ex = &roles.executor;
        if target.is_sbf() {
            let programdata =
                Pubkey::find_program_address(&[program.as_ref()], &solana_program::bpf_loader_upgradeable::id()).0;
            let mut data = vec![config::TAG_CONFIG_INIT];
            for _ in 0..3 {
                data.extend_from_slice(ex.pubkey().as_ref());
            }
            chain
                .send(
                    ex,
                    &[],
                    data,
                    vec![
                        AccountMeta::new(ex.pubkey(), true),
                        AccountMeta::new(config, false),
                        AccountMeta::new_readonly(program, false),
                        AccountMeta::new_readonly(programdata, false),
                        AccountMeta::new_readonly(SYSTEM, false),
                    ],
                )
                .await
                .expect("ConfigInit (tag 174)");
        }

        // PT1X and its three byte accounts, then PT2S: allocated through the
        // System Program and written only by the program's own instructions.
        let byte_keys = [routes_kp.pubkey(), geometry_kp.pubkey(), payloads_kp.pubkey()];
        chain
            .allocate(ex, &pt1x_kp, program, dcg_program::pt1_onchain::OFF_PAYLOAD_INDEX + 4 * (base_entries as usize + 1))
            .await;
        chain.allocate(ex, &routes_kp, SYSTEM, fixture.routes.len()).await;
        chain.allocate(ex, &geometry_kp, SYSTEM, fixture.geometry.len()).await;
        chain.allocate(ex, &payloads_kp, SYSTEM, fixture.payloads.len()).await;
        chain.allocate(ex, &pt2s_kp, program, S::OFF_PWR1 + fixture.pwr1.len()).await;
        upload_pt1x(&mut chain, ex, &pt1x_kp, [&routes_kp, &geometry_kp, &payloads_kp], [&fixture.routes, &fixture.geometry, &fixture.payloads]).await;
        seal_pt1x(&mut chain, ex, pt1x_kp.pubkey(), byte_keys, &fixture.routes).await;
        seal_pt2s(&mut chain, ex, &pt2s_kp, pt1x_kp.pubkey(), byte_keys, &fixture.pwr1, locator).await;
        let pt2s = pt2s_kp.pubkey();
        let pt2s_image = chain.data(pt2s).await;
        assert_eq!(pt2s_image[S::OFF_STATE], S::STATE_SEALED, "the PT2S seal sealed it");
        let pt2s_sha = dcg_program::hash::sha256(&[&pt2s_image]);

        // The registry (156-158).
        let (mut rows, census) = fixture.registry_rows();
        if options.narrowed_registry {
            for row in rows.chunks_exact_mut(registry::ROW_BYTES) {
                row[20..24].copy_from_slice(&0u32.to_le_bytes());
            }
        }
        let drp2 = address::registry(&program, 1).0;
        chain.transfer(ex, drp2, 50_000_000_000).await;
        let mut data = vec![TAG_REGISTRY_CREATE];
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&((rows.len() / registry::ROW_BYTES) as u32).to_le_bytes());
        data.extend_from_slice(&census);
        let create = vec![
            AccountMeta::new(ex.pubkey(), true),
            AccountMeta::new_readonly(config, false),
            AccountMeta::new(drp2, false),
            AccountMeta::new_readonly(SYSTEM, false),
        ];
        chain.send(ex, &[], data, create).await.expect("registry create (156)");
        let rw = vec![
            AccountMeta::new(ex.pubkey(), true),
            AccountMeta::new_readonly(config, false),
            AccountMeta::new(drp2, false),
        ];
        for (i, row) in rows.chunks_exact(registry::ROW_BYTES).enumerate() {
            let mut d = vec![TAG_REGISTRY_WRITE];
            d.extend_from_slice(&1u32.to_le_bytes());
            d.extend_from_slice(&(i as u32).to_le_bytes());
            d.extend_from_slice(row);
            chain.send(ex, &[], d, rw.clone()).await.expect("registry write (157)");
        }
        chain.send(ex, &[], vec![TAG_REGISTRY_FREEZE, 1, 0, 0, 0], rw).await.expect("registry freeze (158)");
        let reg_root: [u8; 32] = chain.data(drp2).await[152..184].try_into().unwrap();
        assert_eq!(reg_root, registry::table_root(1, ex.pubkey().as_ref(), &census, &rows));

        // The template seal (176): creates DTA1 and DTU1.
        let dta1 = address::template_seal(&program, &pt2s, &pt2s_sha).0;
        let dtu1 = address::template_use(&program, &pt2s, &pt2s_sha).0;
        let mut data = vec![TAG_TEMPLATE_SEAL, config::SEAL_APPROVED];
        for limit in [
            options.limits.max_challenge_window_slots,
            options.limits.max_response_window_slots,
            options.limits.max_document_lifetime_slots,
            options.limits.max_abandon_after_slots,
            options.limits.min_abandon_after_slots,
        ] {
            data.extend_from_slice(&limit.to_le_bytes());
        }
        let seal = vec![
            AccountMeta::new(ex.pubkey(), true),
            AccountMeta::new_readonly(config, false),
            AccountMeta::new(dta1, false),
            AccountMeta::new_readonly(pt2s, false),
            AccountMeta::new(dtu1, false),
            AccountMeta::new_readonly(pt1x_kp.pubkey(), false),
            AccountMeta::new_readonly(byte_keys[1], false),
            AccountMeta::new_readonly(byte_keys[0], false),
            AccountMeta::new_readonly(byte_keys[2], false),
            AccountMeta::new_readonly(SYSTEM, false),
            AccountMeta::new_readonly(drp2, false),
        ];
        chain.send(ex, &[], data, seal).await.expect("template seal (176)");

        // Admission (159, then 160 in steps of 16 classes).
        let dea2 = address::admission(&program, &drp2, &pt2s, k).0;
        chain
            .send(
                ex,
                &[],
                vec![159],
                vec![
                    AccountMeta::new(ex.pubkey(), true),
                    AccountMeta::new(dea2, false),
                    AccountMeta::new_readonly(drp2, false),
                    AccountMeta::new_readonly(pt2s, false),
                    AccountMeta::new_readonly(byte_keys[0], false),
                    AccountMeta::new_readonly(byte_keys[1], false),
                    AccountMeta::new_readonly(SYSTEM, false),
                    AccountMeta::new_readonly(dtu1, false),
                ],
            )
            .await
            .expect("admission begin (159)");
        let (first, end) = match options.admission {
            Admission::Complete => (0, class_total),
            Admission::Begun => (0, 0),
            Admission::Form48Only => {
                let view = fixture.view_indexed();
                let c = (0..class_total)
                    .find(|i| {
                        let key = dcg_program::unified::classes::key_of(&view, *i).unwrap();
                        dcg_program::unified::classes::class_shape(&view, key)
                            .unwrap()
                            .is_some_and(|s| s.form == decision::GATHER_FORM_ID)
                    })
                    .expect("the fixture has a Form-48 class");
                (c, c + 1)
            }
        };
        let mut at = first;
        while at < end {
            let count = (end - at).min(16) as u16;
            let mut step = vec![160];
            step.extend_from_slice(&at.to_le_bytes());
            step.extend_from_slice(&count.to_le_bytes());
            chain
                .send(
                    ex,
                    &[],
                    step,
                    vec![
                        AccountMeta::new(dea2, false),
                        AccountMeta::new_readonly(drp2, false),
                        AccountMeta::new_readonly(pt2s, false),
                        AccountMeta::new_readonly(pt1x_kp.pubkey(), false),
                        AccountMeta::new_readonly(byte_keys[0], false),
                        AccountMeta::new_readonly(byte_keys[1], false),
                    ],
                )
                .await
                .unwrap_or_else(|e| panic!("admission step (160) at class {at}: {e:?}"));
            at += count as u32;
        }

        Some(Template {
            chain,
            fixture,
            roles,
            program,
            config,
            pt1x: pt1x_kp.pubkey(),
            pt2s,
            routes: byte_keys[0],
            geometry: byte_keys[1],
            payloads: byte_keys[2],
            drp2,
            dta1,
            dtu1,
            dea2,
            pt2s_image,
            pt2s_sha,
            reg_root,
            locator,
            k,
            segments,
            class_total,
        })
    }

    /// The snapshot key of this stage with these options and program.
    pub fn snapshot_key(target: &Target, options: &TemplateOptions, fixture: &Fixture) -> [u8; 32] {
        let admission = match options.admission {
            Admission::Complete => 0u8,
            Admission::Form48Only => 1,
            Admission::Begun => 2,
        };
        let mut opts = vec![
            options.kind as u8,
            options.swap_roles as u8,
            admission,
            target.is_sbf() as u8,
            options.narrowed_registry as u8,
        ];
        let l = &options.limits;
        for v in [
            l.max_challenge_window_slots,
            l.max_response_window_slots,
            l.max_document_lifetime_slots,
            l.max_abandon_after_slots,
            l.min_abandon_after_slots,
        ] {
            opts.extend_from_slice(&v.to_le_bytes());
        }
        crate::snapshot::key("template", &opts, &fixture.digest(), &target.identity)
    }

    /// `build`, or a restore of a snapshot a previous real `build` saved with
    /// the same key (owner decision 2026-10-02). The first call saves it.
    pub async fn build_cached(target: &Target, options: TemplateOptions) -> Option<Template> {
        let fixture = Fixture::load(options.kind)?;
        let key = Template::snapshot_key(target, &options, &fixture);
        if let Some(snapshot) = crate::snapshot::Snapshot::load(&key) {
            return Some(Template::restore(target, options, fixture, snapshot).await);
        }
        drop(fixture);
        let mut t = Template::build(target, options).await?;
        let keys = t.accounts();
        crate::snapshot::Snapshot::capture(&mut t.chain, key, &keys).await.save();
        Some(t)
    }

    async fn restore(
        target: &Target,
        options: TemplateOptions,
        fixture: Fixture,
        snapshot: crate::snapshot::Snapshot,
    ) -> Template {
        let roles = Roles::fixed(options.swap_roles);
        let program = target.program_id;
        let mut test = target.program_test(roles.executor.pubkey());
        for (key, account) in &snapshot.accounts {
            test.add_account(*key, account.clone());
        }
        let mut chain = Chain::start(test, program, &[roles.executor.pubkey(), roles.signer.pubkey()]).await;
        if options.trace_cu {
            chain.trace_cu_tags = vec![140, 141, 142, 143, 144, 145, 156, 157, 158, 159, 160, 176, 193];
        }
        let [pt1x, pt2s, routes, geometry, payloads] = resource_keys().map(|k| k.pubkey());
        let pt2s_image = chain.data(pt2s).await;
        let pt2s_sha = dcg_program::hash::sha256(&[&pt2s_image]);
        let drp2 = address::registry(&program, 1).0;
        let reg_root: [u8; 32] = chain.data(drp2).await[152..184].try_into().unwrap();
        let (k, segments, class_total) = {
            let view = fixture.view();
            (view.position_count, view.segment_count, dcg_program::unified::classes::class_count(&view).unwrap())
        };
        let locator = locator_for(&fixture);
        Template {
            chain,
            roles,
            program,
            config: address::config(&program).0,
            pt1x,
            pt2s,
            routes,
            geometry,
            payloads,
            drp2,
            dta1: address::template_seal(&program, &pt2s, &pt2s_sha).0,
            dtu1: address::template_use(&program, &pt2s, &pt2s_sha).0,
            dea2: address::admission(&program, &drp2, &pt2s, k).0,
            pt2s_image,
            pt2s_sha,
            reg_root,
            locator,
            k,
            segments,
            class_total,
            fixture,
        }
    }

    /// One real admission step (160) over `count` classes from `first`.
    pub async fn admission_step(&mut self, first: u32, count: u16) -> Result<(), TransactionError> {
        let mut step = vec![160];
        step.extend_from_slice(&first.to_le_bytes());
        step.extend_from_slice(&count.to_le_bytes());
        let metas = vec![
            AccountMeta::new(self.dea2, false),
            AccountMeta::new_readonly(self.drp2, false),
            AccountMeta::new_readonly(self.pt2s, false),
            AccountMeta::new_readonly(self.pt1x, false),
            AccountMeta::new_readonly(self.routes, false),
            AccountMeta::new_readonly(self.geometry, false),
        ];
        let ex = self.roles.executor.insecure_clone();
        self.chain.send(&ex, &[], step, metas).await
    }

    /// Every account this stage created (the snapshot set).
    pub fn accounts(&self) -> Vec<Pubkey> {
        vec![
            self.config, self.pt1x, self.pt2s, self.routes, self.geometry, self.payloads, self.drp2, self.dta1,
            self.dtu1, self.dea2,
        ]
    }
}

async fn upload_pt1x(chain: &mut Chain, authority: &Keypair, pt1x: &Keypair, byte_signers: [&Keypair; 3], blobs: [&[u8]; 3]) {
    let mut metas = vec![AccountMeta::new(pt1x.pubkey(), true)];
    metas.extend(byte_signers.iter().map(|k| AccountMeta::new(k.pubkey(), true)));
    metas.push(AccountMeta::new_readonly(authority.pubkey(), true));
    metas.push(AccountMeta::new_readonly(SYSTEM, false));
    let signers = [pt1x, byte_signers[0], byte_signers[1], byte_signers[2]];
    chain.send(authority, &signers, vec![140], metas).await.expect("PT1X init (140)");
    for kind in 0..3 {
        for (chunk, bytes) in blobs[kind].chunks(900).enumerate() {
            let mut data = vec![141, kind as u8];
            data.extend_from_slice(&u32::try_from(chunk * 900).unwrap().to_le_bytes());
            data.extend_from_slice(bytes);
            chain
                .send(
                    authority,
                    &[],
                    data,
                    vec![
                        AccountMeta::new(pt1x.pubkey(), false),
                        AccountMeta::new(byte_signers[kind].pubkey(), false),
                        AccountMeta::new_readonly(authority.pubkey(), true),
                    ],
                )
                .await
                .expect("PT1X upload (141)");
        }
    }
}

async fn seal_pt1x(chain: &mut Chain, authority: &Keypair, pt1x: Pubkey, byte_keys: [Pubkey; 3], routes: &[u8]) {
    let n = u32::from_le_bytes(routes[..4].try_into().unwrap()) as usize;
    let mut prefix = vec![0usize];
    for i in 0..n {
        let at = 80 + 16 * i + 6;
        let count = u16::from_le_bytes(routes[at..at + 2].try_into().unwrap()) as usize
            + u16::from_le_bytes(routes[at + 2..at + 4].try_into().unwrap()) as usize;
        prefix.push(prefix[i] + count);
    }
    let metas = vec![
        AccountMeta::new(pt1x, false),
        AccountMeta::new_readonly(byte_keys[0], false),
        AccountMeta::new_readonly(byte_keys[1], false),
        AccountMeta::new_readonly(byte_keys[2], false),
        AccountMeta::new_readonly(authority.pubkey(), true),
    ];
    loop {
        let state = chain.data(pt1x).await;
        if state[4] == 3 {
            break;
        }
        let cursor = u32::from_le_bytes(state[157..161].try_into().unwrap()) as usize;
        // The same batch sizes the retained harness measured per phase.
        let mut count = if state[4] == 4 {
            [(64usize, 245usize), (48, 245), (32, 100), (20, 200), (16, 220), (8, 245), (4, 245), (1, usize::MAX)]
                .iter()
                .find(|(size, limit)| cursor + size <= n && prefix[cursor + size] - prefix[cursor] <= *limit)
                .map_or(1, |item| item.0)
        } else if state[4] == 5 {
            64
        } else {
            16
        };
        loop {
            match chain.send(authority, &[], vec![142, count as u8, (count >> 8) as u8], metas.clone()).await {
                Ok(()) => break,
                Err(_) if count > 1 => count /= 2,
                Err(error) => panic!("PT1X seal (142) phase {} at {cursor}: {error:?}", state[4]),
            }
        }
    }
}

async fn seal_pt2s(
    chain: &mut Chain,
    authority: &Keypair,
    pt2s: &Keypair,
    pt1x: Pubkey,
    byte_keys: [Pubkey; 3],
    pwr1: &[u8],
    locator: Locator,
) {
    let mut data = vec![S::TAG_INIT];
    data.extend_from_slice(pwr1);
    chain
        .send(
            authority,
            &[pt2s],
            data,
            vec![
                AccountMeta::new(pt2s.pubkey(), true),
                AccountMeta::new(pt1x, false),
                AccountMeta::new_readonly(authority.pubkey(), true),
            ],
        )
        .await
        .expect("PT2S init binds PT1X");
    let hash_metas = vec![
        AccountMeta::new(pt2s.pubkey(), false),
        AccountMeta::new_readonly(byte_keys[0], false),
        AccountMeta::new_readonly(byte_keys[1], false),
        AccountMeta::new_readonly(byte_keys[2], false),
        AccountMeta::new_readonly(authority.pubkey(), true),
    ];
    while chain.data(pt2s.pubkey()).await[S::OFF_CURSOR_KIND] != 3 {
        chain
            .send(authority, &[], vec![S::TAG_HASH, S::MAX_HASH_BLOCKS as u8, (S::MAX_HASH_BLOCKS >> 8) as u8], hash_metas.clone())
            .await
            .expect("PT2S hash chunk");
    }
    let mut data = vec![S::TAG_SEAL];
    data.extend_from_slice(&[9u8; 32]);
    data.extend_from_slice(&locator.base_entry.to_le_bytes());
    data.push(locator.write);
    data.push(locator.width);
    let mut seal_metas = hash_metas;
    seal_metas.push(AccountMeta::new_readonly(pt1x, false));
    chain.send(authority, &[], data, seal_metas.clone()).await.expect("PT2S seal begin");
    loop {
        let state = chain.data(pt2s.pubkey()).await;
        if state[S::OFF_STATE] == S::STATE_SEALED {
            break;
        }
        assert_eq!(state[S::OFF_STATE], S::STATE_SEALING_PXR);
        let mut data = vec![S::TAG_SEAL_PXR_CHUNK];
        data.extend_from_slice(&S::MAX_PXR_SEAL_ROWS.to_le_bytes());
        chain.send(authority, &[], data, seal_metas.clone()).await.expect("PT2S PXR1 seal chunk");
    }
}
