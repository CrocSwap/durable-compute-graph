//! Seeded ProgramTest state-machine probe for the revision-8 lifecycle surface.
//!
//! The native processor is deliberate: each generated instruction reaches the
//! real Rust handler under ProgramTest, without requiring an SBF artifact or a
//! network service. This first harness has one handler-produced happy path
//! (PT1X create -> unpublished close) and follows it with deterministic,
//! malformed instruction sequences across setup, document, challenge, and
//! close families. Existing artifact-backed lifecycle tests remain responsible
//! for full PT2P admission and document completion.
//!
//! Default: 96 generated attempts. Set `BASANOS_DCG_PREP_LONG=1` for 1,024
//! attempts, and optionally set `BASANOS_DCG_PREP_SEED` to reproduce a seed.
#![cfg(feature = "revision-8")]

use dcg_program::pt1_onchain as pt1;
use solana_account::Account;
use solana_instruction::{account_meta::AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_program::{rent::Rent, system_instruction, system_program};
use solana_program_test::{processor, ProgramTest, ProgramTestContext};
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;
use solana_transaction_error::TransactionError;
use std::collections::BTreeSet;

#[cfg(feature = "test-kernel")]
mod kernel_lifecycle {
    use dcg_program::kernel::{
        test_kernel::{BYTE_SUM, MANIFEST_APP, MODE_OPTIMISTIC_V1},
        Commitment, Kernel, KernelId, ResolutionBackend, ResolutionStatus,
    };

    struct State {
        claim: Commitment,
        status: ResolutionStatus,
    }

    struct ObserveBackend;

    impl ResolutionBackend for ObserveBackend {
        type State = State;
        type Transition = Vec<u8>;
        type Error = ();

        fn mode(&self) -> dcg_program::kernel::ModeId {
            MODE_OPTIMISTIC_V1
        }

        fn start(&self, claimed_output: Commitment) -> Result<Self::State, Self::Error> {
            Ok(State {
                claim: claimed_output,
                status: ResolutionStatus::Pending,
            })
        }

        fn advance(
            &self,
            state: &mut Self::State,
            observed_output: Self::Transition,
        ) -> Result<ResolutionStatus, Self::Error> {
            if state.status != ResolutionStatus::Pending {
                return Ok(state.status);
            }
            state.status = if Commitment::sha256(&observed_output) == state.claim {
                ResolutionStatus::Final
            } else {
                ResolutionStatus::Refuted
            };
            Ok(state.status)
        }
    }

    #[test]
    fn test_kernel_runs_through_static_registry_commitment_and_lifecycle() {
        let app = &MANIFEST_APP;
        let kernel_id = KernelId(*b"dcg-test-sum-v1\0");
        let mut output = [0u8; 8];
        let written = app
            .execute(
                kernel_id,
                1,
                1,
                MODE_OPTIMISTIC_V1,
                &[1, 2, 3, 250],
                &mut output,
            )
            .unwrap();
        assert_eq!(written, 8);
        assert_eq!(u64::from_le_bytes(output), 256);

        let backend = ObserveBackend;
        let mut honest = backend.start(Commitment::sha256(&output)).unwrap();
        assert_eq!(backend.mode(), MODE_OPTIMISTIC_V1);
        assert_eq!(
            backend.advance(&mut honest, output.to_vec()).unwrap(),
            ResolutionStatus::Final
        );

        let mut malformed = backend.start(Commitment::sha256(&[0u8; 8])).unwrap();
        assert_eq!(
            backend.advance(&mut malformed, output.to_vec()).unwrap(),
            ResolutionStatus::Refuted
        );
        assert_eq!(BYTE_SUM.manifest().id, kernel_id);
    }
}

const PROGRAM: Pubkey = Pubkey::new_from_array([0xD8; 32]);
const LONG_STEPS: usize = 1_024;
const DEFAULT_STEPS: usize = 96;

#[derive(Clone, Copy)]
struct Operation {
    tag: u8,
    account_count: usize,
}

// This includes PT1X/PT2P setup and output reservation, the revision-8
// document transitions, both unified and ROOT_ONLY challenge opens, and every
// close tag named in the extraction lifecycle inventory.
const OPERATIONS: &[Operation] = &[
    Operation {
        tag: 140,
        account_count: 6,
    },
    Operation {
        tag: 141,
        account_count: 3,
    },
    Operation {
        tag: 142,
        account_count: 5,
    },
    Operation {
        tag: 143,
        account_count: 3,
    },
    Operation {
        tag: 144,
        account_count: 5,
    },
    Operation {
        tag: 145,
        account_count: 6,
    },
    Operation {
        tag: 146,
        account_count: 8,
    },
    Operation {
        tag: 147,
        account_count: 5,
    },
    Operation {
        tag: 159,
        account_count: 8,
    },
    Operation {
        tag: 160,
        account_count: 6,
    },
    Operation {
        tag: 161,
        account_count: 14,
    },
    Operation {
        tag: 162,
        account_count: 4,
    },
    Operation {
        tag: 165,
        account_count: 4,
    },
    Operation {
        tag: 166,
        account_count: 10,
    },
    Operation {
        tag: 167,
        account_count: 10,
    },
    Operation {
        tag: 172,
        account_count: 10,
    },
    Operation {
        tag: 177,
        account_count: 7,
    },
    Operation {
        tag: 185,
        account_count: 3,
    },
    Operation {
        tag: 186,
        account_count: 15,
    },
    Operation {
        tag: 197,
        account_count: 5,
    },
    Operation {
        tag: 198,
        account_count: 2,
    },
    Operation {
        tag: 199,
        account_count: 8,
    },
    Operation {
        tag: 200,
        account_count: 8,
    },
    Operation {
        tag: 100,
        account_count: 7,
    },
    Operation {
        tag: 111,
        account_count: 6,
    },
    Operation {
        tag: 112,
        account_count: 6,
    },
];

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*; the seed and call order are stable across platforms.
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn index(&mut self, n: usize) -> usize {
        (self.next() as usize) % n
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AccountImage {
    lamports: u64,
    data: Vec<u8>,
    owner: Pubkey,
    executable: bool,
    rent_epoch: u64,
}

fn image(account: Option<Account>) -> Option<AccountImage> {
    account.map(|a| AccountImage {
        lamports: a.lamports,
        data: a.data,
        owner: a.owner,
        executable: a.executable,
        rent_epoch: a.rent_epoch,
    })
}

fn funded(owner: Pubkey, lamports: u64, data: Vec<u8>) -> Account {
    Account {
        lamports,
        data,
        owner,
        executable: false,
        rent_epoch: 0,
    }
}

fn kp(byte: u8) -> Keypair {
    Keypair::new_from_array([byte; 32])
}

fn ix(_tag: u8, data: Vec<u8>, accounts: Vec<AccountMeta>) -> Instruction {
    Instruction {
        program_id: PROGRAM,
        accounts,
        data,
    }
}

fn writable(key: Pubkey) -> AccountMeta {
    AccountMeta::new(key, false)
}
fn readonly(key: Pubkey) -> AccountMeta {
    AccountMeta::new_readonly(key, false)
}
fn signer_writable(key: Pubkey) -> AccountMeta {
    AccountMeta::new(key, true)
}
fn signer_readonly(key: Pubkey) -> AccountMeta {
    AccountMeta::new_readonly(key, true)
}

async fn send_instructions(
    ctx: &mut ProgramTestContext,
    instructions: &[Instruction],
    extra_signers: &[&Keypair],
) -> Result<(), TransactionError> {
    let blockhash = ctx.get_new_latest_blockhash().await.unwrap();
    let mut signers = vec![&ctx.payer];
    signers.extend_from_slice(extra_signers);
    let tx = Transaction::new(
        &signers,
        solana_message::Message::new(instructions, Some(&ctx.payer.pubkey())),
        blockhash,
    );
    ctx.banks_client
        .process_transaction(tx)
        .await
        .map_err(|e| e.unwrap())
}

async fn get_image(ctx: &mut ProgramTestContext, key: Pubkey) -> Option<AccountImage> {
    image(ctx.banks_client.get_account(key).await.unwrap())
}

async fn assert_output_pda_safe(ctx: &mut ProgramTestContext, output: Pubkey, step: &str) {
    if let Some(candidate) = get_image(ctx, output).await {
        assert!(
            candidate.owner != PROGRAM || candidate.data.iter().any(|byte| *byte != 0),
            "program-owned all-zero derived output after {step}"
        );
    }
}

async fn snapshot(
    ctx: &mut ProgramTestContext,
    keys: &[Pubkey],
) -> Vec<(Pubkey, Option<AccountImage>)> {
    let unique: BTreeSet<Pubkey> = keys.iter().copied().collect();
    let mut result = Vec::with_capacity(unique.len());
    for key in unique {
        result.push((key, get_image(ctx, key).await));
    }
    result
}

async fn assert_refusal_unchanged(
    ctx: &mut ProgramTestContext,
    before: &[(Pubkey, Option<AccountImage>)],
    label: &str,
) {
    let fee_payer = ctx.payer.pubkey();
    for (key, prior) in before {
        let current = get_image(ctx, *key).await;
        if *key == fee_payer {
            let prior = prior.as_ref().expect("the transaction fee payer exists");
            let current = current.as_ref().expect("the transaction fee payer remains");
            assert_eq!(
                current.owner, prior.owner,
                "{label}: fee payer owner changed"
            );
            assert_eq!(current.data, prior.data, "{label}: fee payer data changed");
            assert!(
                current.lamports <= prior.lamports,
                "{label}: fee payer gained lamports on refusal"
            );
        } else {
            assert_eq!(current, *prior, "{label}: refusal changed account {key}");
        }
    }
}

async fn total_lamports_except_fee_payer(ctx: &mut ProgramTestContext, keys: &[Pubkey]) -> u128 {
    let fee_payer = ctx.payer.pubkey();
    let unique: BTreeSet<Pubkey> = keys
        .iter()
        .copied()
        .filter(|key| *key != fee_payer)
        .collect();
    let mut total = 0u128;
    for key in unique {
        if let Some(account) = ctx.banks_client.get_account(key).await.unwrap() {
            total += u128::from(account.lamports);
        }
    }
    total
}

fn operation_data(tag: u8) -> Vec<u8> {
    match tag {
        140 | 197 | 198 | 186 => vec![tag],
        141 => vec![tag, 0, 0, 0, 0, 0],
        142 | 144 => vec![tag, 1, 0],
        143 => vec![tag, 0],
        145 => [vec![tag], vec![0; 39]].concat(),
        146 | 199 | 200 => {
            let mut data = vec![tag];
            data.extend_from_slice(&0u32.to_le_bytes());
            data.extend_from_slice(&0u32.to_le_bytes());
            data.extend_from_slice(&1u16.to_le_bytes());
            data
        }
        147 => [vec![tag], vec![0; 32]].concat(),
        159 => [vec![tag], vec![0; 32]].concat(),
        160 => [vec![tag], vec![0; 6]].concat(),
        161 => [vec![tag], vec![0; 400]].concat(),
        162 => [vec![tag], vec![0; 69]].concat(),
        165 => [vec![tag], vec![0; 38]].concat(),
        166 | 111 => [vec![tag], vec![0; 79]].concat(),
        167 => [vec![tag], vec![0; 38]].concat(),
        100 => [vec![tag], vec![0; 78]].concat(),
        112 => [vec![tag], vec![0; 42]].concat(),
        172 | 185 => [vec![tag], vec![0; 32]].concat(),
        177 => [vec![tag], vec![0; 80]].concat(),
        _ => vec![tag],
    }
}

fn nominal_keys(
    operation: Operation,
    state: Pubkey,
    base: [Pubkey; 3],
    authority: Pubkey,
    attacker: Pubkey,
    pt2s: Pubkey,
    output: Pubkey,
    decoys: &[Pubkey],
) -> Vec<Pubkey> {
    let mut keys = vec![decoys[0]; operation.account_count];
    match operation.tag {
        140 => {
            keys = vec![
                state,
                base[0],
                base[1],
                base[2],
                authority,
                system_program::ID,
            ]
        }
        141 => keys = vec![state, base[0], authority],
        142 => keys = vec![state, base[0], base[1], base[2], authority],
        143 => keys = vec![pt2s, state, authority],
        144 => keys = vec![pt2s, base[0], base[1], base[2], authority],
        145 => keys = vec![pt2s, base[0], base[1], base[2], authority, state],
        146 | 199 | 200 => {
            keys = vec![
                pt2s,
                state,
                base[0],
                base[1],
                base[2],
                output,
                system_program::ID,
                authority,
            ]
        }
        197 => keys = vec![authority, state, base[0], base[1], base[2]],
        198 => keys = vec![output, authority],
        159 => {
            keys = vec![
                authority,
                decoys[1],
                decoys[2],
                pt2s,
                base[0],
                base[1],
                system_program::ID,
                decoys[3],
            ]
        }
        160 => keys = vec![decoys[1], decoys[2], pt2s, decoys[4], base[0], base[1]],
        162 => keys = vec![authority, decoys[1], decoys[2], decoys[3]],
        165 => keys = vec![authority, decoys[1], decoys[2], decoys[3]],
        172 => {
            keys = vec![
                attacker, decoys[1], decoys[2], decoys[3], decoys[4], authority, decoys[5],
                decoys[6], decoys[7], decoys[8],
            ]
        }
        177 => {
            keys = vec![
                attacker, decoys[1], decoys[2], decoys[3], pt2s, base[0], base[1],
            ]
        }
        185 => keys = vec![attacker, decoys[1], authority],
        186 => {
            keys = vec![
                attacker,
                decoys[1],
                decoys[2],
                pt2s,
                state,
                base[0],
                base[1],
                base[2],
                authority,
                authority,
                attacker,
                decoys[3],
                decoys[4],
                decoys[5],
                system_program::ID,
            ]
        }
        100 => {
            keys = vec![
                decoys[0],
                attacker,
                decoys[1],
                decoys[2],
                decoys[3],
                decoys[4],
                system_program::ID,
            ]
        }
        111 | 112 => {
            keys = vec![
                decoys[0],
                attacker,
                decoys[1],
                decoys[2],
                decoys[3],
                system_program::ID,
            ]
        }
        _ => {}
    }
    debug_assert_eq!(keys.len(), operation.account_count);
    keys
}

fn metas_for(
    rng: &mut Rng,
    keys: &[Pubkey],
    authority: Pubkey,
    attacker: Pubkey,
    state: Pubkey,
    base: [Pubkey; 3],
    variant: usize,
) -> Vec<AccountMeta> {
    let mut metas: Vec<AccountMeta> = keys
        .iter()
        .enumerate()
        .map(|(i, key)| {
            let writable_flag = (rng.next() & 1) != 0;
            let known_signer =
                *key == authority || *key == attacker || *key == state || base.contains(key);
            let signer =
                known_signer && (*key == authority || *key == attacker || (i == 0 && variant == 2));
            if signer && writable_flag {
                signer_writable(*key)
            } else if signer {
                signer_readonly(*key)
            } else if writable_flag {
                writable(*key)
            } else {
                readonly(*key)
            }
        })
        .collect();
    match variant {
        0 if !metas.is_empty() => {
            metas.pop();
        }
        1 if !metas.is_empty() => {
            let at = rng.index(metas.len());
            let key = metas[at].pubkey;
            metas[at] = readonly(key);
        }
        2 if metas.len() > 1 => {
            let at = rng.index(metas.len());
            metas[at] = metas[0].clone();
        }
        3 if !metas.is_empty() => {
            let at = rng.index(metas.len());
            // The attacker has a real signature, so this is a wrong-role
            // attempt that reaches the handler instead of failing message signing.
            metas[at] = signer_writable(attacker);
        }
        _ => {}
    }
    metas
}

fn read_seed() -> u64 {
    std::env::var("BASANOS_DCG_PREP_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0x8deb_236c_0dc0_0001u64)
}

fn signers_for<'a>(metas: &[AccountMeta], possible: &[&'a Keypair]) -> Vec<&'a Keypair> {
    let required: BTreeSet<Pubkey> = metas
        .iter()
        .filter(|meta| meta.is_signer)
        .map(|meta| meta.pubkey)
        .collect();
    possible
        .iter()
        .copied()
        .filter(|kp| required.contains(&kp.pubkey()))
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn seeded_lifecycle_refusals_are_atomic_and_unpublished_close_refunds_authority() {
    let authority = kp(0xA1);
    let attacker = kp(0xA2);
    let state = kp(0xB0);
    let base_kps = [kp(0xB1), kp(0xB2), kp(0xB3)];
    let base: [Pubkey; 3] = base_kps
        .iter()
        .map(|k| k.pubkey())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    let pt2s = Pubkey::new_from_array([0xC1; 32]);
    let decoy_keys: Vec<Pubkey> = (0..12)
        .map(|i| Pubkey::new_from_array([0x40 + i; 32]))
        .collect();
    let output_binding = pt1::pt1x_output_binding(
        &PROGRAM,
        &[&pt2s, &state.pubkey(), &base[0], &base[1], &base[2]],
        0,
        0,
        1,
    );
    let (output, _) = pt1::pt1x_output_address(&PROGRAM, &output_binding);

    let mut test = ProgramTest::new(
        "dcg_program",
        PROGRAM,
        processor!(dcg_program::process_instruction),
    );
    test.set_compute_max_units(1_400_000);
    test.add_account(
        authority.pubkey(),
        funded(system_program::ID, 10_000_000_000, vec![]),
    );
    test.add_account(
        attacker.pubkey(),
        funded(system_program::ID, 10_000_000, vec![]),
    );
    test.add_account(
        output,
        funded(
            system_program::ID,
            Rent::default().minimum_balance(16_384),
            vec![],
        ),
    );
    for (i, key) in decoy_keys.iter().enumerate() {
        let account = match i % 4 {
            0 => funded(PROGRAM, 3_000_000 + i as u64, vec![]),
            1 => funded(PROGRAM, 3_000_000 + i as u64, vec![0]),
            2 => funded(
                Pubkey::new_from_array([0xE0 + i as u8; 32]),
                3_000_000 + i as u64,
                vec![1, 2, 3],
            ),
            _ => funded(system_program::ID, 3_000_000 + i as u64, vec![]),
        };
        test.add_account(*key, account);
    }
    let mut ctx = test.start_with_context().await;

    // Create a real PT1X base allocation. Its keys, lengths, authority, state,
    // and rent are produced by System Program account creation followed by the
    // real tag-140 handler.
    let state_len = pt1::PT1X_MAX_STATE_BYTES;
    let byte_lens = [900usize, 128, 256];
    let mut create = vec![system_instruction::create_account(
        &authority.pubkey(),
        &state.pubkey(),
        Rent::default().minimum_balance(state_len),
        state_len as u64,
        &PROGRAM,
    )];
    for (byte, len) in base_kps.iter().zip(byte_lens) {
        create.push(system_instruction::create_account(
            &authority.pubkey(),
            &byte.pubkey(),
            Rent::default().minimum_balance(len),
            len as u64,
            &system_program::ID,
        ));
    }
    let all_setup_signers = [&authority, &state, &base_kps[0], &base_kps[1], &base_kps[2]];
    let conservation_keys = [
        authority.pubkey(),
        attacker.pubkey(),
        state.pubkey(),
        base[0],
        base[1],
        base[2],
        output,
    ];
    let before_create = total_lamports_except_fee_payer(&mut ctx, &conservation_keys).await;
    send_instructions(&mut ctx, &create, &all_setup_signers)
        .await
        .unwrap();
    assert_eq!(
        total_lamports_except_fee_payer(&mut ctx, &conservation_keys).await,
        before_create,
        "System allocations only move lamports within the tracked setup accounts",
    );

    let init = ix(
        140,
        vec![140],
        vec![
            signer_writable(state.pubkey()),
            signer_writable(base[0]),
            signer_writable(base[1]),
            signer_writable(base[2]),
            signer_readonly(authority.pubkey()),
            readonly(system_program::ID),
        ],
    );
    let before_init = total_lamports_except_fee_payer(&mut ctx, &conservation_keys).await;
    send_instructions(&mut ctx, &[init], &all_setup_signers)
        .await
        .unwrap();
    assert_eq!(
        total_lamports_except_fee_payer(&mut ctx, &conservation_keys).await,
        before_init,
        "PT1X assignment conserves lamports",
    );
    let pt1x = get_image(&mut ctx, state.pubkey()).await.unwrap();
    assert_eq!(&pt1x.data[..4], b"PT1X");
    assert_eq!(pt1x.data[4], 1);
    assert_output_pda_safe(&mut ctx, output, "PT1X setup").await;

    // Wrong authority, substituted base, and duplicate setup attempts must
    // leave every touched account unchanged.
    for (label, accounts, signers) in [
        (
            "tag197 wrong authority",
            vec![
                signer_writable(attacker.pubkey()),
                writable(state.pubkey()),
                writable(base[0]),
                writable(base[1]),
                writable(base[2]),
            ],
            vec![&attacker as &Keypair],
        ),
        (
            "tag197 substituted base",
            vec![
                signer_writable(authority.pubkey()),
                writable(state.pubkey()),
                writable(base[0]),
                writable(decoy_keys[2]),
                writable(base[2]),
            ],
            vec![&authority as &Keypair],
        ),
        (
            "tag197 wrong writable flag",
            vec![
                signer_writable(authority.pubkey()),
                readonly(state.pubkey()),
                writable(base[0]),
                writable(base[1]),
                writable(base[2]),
            ],
            vec![&authority as &Keypair],
        ),
        (
            "tag197 wrong-sized base",
            vec![
                signer_writable(authority.pubkey()),
                writable(state.pubkey()),
                writable(base[0]),
                writable(decoy_keys[1]),
                writable(base[2]),
            ],
            vec![&authority as &Keypair],
        ),
        (
            "duplicate PT1X initialization",
            vec![
                signer_writable(state.pubkey()),
                signer_writable(base[0]),
                signer_writable(base[1]),
                signer_writable(base[2]),
                signer_readonly(authority.pubkey()),
                readonly(system_program::ID),
            ],
            all_setup_signers.to_vec(),
        ),
    ] {
        let instruction = if label == "duplicate PT1X initialization" {
            ix(140, vec![140], accounts)
        } else {
            ix(197, vec![197], accounts)
        };
        let keys: Vec<Pubkey> = instruction
            .accounts
            .iter()
            .map(|m| m.pubkey)
            .chain([
                authority.pubkey(),
                attacker.pubkey(),
                state.pubkey(),
                base[0],
                base[1],
                base[2],
                output,
            ])
            .collect();
        let before = snapshot(&mut ctx, &keys).await;
        let result = send_instructions(&mut ctx, &[instruction], &signers).await;
        assert!(
            result.is_err(),
            "{label} unexpectedly succeeded: seed={:#x}",
            read_seed()
        );
        assert_refusal_unchanged(&mut ctx, &before, label).await;
        assert_output_pda_safe(&mut ctx, output, label).await;
    }

    // Published-template counter/deadline rules are tested in the artifact-
    // backed lifecycle suite. This handler-produced unpublished close tests
    // the concrete refund edge: only the PT1X-recorded authority receives the
    // base rent, and the closed accounts become reusable System accounts.
    let close = ix(
        197,
        vec![197],
        vec![
            signer_writable(authority.pubkey()),
            writable(state.pubkey()),
            writable(base[0]),
            writable(base[1]),
            writable(base[2]),
        ],
    );
    let before_close = snapshot(
        &mut ctx,
        &[
            authority.pubkey(),
            attacker.pubkey(),
            state.pubkey(),
            base[0],
            base[1],
            base[2],
            output,
        ],
    )
    .await;
    let refunded: u64 = [state.pubkey(), base[0], base[1], base[2]]
        .iter()
        .map(|key| {
            before_close
                .iter()
                .find(|(k, _)| k == key)
                .unwrap()
                .1
                .as_ref()
                .unwrap()
                .lamports
        })
        .sum();
    let auth_before = before_close
        .iter()
        .find(|(k, _)| *k == authority.pubkey())
        .unwrap()
        .1
        .as_ref()
        .unwrap()
        .lamports;
    let attacker_before = before_close
        .iter()
        .find(|(k, _)| *k == attacker.pubkey())
        .unwrap()
        .1
        .as_ref()
        .unwrap()
        .lamports;
    let before_close_total = total_lamports_except_fee_payer(&mut ctx, &conservation_keys).await;
    send_instructions(&mut ctx, &[close.clone()], &[&authority])
        .await
        .unwrap();
    assert_eq!(
        total_lamports_except_fee_payer(&mut ctx, &conservation_keys).await,
        before_close_total
    );
    let auth_after = get_image(&mut ctx, authority.pubkey())
        .await
        .unwrap()
        .lamports;
    let attacker_after = get_image(&mut ctx, attacker.pubkey())
        .await
        .unwrap()
        .lamports;
    assert_eq!(
        auth_after,
        auth_before + refunded,
        "tag197 must refund the recorded authority"
    );
    assert_eq!(
        attacker_after, attacker_before,
        "tag197 must not pay the closer/attacker"
    );
    assert_output_pda_safe(&mut ctx, output, "unpublished close").await;
    for key in [state.pubkey(), base[0], base[1], base[2]] {
        if let Some(closed) = get_image(&mut ctx, key).await {
            assert_eq!(
                closed.owner,
                system_program::ID,
                "closed account {key} was not returned to System"
            );
            assert_eq!(closed.lamports, 0, "closed account {key} kept a balance");
            assert!(closed.data.is_empty(), "closed account {key} kept data");
        }
    }

    // A second close and a setup replay over the same closed addresses are
    // terminal refusals. The account key cannot be hijacked into a new PT1X.
    for (label, instruction, signers) in [
        ("double close", close, vec![&authority as &Keypair]),
        (
            "reinitialize closed PT1X",
            ix(
                140,
                vec![140],
                vec![
                    signer_writable(state.pubkey()),
                    signer_writable(base[0]),
                    signer_writable(base[1]),
                    signer_writable(base[2]),
                    signer_readonly(authority.pubkey()),
                    readonly(system_program::ID),
                ],
            ),
            all_setup_signers.to_vec(),
        ),
    ] {
        let keys = [
            authority.pubkey(),
            attacker.pubkey(),
            state.pubkey(),
            base[0],
            base[1],
            base[2],
            output,
        ];
        let before = snapshot(&mut ctx, &keys).await;
        let result = send_instructions(&mut ctx, &[instruction], &signers).await;
        assert!(result.is_err(), "{label} unexpectedly succeeded");
        assert_refusal_unchanged(&mut ctx, &before, label).await;
        assert_output_pda_safe(&mut ctx, output, label).await;
    }

    let mut rng = Rng(read_seed().max(1));
    let steps = if std::env::var_os("BASANOS_DCG_PREP_LONG").is_some() {
        LONG_STEPS
    } else {
        DEFAULT_STEPS
    };
    let mut refused = 0usize;
    for step in 0..steps {
        let operation = OPERATIONS[step % OPERATIONS.len()];
        let variant = rng.index(8);
        let mut keys = nominal_keys(
            operation,
            state.pubkey(),
            base,
            authority.pubkey(),
            attacker.pubkey(),
            pt2s,
            output,
            &decoy_keys,
        );
        if variant == 4 && keys.len() > 1 {
            keys[1] = decoy_keys[rng.index(decoy_keys.len())];
        }
        if variant == 5 && keys.len() > 2 {
            keys[2] = keys[0];
        }
        if variant == 6 && !keys.is_empty() {
            keys[0] = decoy_keys[1];
        }
        // The seeded PT1O PDA is a prefunded System account. Routes through
        // 146/199/200 see this exact address even in the malformed stream.
        if matches!(operation.tag, 146 | 199 | 200) && keys.len() > 5 {
            keys[5] = output;
        }
        let accounts = metas_for(
            &mut rng,
            &keys,
            authority.pubkey(),
            attacker.pubkey(),
            state.pubkey(),
            base,
            variant % 4,
        );
        let instruction = ix(operation.tag, operation_data(operation.tag), accounts);
        let label = format!(
            "seed={:#x} step={step} tag={} mutation={variant}",
            read_seed(),
            operation.tag
        );
        let touched: Vec<Pubkey> = instruction
            .accounts
            .iter()
            .map(|meta| meta.pubkey)
            .chain([authority.pubkey(), attacker.pubkey(), output])
            .collect();
        let before = snapshot(&mut ctx, &touched).await;
        let before_total = total_lamports_except_fee_payer(&mut ctx, &touched).await;
        let possible_signers = [
            &authority,
            &attacker,
            &state,
            &base_kps[0],
            &base_kps[1],
            &base_kps[2],
        ];
        let extra_signers = signers_for(&instruction.accounts, &possible_signers);
        let result = send_instructions(&mut ctx, &[instruction], &extra_signers).await;
        assert!(
            result.is_err(),
            "generated malformed instruction succeeded: {label}"
        );
        assert_refusal_unchanged(&mut ctx, &before, &label).await;
        assert_eq!(
            total_lamports_except_fee_payer(&mut ctx, &touched).await,
            before_total,
            "refused instruction did not conserve non-fee lamports: {label}"
        );
        refused += 1;

        // The only output PDA in this first version is the pre-funded PT1O
        // derived from the operation's exact binding. No instruction may
        // leave a program-owned all-zero account there.
        assert_output_pda_safe(&mut ctx, output, &label).await;
    }
    eprintln!(
        "dcg_prep_lifecycle seed={:#x} generated={steps} refused={refused} native=true",
        read_seed()
    );
}
