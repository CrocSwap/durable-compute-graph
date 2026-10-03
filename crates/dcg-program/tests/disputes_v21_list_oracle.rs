//! Tag-227 native/SBF execution of Python's DLS1 list-input oracle vectors.
#![cfg(feature = "graph-v21")]

use dcg_disputes as D;
use dcg_program::disputes_v21 as V;
use dcg_program::hash::sha256;
use solana_account::Account;
use solana_instruction::{account_meta::AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_program::system_program;
use solana_program_test::{processor, ProgramTest, ProgramTestContext};
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;
use solana_transaction_error::TransactionError;

const PROGRAM: Pubkey = Pubkey::new_from_array([0xD7; 32]);
const SYSTEM: Pubkey = system_program::ID;
const STAGE_CHUNK: usize = 700;

struct Soft;
impl D::Sha256 for Soft {
    fn hash(&self, parts: &[&[u8]]) -> D::Hash {
        sha256(parts)
    }
}

fn kp(b: u8) -> Keypair {
    Keypair::new_from_array([b; 32])
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn levels(tree: D::Tree, leaves: &[D::Hash]) -> Vec<Vec<D::Hash>> {
    let n = leaves.len().max(1);
    let height = usize::BITS - (n - 1).leading_zeros();
    let mut row = leaves.to_vec();
    row.resize(1 << height, D::empty(&Soft, tree, 0));
    let mut out = vec![row.clone()];
    for level in 0..height {
        row = row
            .chunks(2)
            .map(|p| D::node(&Soft, tree, level as u16, &p[0], &p[1]))
            .collect();
        out.push(row.clone());
    }
    out
}

fn path(levels: &[Vec<D::Hash>], mut position: usize) -> Vec<u8> {
    let mut out = vec![(levels.len() - 1) as u8];
    for row in &levels[..levels.len() - 1] {
        out.extend_from_slice(&row[position ^ 1]);
        position >>= 1;
    }
    out
}

fn ix(sub: u8, data: &[u8], accounts: Vec<AccountMeta>) -> Instruction {
    let mut body = vec![V::TAG, sub];
    body.extend_from_slice(data);
    Instruction {
        program_id: PROGRAM,
        accounts,
        data: body,
    }
}

async fn send(
    ctx: &mut ProgramTestContext,
    instruction: Instruction,
    signers: &[&Keypair],
) -> Result<(), TransactionError> {
    let blockhash = ctx.get_new_latest_blockhash().await.unwrap();
    let mut all = vec![&ctx.payer];
    all.extend_from_slice(signers);
    let ixs = vec![
        solana_compute_budget_interface::ComputeBudgetInstruction::set_compute_unit_limit(
            1_400_000,
        ),
        instruction,
    ];
    let tx = Transaction::new(
        &all,
        solana_message::Message::new(&ixs, Some(&ctx.payer.pubkey())),
        blockhash,
    );
    ctx.banks_client
        .process_transaction_with_metadata(tx)
        .await
        .map_err(|e| e.unwrap())?
        .result
}

fn account(k: Pubkey, writable: bool, signer: bool) -> AccountMeta {
    if writable {
        AccountMeta::new(k, signer)
    } else {
        AccountMeta::new_readonly(k, signer)
    }
}

async fn stage_write(
    ctx: &mut ProgramTestContext,
    signer: &Keypair,
    run: Pubkey,
    template: Pubkey,
    dispute: Pubkey,
    buffer: Pubkey,
    bytes: &[u8],
) {
    for (i, chunk) in bytes.chunks(STAGE_CHUNK).enumerate() {
        let offset = i * STAGE_CHUNK;
        let mut data = (offset as u32).to_le_bytes().to_vec();
        data.extend_from_slice(chunk);
        let accounts = vec![
            account(signer.pubkey(), false, true),
            account(run, false, false),
            account(template, false, false),
            account(dispute, false, false),
            account(buffer, true, false),
        ];
        send(ctx, ix(V::SUB_STAGE_WRITE, &data, accounts), &[signer])
            .await
            .unwrap();
    }
}

async fn new_test() -> ProgramTestContext {
    let sbf = std::env::var("V21_SBF").is_ok_and(|v| v == "1");
    let mut test = ProgramTest::default();
    test.prefer_bpf(sbf);
    if sbf {
        test.add_program("dcg_program", PROGRAM, None);
    } else {
        test.add_program(
            "dcg_program",
            PROGRAM,
            processor!(dcg_program::process_instruction),
        );
    }
    for b in [0xA1u8, 0xE1, 0xC1] {
        test.add_account(
            kp(b).pubkey(),
            Account {
                lamports: 10_000_000_000,
                data: vec![],
                owner: SYSTEM,
                executable: false,
                rent_epoch: 0,
            },
        );
    }
    test.start_with_context().await
}

async fn replay(
    setup: &serde_json::Value,
    commits: &serde_json::Value,
    scenario: &serde_json::Value,
    nonce: u8,
) -> u8 {
    let mut ctx = new_test().await;
    let (admitter, executor, challenger) = (kp(0xA1), kp(0xE1), kp(0xC1));
    let template_data = hex(setup["template_data"].as_str().unwrap());
    let template_id = sha256(&[V::TEMPLATE_DOMAIN, &template_data]);
    assert_eq!(
        template_id.as_slice(),
        hex(setup["template_id"].as_str().unwrap())
    );
    let template = Pubkey::find_program_address(&[b"dcg21tmpl", &template_id], &PROGRAM).0;
    send(
        &mut ctx,
        ix(
            V::SUB_CREATE_TEMPLATE,
            &template_data,
            vec![
                account(admitter.pubkey(), true, true),
                account(template, true, false),
                account(SYSTEM, false, false),
            ],
        ),
        &[&admitter],
    )
    .await
    .unwrap();

    let refs: Vec<Vec<u8>> = setup["refs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| hex(r.as_str().unwrap()))
        .collect();
    let mut init = vec![0u8; 32];
    init.extend_from_slice(executor.pubkey().as_ref());
    init.extend_from_slice(&(refs.len() as u32).to_le_bytes());
    for r in &refs {
        init.extend_from_slice(r);
    }
    let mut flat = Vec::new();
    for r in &refs {
        flat.extend_from_slice(r);
    }
    let run_id = sha256(&[
        b"dcg.run.id.v2.1\x00",
        &template_id,
        &[0u8; 32],
        &(refs.len() as u32).to_le_bytes(),
        &flat,
        executor.pubkey().as_ref(),
    ]);
    assert_eq!(run_id.as_slice(), hex(setup["run_id"].as_str().unwrap()));
    let run = Pubkey::find_program_address(
        &[b"dcg21run", &run_id, admitter.pubkey().as_ref()],
        &PROGRAM,
    )
    .0;
    send(
        &mut ctx,
        ix(
            V::SUB_INIT_RUN,
            &init,
            vec![
                account(admitter.pubkey(), true, true),
                account(run, true, false),
                account(template, true, false),
                account(SYSTEM, false, false),
            ],
        ),
        &[&admitter],
    )
    .await
    .unwrap();

    let commit = &commits[scenario["commit"].as_str().unwrap()];
    let leaves: Vec<Option<Vec<u8>>> = commit["leaves"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_str().map(hex))
        .collect();
    let outs: Vec<Option<Vec<u8>>> = commit["out_entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_str().map(hex))
        .collect();
    let step = levels(
        D::Tree::Step,
        &leaves
            .iter()
            .map(|l| D::leaf_hash(&Soft, l.as_deref()))
            .collect::<Vec<_>>(),
    );
    let out = levels(
        D::Tree::Out,
        &outs
            .iter()
            .enumerate()
            .map(|(j, x)| D::out_leaf(&Soft, j as u64, x.as_deref()))
            .collect::<Vec<_>>(),
    );
    let records: Vec<(u8, Vec<u8>)> = setup["spec_records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| (r[0].as_u64().unwrap() as u8, hex(r[1].as_str().unwrap())))
        .collect();
    let spec = levels(
        D::Tree::Spec,
        &records
            .iter()
            .map(|(t, r)| D::spec_leaf(&Soft, *t, r))
            .collect::<Vec<_>>(),
    );
    assert_eq!(
        spec.last().unwrap()[0].as_slice(),
        hex(setup["spec_root"].as_str().unwrap())
    );
    let mut root = hex(setup["plan_id"].as_str().unwrap());
    root.extend_from_slice(&run_id);
    root.extend_from_slice(&spec.last().unwrap()[0]);
    root.extend_from_slice(&(leaves.len() as u64).to_le_bytes());
    root.extend_from_slice(&step.last().unwrap()[0]);
    root.extend_from_slice(&(outs.len() as u64).to_le_bytes());
    root.extend_from_slice(&out.last().unwrap()[0]);
    send(
        &mut ctx,
        ix(
            V::SUB_COMMIT,
            &root,
            vec![
                account(executor.pubkey(), true, true),
                account(run, true, false),
                account(template, false, false),
                account(SYSTEM, false, false),
            ],
        ),
        &[&executor],
    )
    .await
    .unwrap();

    let dispute_nonce = [nonce; 32];
    let dispute = Pubkey::find_program_address(
        &[
            b"dcg21dsp",
            run.as_ref(),
            challenger.pubkey().as_ref(),
            &dispute_nonce,
        ],
        &PROGRAM,
    )
    .0;
    let mut open = dispute_nonce.to_vec();
    open.push(V::KIND_STEP_DESCEND);
    send(
        &mut ctx,
        ix(
            V::SUB_OPEN,
            &open,
            vec![
                account(challenger.pubkey(), true, true),
                account(run, true, false),
                account(template, false, false),
                account(dispute, true, false),
                account(SYSTEM, false, false),
            ],
        ),
        &[&challenger],
    )
    .await
    .unwrap();

    let depth = setup["template_data"].as_str().unwrap();
    let template_depth = hex(depth)[0] as usize;
    let mut level = step.len() - 1;
    let mut position = 0usize;
    for pick in scenario["picks"].as_array().unwrap() {
        let d = template_depth.min(level);
        let base = level - d;
        let mut hashes = Vec::new();
        for i in 0..1usize << d {
            let p = (position << d) + i;
            if (p << base) < leaves.len() {
                hashes.extend_from_slice(&step[base][p]);
            }
        }
        let accounts = vec![
            account(executor.pubkey(), false, true),
            account(run, false, false),
            account(template, false, false),
            account(dispute, true, false),
        ];
        send(
            &mut ctx,
            ix(V::SUB_REVEAL_NODES, &hashes, accounts),
            &[&executor],
        )
        .await
        .unwrap();
        let selected = pick.as_u64().unwrap() as usize;
        let accounts = vec![
            account(challenger.pubkey(), false, true),
            account(run, false, false),
            account(template, false, false),
            account(dispute, true, false),
        ];
        send(
            &mut ctx,
            ix(V::SUB_PICK, &[selected as u8], accounts),
            &[&challenger],
        )
        .await
        .unwrap();
        level = base;
        position = (position << d) + selected;
    }
    assert_eq!(level, 0);
    assert_eq!(position as u64, scenario["position"].as_u64().unwrap());

    let executor_buffer = Pubkey::find_program_address(
        &[b"dcg21stg", dispute.as_ref(), &[V::ROLE_EXECUTOR]],
        &PROGRAM,
    )
    .0;
    send(
        &mut ctx,
        ix(
            V::SUB_STAGE_CREATE,
            &[V::ROLE_EXECUTOR, 0, 0, 0, 0],
            vec![
                account(executor.pubkey(), true, true),
                account(run, false, false),
                account(template, false, false),
                account(dispute, false, false),
                account(executor_buffer, true, false),
                account(SYSTEM, false, false),
            ],
        ),
        &[&executor],
    )
    .await
    .unwrap();
    let reveal = hex(scenario["staged_leaf_reveal"].as_str().unwrap());
    stage_write(
        &mut ctx,
        &executor,
        run,
        template,
        dispute,
        executor_buffer,
        &reveal,
    )
    .await;
    send(
        &mut ctx,
        ix(
            V::SUB_REVEAL_LEAF,
            &[V::FROM_STAGING],
            vec![
                account(executor.pubkey(), false, true),
                account(run, false, false),
                account(template, false, false),
                account(dispute, true, false),
                account(executor_buffer, false, false),
            ],
        ),
        &[&executor],
    )
    .await
    .unwrap();

    let claim_body = hex(scenario["claim_body"].as_str().unwrap());
    let challenger_buffer = Pubkey::find_program_address(
        &[b"dcg21stg", dispute.as_ref(), &[V::ROLE_CHALLENGER]],
        &PROGRAM,
    )
    .0;
    let mut create_c = vec![V::ROLE_CHALLENGER];
    create_c.extend_from_slice(&(claim_body.len() as u32).to_le_bytes());
    send(
        &mut ctx,
        ix(
            V::SUB_STAGE_CREATE,
            &create_c,
            vec![
                account(challenger.pubkey(), true, true),
                account(run, false, false),
                account(template, false, false),
                account(dispute, false, false),
                account(challenger_buffer, true, false),
                account(SYSTEM, false, false),
            ],
        ),
        &[&challenger],
    )
    .await
    .unwrap();
    if let Some(forged) = scenario["forged_claim_body"].as_str() {
        stage_write(
            &mut ctx,
            &challenger,
            run,
            template,
            dispute,
            challenger_buffer,
            &hex(forged),
        )
        .await;
        let accounts = vec![
            account(challenger.pubkey(), false, true),
            account(run, true, false),
            account(template, false, false),
            account(dispute, true, false),
            account(executor.pubkey(), true, false),
            account(challenger.pubkey(), true, false),
            account(challenger_buffer, true, false),
            account(executor_buffer, false, false),
        ];
        assert!(
            send(
                &mut ctx,
                ix(V::SUB_CLAIM, &[V::FROM_STAGING], accounts),
                &[&challenger]
            )
            .await
            .is_err(),
            "forged ListSpec proof was accepted"
        );
    }
    stage_write(
        &mut ctx,
        &challenger,
        run,
        template,
        dispute,
        challenger_buffer,
        &claim_body,
    )
    .await;
    let accounts = vec![
        account(challenger.pubkey(), false, true),
        account(run, true, false),
        account(template, false, false),
        account(dispute, true, false),
        account(executor.pubkey(), true, false),
        account(challenger.pubkey(), true, false),
        account(challenger_buffer, true, false),
        account(executor_buffer, false, false),
    ];
    send(
        &mut ctx,
        ix(V::SUB_CLAIM, &[V::FROM_STAGING], accounts),
        &[&challenger],
    )
    .await
    .unwrap_or_else(|err| panic!("{}: claim accepted: {err:?}", scenario["name"].as_str().unwrap()));
    ctx.banks_client
        .get_account(dispute)
        .await
        .unwrap()
        .unwrap()
        .data[6]
}

#[tokio::test(flavor = "multi_thread")]
async fn program_rules_list_input_oracle_scenarios() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/golden/dcg/disputes_v21/list_scenarios.json"
    );
    let data: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let scenarios = data["scenarios"].as_array().unwrap();
    assert_eq!(scenarios.len(), 11);
    let mut mismatches = Vec::new();
    for (i, scenario) in scenarios.iter().enumerate() {
        let setup = &data["setups"][scenario["setup"].as_str().unwrap()];
        let got = replay(setup, &data["commits"], scenario, i as u8 + 1).await;
        let want = if scenario["ruling"] == "C" {
            V::RULING_CHALLENGER
        } else {
            V::RULING_EXECUTOR
        };
        if got != want {
            mismatches.push(format!(
                "{}: got {got}, want {want}",
                scenario["name"].as_str().unwrap()
            ));
        }
    }
    assert!(mismatches.is_empty(), "{mismatches:#?}");
}
