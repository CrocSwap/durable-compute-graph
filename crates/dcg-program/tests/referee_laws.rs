//! Native ProgramTest checks for referee laws expressible without the retained
//! PT2P artifact fixture: authority, rent conservation, named refund, and a
//! terminal close. This is lifecycle mechanics, not a dispute soundness test.
#![cfg(feature = "revision-8")]

use solana_account::Account;
use solana_instruction::{account_meta::AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_program::{
    instruction::InstructionError, rent::Rent, system_instruction, system_program,
};
use solana_program_test::{processor, ProgramTest, ProgramTestContext};
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;
use solana_transaction_error::TransactionError;
use std::collections::BTreeSet;

const PROGRAM: Pubkey = Pubkey::new_from_array([0xD8; 32]);

fn kp(byte: u8) -> Keypair {
    Keypair::new_from_array([byte; 32])
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

fn writable(key: Pubkey) -> AccountMeta {
    AccountMeta::new(key, false)
}

fn signer_writable(key: Pubkey) -> AccountMeta {
    AccountMeta::new(key, true)
}

#[derive(Debug, PartialEq, Eq)]
struct AccountImage {
    lamports: u64,
    data: Vec<u8>,
    owner: Pubkey,
    executable: bool,
    rent_epoch: u64,
}

fn ix(tag: u8, accounts: Vec<AccountMeta>) -> Instruction {
    Instruction {
        program_id: PROGRAM,
        accounts,
        data: vec![tag],
    }
}

async fn send(
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
    let result = ctx
        .banks_client
        .process_transaction_with_metadata(tx)
        .await
        .map_err(|error| error.unwrap())?;
    result.result
}

async fn account(ctx: &mut ProgramTestContext, key: Pubkey) -> Account {
    ctx.banks_client
        .get_account(key)
        .await
        .unwrap()
        .expect("tracked account exists")
}

async fn image(ctx: &mut ProgramTestContext, key: Pubkey) -> Option<AccountImage> {
    ctx.banks_client
        .get_account(key)
        .await
        .unwrap()
        .map(|value| AccountImage {
            lamports: value.lamports,
            data: value.data,
            owner: value.owner,
            executable: value.executable,
            rent_epoch: value.rent_epoch,
        })
}

async fn total_tracked(ctx: &mut ProgramTestContext, keys: &[Pubkey]) -> u128 {
    let unique: BTreeSet<Pubkey> = keys.iter().copied().collect();
    let mut total = 0u128;
    for key in unique {
        if let Some(value) = ctx.banks_client.get_account(key).await.unwrap() {
            total += u128::from(value.lamports);
        }
    }
    total
}

#[tokio::test(flavor = "multi_thread")]
async fn referee_authority_rent_and_terminal_close_laws() {
    let authority = kp(0xA1);
    let attacker = kp(0xA2);
    let state = kp(0xB0);
    let bases = [kp(0xB1), kp(0xB2), kp(0xB3)];
    let base_keys = [&bases[0], &bases[1], &bases[2]].map(|key| key.pubkey());
    let protected = Pubkey::new_from_array([0xC1; 32]);

    let mut test = ProgramTest::default();
    test.prefer_bpf(false);
    test.add_program(
        "dcg_program",
        PROGRAM,
        processor!(dcg_program::process_instruction),
    );
    test.add_account(
        authority.pubkey(),
        funded(system_program::ID, 10_000_000_000, vec![]),
    );
    test.add_account(
        attacker.pubkey(),
        funded(system_program::ID, 10_000_000, vec![]),
    );
    test.add_account(
        protected,
        funded(PROGRAM, 5_000_000, b"do-not-overwrite".to_vec()),
    );
    let mut ctx = test.start_with_context().await;

    // Legacy tag 98 is not dispatched in revision 8. Passing a writable
    // program-owned account and an unrelated signer must not grant write access.
    let protected_before = image(&mut ctx, protected).await.unwrap();
    let result = send(
        &mut ctx,
        &[Instruction {
            program_id: PROGRAM,
            accounts: vec![signer_writable(attacker.pubkey()), writable(protected)],
            data: vec![98],
        }],
        &[&attacker],
    )
    .await;
    assert!(matches!(
        result,
        Err(TransactionError::InstructionError(
            _,
            InstructionError::InvalidInstructionData
        ))
    ));
    assert_eq!(image(&mut ctx, protected).await, Some(protected_before));

    // Create handler-produced PT1X state and base allocations. System account
    // creation transfers exact rent from the recorded authority into the new
    // accounts; tag 140 assigns the signed byte accounts to the program.
    let byte_lens = [900usize, 128, 256];
    let mut create = vec![system_instruction::create_account(
        &authority.pubkey(),
        &state.pubkey(),
        Rent::default().minimum_balance(dcg_program::pt1_onchain::PT1X_MAX_STATE_BYTES),
        dcg_program::pt1_onchain::PT1X_MAX_STATE_BYTES as u64,
        &PROGRAM,
    )];
    for (base, len) in bases.iter().zip(byte_lens) {
        create.push(system_instruction::create_account(
            &authority.pubkey(),
            &base.pubkey(),
            Rent::default().minimum_balance(len),
            len as u64,
            &system_program::ID,
        ));
    }
    let tracked = [
        authority.pubkey(),
        attacker.pubkey(),
        state.pubkey(),
        base_keys[0],
        base_keys[1],
        base_keys[2],
    ];
    let before_create = total_tracked(&mut ctx, &tracked).await;
    send(
        &mut ctx,
        &create,
        &[&authority, &state, &bases[0], &bases[1], &bases[2]],
    )
    .await
    .unwrap();
    assert_eq!(total_tracked(&mut ctx, &tracked).await, before_create);

    let init = Instruction {
        program_id: PROGRAM,
        accounts: vec![
            signer_writable(state.pubkey()),
            signer_writable(base_keys[0]),
            signer_writable(base_keys[1]),
            signer_writable(base_keys[2]),
            AccountMeta::new_readonly(authority.pubkey(), true),
            AccountMeta::new_readonly(system_program::ID, false),
        ],
        data: vec![140],
    };
    let before_init = total_tracked(&mut ctx, &tracked).await;
    send(
        &mut ctx,
        &[init],
        &[&authority, &state, &bases[0], &bases[1], &bases[2]],
    )
    .await
    .unwrap();
    assert_eq!(total_tracked(&mut ctx, &tracked).await, before_init);
    assert_eq!(&account(&mut ctx, state.pubkey()).await.data[..4], b"PT1X");

    let close_with = |who| {
        ix(
            197,
            vec![
                signer_writable(who),
                writable(state.pubkey()),
                writable(base_keys[0]),
                writable(base_keys[1]),
                writable(base_keys[2]),
            ],
        )
    };
    // Snapshot explicitly so a rejected close proves no program-state change.
    let mut bad_snapshot = Vec::new();
    for key in tracked.iter().copied() {
        bad_snapshot.push((key, image(&mut ctx, key).await));
    }
    let total_before_bad_close = total_tracked(&mut ctx, &tracked).await;
    assert!(
        send(&mut ctx, &[close_with(attacker.pubkey())], &[&attacker])
            .await
            .is_err()
    );
    assert_eq!(
        total_tracked(&mut ctx, &tracked).await,
        total_before_bad_close
    );
    for (key, before) in bad_snapshot {
        assert_eq!(image(&mut ctx, key).await, before);
    }

    // Only the PT1X-recorded authority can close; every allocation's balance
    // returns to that authority, not to the caller. The close makes each child
    // a zero-balance, empty System account, and a second close refuses.
    let authority_before = account(&mut ctx, authority.pubkey()).await.lamports;
    let attacker_before = account(&mut ctx, attacker.pubkey()).await.lamports;
    let mut rent_refund = 0u64;
    for key in [state.pubkey(), base_keys[0], base_keys[1], base_keys[2]] {
        rent_refund += account(&mut ctx, key).await.lamports;
    }
    let total_before_close = total_tracked(&mut ctx, &tracked).await;
    send(&mut ctx, &[close_with(authority.pubkey())], &[&authority])
        .await
        .unwrap();
    assert_eq!(total_tracked(&mut ctx, &tracked).await, total_before_close);
    assert_eq!(
        account(&mut ctx, authority.pubkey()).await.lamports,
        authority_before + rent_refund
    );
    assert_eq!(
        account(&mut ctx, attacker.pubkey()).await.lamports,
        attacker_before
    );
    for key in [state.pubkey(), base_keys[0], base_keys[1], base_keys[2]] {
        if let Some(closed) = image(&mut ctx, key).await {
            assert_eq!(closed.owner, system_program::ID);
            assert_eq!(closed.lamports, 0);
            assert!(closed.data.is_empty());
        }
    }
    let mut after_close = Vec::new();
    for key in tracked.iter().copied() {
        after_close.push((key, image(&mut ctx, key).await));
    }
    assert!(
        send(&mut ctx, &[close_with(authority.pubkey())], &[&authority])
            .await
            .is_err()
    );
    for (key, before) in after_close {
        assert_eq!(image(&mut ctx, key).await, before);
    }
}
