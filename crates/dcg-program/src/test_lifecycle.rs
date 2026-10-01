// SPDX-License-Identifier: GPL-3.0-only

//! Fixed-size application adapter used only by the SBF lifecycle canary.
//!
//! These test instructions are deliberately not a graph/sweep format. They
//! exercise a compiled kernel manifest and the optimistic one-step replay
//! seam in an SBF image, using one four-entry ByteSum trace.

use crate::account_provenance::CanonicalBump;
use crate::kernel::{
    test_kernel::{MANIFEST_APP, MODE_OPTIMISTIC_V1},
    KernelId, ModeId,
};
use solana_program::{
    account_info::AccountInfo, entrypoint::ProgramResult, program::invoke_signed,
    program_error::ProgramError, pubkey::Pubkey, rent::Rent, system_instruction, system_program,
    sysvar::Sysvar,
};

pub const TAG_REGISTER_TEMPLATE: u8 = 240;
pub const TAG_ADMIT: u8 = 241;
pub const TAG_INIT_DOCUMENT: u8 = 242;
pub const TAG_LAND_ROOTS: u8 = 243;
pub const TAG_FINALIZE: u8 = 244;
pub const TAG_RESOLVE: u8 = 245;
pub const TAG_CHALLENGE: u8 = 246;
pub const TAG_BISECT: u8 = 247;
pub const TAG_REPLAY: u8 = 248;
pub const TAG_SETTLE: u8 = 249;
pub const TAG_CLOSE: u8 = 250;

const REFUSAL: u32 = 900;
const TEMPLATE_BYTES: usize = 128;
const DOCUMENT_BYTES: usize = 368;
const BOND_BYTES: usize = 16;
const ENTRY_COUNT: usize = 4;
const ENTRY_BYTES: usize = 17;
const ENTRY_AT: usize = 288;
const CLAIM_CHEATER: u8 = 1;
const CLAIM_HONEST: u8 = 2;
pub const TEST_STAKE_LAMPORTS: u64 = 2_000_000;
const LEAF_DOMAIN: &[u8] = b"dcg-test-bytesum-leaf/1";
const NODE_DOMAIN: &[u8] = b"dcg-test-bytesum-node/1";

fn refusal() -> ProgramError {
    ProgramError::Custom(REFUSAL)
}

fn exact_data(data: &[u8], len: usize) -> ProgramResult {
    if data.len() == len {
        Ok(())
    } else {
        Err(ProgramError::InvalidInstructionData)
    }
}

fn check_pda(
    program: &Pubkey,
    account: &AccountInfo,
    seeds: &[&[u8]],
    writable: bool,
) -> ProgramResult {
    if account.owner != program || (writable && !account.is_writable) {
        return Err(refusal());
    }
    let expected = Pubkey::find_program_address(seeds, program).0;
    if *account.key != expected {
        return Err(refusal());
    }
    Ok(())
}

fn create_pda<'a>(
    program: &Pubkey,
    payer: &AccountInfo<'a>,
    account: &AccountInfo<'a>,
    system: &AccountInfo<'a>,
    seeds: &[&[u8]],
    bump: CanonicalBump,
    bytes: usize,
    lamports: u64,
) -> ProgramResult {
    if !payer.is_signer
        || !payer.is_writable
        || !account.is_writable
        || *system.key != system_program::id()
        || account.owner != &system_program::id()
        || account.lamports() != 0
        || !account.data_is_empty()
        || lamports < Rent::get()?.minimum_balance(bytes)
    {
        solana_program::msg!("test lifecycle create-account precondition failed");
        return Err(refusal());
    }
    if account.key != bump.address() {
        return Err(refusal());
    }
    let bump_seed = [bump.value()];
    let mut signer_seeds = seeds.to_vec();
    signer_seeds.push(&bump_seed);
    invoke_signed(
        &system_instruction::create_account(
            payer.key,
            account.key,
            lamports,
            bytes as u64,
            program,
        ),
        &[payer.clone(), account.clone(), system.clone()],
        &[&signer_seeds],
    )?;
    Ok(())
}

#[derive(Clone, Copy, Debug)]
struct KernelRef {
    id: KernelId,
    semantic_version: u16,
    abi_version: u16,
    mode: ModeId,
}

fn registered_kernel(raw: &[u8]) -> Result<KernelRef, ProgramError> {
    if raw.len() != TEMPLATE_BYTES || raw[..4] != *b"DTPL" || raw[4..6] != 1u16.to_le_bytes() {
        return Err(refusal());
    }
    let kernel = KernelRef {
        id: KernelId(raw[40..56].try_into().map_err(|_| refusal())?),
        semantic_version: u16::from_le_bytes(raw[56..58].try_into().map_err(|_| refusal())?),
        abi_version: u16::from_le_bytes(raw[58..60].try_into().map_err(|_| refusal())?),
        mode: ModeId {
            id: u32::from_le_bytes(raw[60..64].try_into().map_err(|_| refusal())?),
            version: u16::from_le_bytes(raw[64..66].try_into().map_err(|_| refusal())?),
        },
    };
    Ok(kernel)
}

fn checked_template(
    program: &Pubkey,
    template: &AccountInfo,
    authority: &Pubkey,
    case_id: u8,
    admitted: bool,
) -> Result<KernelRef, ProgramError> {
    let case_seed = [case_id];
    check_pda(
        program,
        template,
        &[b"dcg-test-template", authority.as_ref(), &case_seed],
        false,
    )?;
    let raw = template.try_borrow_data()?;
    let kernel = registered_kernel(&raw)?;
    let expected_status = if admitted { 2 } else { 1 };
    if raw[6] != expected_status
        || raw[7] != case_id
        || raw[8..40] != authority.to_bytes()
        || raw[66..68] != MANIFEST_APP.version.to_le_bytes()
        || raw[68..100] != crate::hash::sha256(&[MANIFEST_APP.application_id])
        || MANIFEST_APP
            .resolve(kernel.id, kernel.semantic_version, kernel.abi_version)
            .is_none()
        || !MANIFEST_APP.supports_mode(
            kernel.id,
            kernel.semantic_version,
            kernel.abi_version,
            kernel.mode,
        )
    {
        return Err(refusal());
    }
    Ok(kernel)
}

fn entry(raw: &[u8], index: usize) -> Result<(&[u8], &[u8]), ProgramError> {
    if index >= ENTRY_COUNT || raw.len() != DOCUMENT_BYTES {
        return Err(refusal());
    }
    let at = ENTRY_AT + index * ENTRY_BYTES;
    let input_len = raw[at] as usize;
    if input_len > 8
        || raw[at + 1 + input_len..at + 9]
            .iter()
            .any(|byte| *byte != 0)
    {
        return Err(refusal());
    }
    Ok((&raw[at + 1..at + 1 + input_len], &raw[at + 9..at + 17]))
}

fn leaf(case_id: u8, index: usize, input: &[u8], output: &[u8]) -> [u8; 32] {
    crate::hash::sha256(&[
        LEAF_DOMAIN,
        &[case_id, index as u8, input.len() as u8],
        input,
        output,
    ])
}

fn node(case_id: u8, level: u8, first: u8, left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    crate::hash::sha256(&[NODE_DOMAIN, &[case_id, level, first], left, right])
}

fn claimed_leaf(raw: &[u8], index: usize) -> Result<[u8; 32], ProgramError> {
    let (input, output) = entry(raw, index)?;
    Ok(leaf(raw[7], index, input, output))
}

fn claimed_root(raw: &[u8]) -> Result<[u8; 32], ProgramError> {
    let leaves = [
        claimed_leaf(raw, 0)?,
        claimed_leaf(raw, 1)?,
        claimed_leaf(raw, 2)?,
        claimed_leaf(raw, 3)?,
    ];
    let left = node(raw[7], 1, 0, &leaves[0], &leaves[1]);
    let right = node(raw[7], 1, 2, &leaves[2], &leaves[3]);
    Ok(node(raw[7], 2, 0, &left, &right))
}

fn checked_document(
    program: &Pubkey,
    template: &AccountInfo,
    document: &AccountInfo,
    executor: &Pubkey,
    case_id: u8,
    writable: bool,
) -> Result<KernelRef, ProgramError> {
    let template_key = template.key.to_bytes();
    let case_seed = [case_id];
    check_pda(
        program,
        document,
        &[b"dcg-test-document", &template_key, &case_seed],
        writable,
    )?;
    let raw = document.try_borrow_data()?;
    if raw.len() != DOCUMENT_BYTES
        || raw[..4] != *b"DDOC"
        || raw[4..6] != 1u16.to_le_bytes()
        || raw[7] != case_id
        || raw[8..40] != template_key
        || raw[72..104] != executor.to_bytes()
        || raw[235] as usize != ENTRY_COUNT
    {
        return Err(refusal());
    }
    let authority: [u8; 32] = raw[40..72].try_into().map_err(|_| refusal())?;
    drop(raw);
    checked_template(
        program,
        template,
        &Pubkey::new_from_array(authority),
        case_id,
        true,
    )
}

pub fn process(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let Some(tag) = data.first().copied() else {
        return Err(ProgramError::InvalidInstructionData);
    };
    match tag {
        TAG_REGISTER_TEMPLATE => register_template(program, accounts, data),
        TAG_ADMIT => admit(program, accounts, data),
        TAG_INIT_DOCUMENT => init_document(program, accounts, data),
        TAG_LAND_ROOTS => land_roots(program, accounts, data),
        TAG_FINALIZE => finalize(program, accounts, data),
        TAG_RESOLVE => resolve(program, accounts, data),
        TAG_CHALLENGE => challenge(program, accounts, data),
        TAG_BISECT => bisect(program, accounts, data),
        TAG_REPLAY => replay(program, accounts, data),
        TAG_SETTLE => settle(program, accounts, data),
        TAG_CLOSE => close(program, accounts, data),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

fn register_template(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    exact_data(data, 28)?;
    let [authority, template, system] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !authority.is_signer || !authority.is_writable {
        solana_program::msg!("test lifecycle registration authority refused");
        return Err(refusal());
    }
    if let Err(error) = MANIFEST_APP.validate() {
        solana_program::msg!("test lifecycle compiled manifest is invalid: {:?}", error);
        return Err(refusal());
    }
    let case_id = data[1];
    let identity = KernelRef {
        id: KernelId(
            data[2..18]
                .try_into()
                .map_err(|_| ProgramError::InvalidInstructionData)?,
        ),
        semantic_version: u16::from_le_bytes(data[18..20].try_into().unwrap()),
        abi_version: u16::from_le_bytes(data[20..22].try_into().unwrap()),
        mode: ModeId {
            id: u32::from_le_bytes(data[22..26].try_into().unwrap()),
            version: u16::from_le_bytes(data[26..28].try_into().unwrap()),
        },
    };
    let registered = MANIFEST_APP
        .resolve(identity.id, identity.semantic_version, identity.abi_version)
        .is_some();
    let replay_registered = MANIFEST_APP
        .resolve_optimistic_replay(
            identity.id,
            identity.semantic_version,
            identity.abi_version,
            identity.mode,
        )
        .is_some();
    if !registered || !replay_registered {
        solana_program::msg!("test lifecycle kernel or optimistic replay is not registered");
        return Err(refusal());
    }
    let case_seed = [case_id];
    let bump = CanonicalBump::find(
        &[b"dcg-test-template", authority.key.as_ref(), &case_seed],
        program,
    );
    if template.key != bump.address() {
        solana_program::msg!("test lifecycle template PDA mismatch");
        return Err(refusal());
    }
    create_pda(
        program,
        authority,
        template,
        system,
        &[b"dcg-test-template", authority.key.as_ref(), &case_seed],
        bump,
        TEMPLATE_BYTES,
        Rent::get()?.minimum_balance(TEMPLATE_BYTES),
    )?;
    let mut raw = template.try_borrow_mut_data()?;
    raw[..4].copy_from_slice(b"DTPL");
    raw[4..6].copy_from_slice(&1u16.to_le_bytes());
    raw[6] = 1;
    raw[7] = case_id;
    raw[8..40].copy_from_slice(authority.key.as_ref());
    raw[40..56].copy_from_slice(&identity.id.0);
    raw[56..58].copy_from_slice(&identity.semantic_version.to_le_bytes());
    raw[58..60].copy_from_slice(&identity.abi_version.to_le_bytes());
    raw[60..64].copy_from_slice(&identity.mode.id.to_le_bytes());
    raw[64..66].copy_from_slice(&identity.mode.version.to_le_bytes());
    raw[66..68].copy_from_slice(&MANIFEST_APP.version.to_le_bytes());
    raw[68..100].copy_from_slice(&crate::hash::sha256(&[MANIFEST_APP.application_id]));
    Ok(())
}

fn admit(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    exact_data(data, 2)?;
    let [authority, template] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !authority.is_signer {
        return Err(refusal());
    }
    let case_seed = [data[1]];
    check_pda(
        program,
        template,
        &[b"dcg-test-template", authority.key.as_ref(), &case_seed],
        true,
    )?;
    let mut raw = template.try_borrow_mut_data()?;
    let kernel = registered_kernel(&raw)?;
    if raw[6] != 1
        || raw[7] != data[1]
        || raw[8..40] != authority.key.to_bytes()
        || raw[66..68] != MANIFEST_APP.version.to_le_bytes()
        || raw[68..100] != crate::hash::sha256(&[MANIFEST_APP.application_id])
        || MANIFEST_APP
            .resolve_optimistic_replay(
                kernel.id,
                kernel.semantic_version,
                kernel.abi_version,
                kernel.mode,
            )
            .is_none()
    {
        return Err(refusal());
    }
    raw[6] = 2;
    Ok(())
}

fn init_document(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    exact_data(data, 2 + 8 + ENTRY_COUNT * ENTRY_BYTES)?;
    let [executor, template, document, bond, system] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !executor.is_signer || !executor.is_writable {
        return Err(refusal());
    }
    let case_id = data[1];
    let kernel = checked_template(program, template, executor.key, case_id, true)?;
    if kernel.mode != MODE_OPTIMISTIC_V1 {
        return Err(refusal());
    }
    let template_key = template.key.to_bytes();
    let case_seed = [case_id];
    let doc_bump = CanonicalBump::find(&[b"dcg-test-document", &template_key, &case_seed], program);
    let bond_bump = CanonicalBump::find(
        &[b"dcg-test-bond", document.key.as_ref(), &case_seed],
        program,
    );
    if document.key != doc_bump.address() || bond.key != bond_bump.address() {
        return Err(refusal());
    }
    for i in 0..ENTRY_COUNT {
        let at = 10 + i * ENTRY_BYTES;
        if data[at] > 8
            || data[at + 1 + data[at] as usize..at + 9]
                .iter()
                .any(|b| *b != 0)
        {
            return Err(ProgramError::InvalidInstructionData);
        }
    }
    let document_rent = Rent::get()?.minimum_balance(DOCUMENT_BYTES);
    let bond_rent = Rent::get()?.minimum_balance(BOND_BYTES);
    let stake = u64::from_le_bytes(data[2..10].try_into().unwrap());
    let bond_balance = bond_rent.checked_add(stake).ok_or(refusal())?;
    create_pda(
        program,
        executor,
        document,
        system,
        &[b"dcg-test-document", &template_key, &case_seed],
        doc_bump,
        DOCUMENT_BYTES,
        document_rent,
    )?;
    create_pda(
        program,
        executor,
        bond,
        system,
        &[b"dcg-test-bond", document.key.as_ref(), &case_seed],
        bond_bump,
        BOND_BYTES,
        bond_balance,
    )?;
    {
        let mut raw = document.try_borrow_mut_data()?;
        raw[..4].copy_from_slice(b"DDOC");
        raw[4..6].copy_from_slice(&1u16.to_le_bytes());
        raw[6] = 1;
        raw[7] = case_id;
        raw[8..40].copy_from_slice(template.key.as_ref());
        raw[40..72].copy_from_slice(executor.key.as_ref());
        raw[72..104].copy_from_slice(executor.key.as_ref());
        raw[235] = ENTRY_COUNT as u8;
        raw[236..244].copy_from_slice(&data[2..10]);
        raw[ENTRY_AT..ENTRY_AT + ENTRY_COUNT * ENTRY_BYTES]
            .copy_from_slice(&data[10..10 + ENTRY_COUNT * ENTRY_BYTES]);
    }
    {
        let mut raw = bond.try_borrow_mut_data()?;
        raw[..4].copy_from_slice(b"DBND");
        raw[4..6].copy_from_slice(&1u16.to_le_bytes());
        raw[7] = case_id;
        raw[8..16].copy_from_slice(&data[2..10]);
    }
    Ok(())
}

fn land_roots(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    exact_data(data, 2)?;
    let [executor, template, document] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !executor.is_signer {
        return Err(refusal());
    }
    checked_document(program, template, document, executor.key, data[1], true)?;
    let mut raw = document.try_borrow_mut_data()?;
    if raw[6] != 1 {
        return Err(refusal());
    }
    let root = claimed_root(&raw)?;
    raw[104..136].copy_from_slice(&root);
    raw[6] = 2;
    Ok(())
}

fn finalize(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    exact_data(data, 2)?;
    let [executor, template, document] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !executor.is_signer {
        return Err(refusal());
    }
    checked_document(program, template, document, executor.key, data[1], true)?;
    let mut raw = document.try_borrow_mut_data()?;
    if raw[6] != 2 || raw[104..136] == [0; 32] {
        return Err(refusal());
    }
    raw[6] = 3;
    Ok(())
}

fn resolve(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    exact_data(data, 2)?;
    let [executor, template, document] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !executor.is_signer {
        return Err(refusal());
    }
    let kernel = checked_document(program, template, document, executor.key, data[1], true)?;
    let raw = document.try_borrow_data()?;
    if raw[6] != 3 {
        return Err(refusal());
    }
    let mut output = [0u8; 8];
    for i in 0..ENTRY_COUNT {
        let (input, claim) = entry(&raw, i)?;
        let written = MANIFEST_APP
            .execute(
                kernel.id,
                kernel.semantic_version,
                kernel.abi_version,
                kernel.mode,
                input,
                &mut output,
            )
            .map_err(|_| refusal())?;
        if written != 8 || output.as_slice() != claim {
            return Err(refusal());
        }
    }
    drop(raw);
    document.try_borrow_mut_data()?[6] = 4;
    Ok(())
}

fn challenge(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    exact_data(data, 34)?;
    let [challenger, template, document] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !challenger.is_signer || !challenger.is_writable {
        return Err(refusal());
    }
    let executor = {
        let raw = document.try_borrow_data()?;
        Pubkey::new_from_array(raw[72..104].try_into().map_err(|_| refusal())?)
    };
    checked_document(program, template, document, &executor, data[1], true)?;
    let mut raw = document.try_borrow_mut_data()?;
    if raw[6] != 3 || data[2..34] == [0; 32] || data[2..34] == raw[104..136] {
        return Err(refusal());
    }
    raw[6] = 5;
    raw[136..168].copy_from_slice(&data[2..34]);
    let claim_root: [u8; 32] = raw[104..136].try_into().map_err(|_| refusal())?;
    raw[168..200].copy_from_slice(&claim_root);
    raw[200..232].copy_from_slice(&data[2..34]);
    raw[232] = 0;
    raw[233] = 2;
    raw[244..276].copy_from_slice(challenger.key.as_ref());
    Ok(())
}

fn bisect(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    exact_data(data, 130)?;
    let [challenger, document] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !challenger.is_signer {
        return Err(refusal());
    }
    let (template_key, case_id) = {
        let raw = document.try_borrow_data()?;
        if raw.len() != DOCUMENT_BYTES || raw[..4] != *b"DDOC" {
            return Err(refusal());
        }
        (
            <[u8; 32]>::try_from(&raw[8..40]).map_err(|_| refusal())?,
            raw[7],
        )
    };
    let case_seed = [case_id];
    check_pda(
        program,
        document,
        &[b"dcg-test-document", &template_key, &case_seed],
        true,
    )?;
    let mut raw = document.try_borrow_mut_data()?;
    if raw.len() != DOCUMENT_BYTES
        || raw[..4] != *b"DDOC"
        || raw[6] != 5
        || raw[244..276] != challenger.key.to_bytes()
        || raw[233] == 0
    {
        return Err(refusal());
    }
    let case_id = raw[7];
    let level = raw[233];
    let start = raw[232];
    let left_claim: [u8; 32] = data[2..34].try_into().unwrap();
    let right_claim: [u8; 32] = data[34..66].try_into().unwrap();
    let left_challenger: [u8; 32] = data[66..98].try_into().unwrap();
    let right_challenger: [u8; 32] = data[98..130].try_into().unwrap();
    let current_claim: [u8; 32] = raw[168..200].try_into().unwrap();
    let current_challenger: [u8; 32] = raw[200..232].try_into().unwrap();
    if node(case_id, level, start, &left_claim, &right_claim) != current_claim
        || node(case_id, level, start, &left_challenger, &right_challenger) != current_challenger
    {
        return Err(refusal());
    }
    let next_level = level - 1;
    let choose_left = left_claim != left_challenger;
    let (claim, challenger_root) = if choose_left {
        (left_claim, left_challenger)
    } else if right_claim != right_challenger {
        let next_start = start + (1u8 << next_level);
        raw[232] = next_start;
        (right_claim, right_challenger)
    } else {
        return Err(refusal());
    };
    raw[168..200].copy_from_slice(&claim);
    raw[200..232].copy_from_slice(&challenger_root);
    raw[233] = next_level;
    Ok(())
}

fn replay(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    exact_data(data, 2)?;
    let [challenger, template, document] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    let executor = {
        let raw = document.try_borrow_data()?;
        Pubkey::new_from_array(raw[72..104].try_into().map_err(|_| refusal())?)
    };
    let kernel = checked_document(program, template, document, &executor, data[1], true)?;
    let mut raw = document.try_borrow_mut_data()?;
    if !challenger.is_signer
        || raw[6] != 5
        || raw[233] != 0
        || raw[244..276] != challenger.key.to_bytes()
        || raw[168..200] == raw[200..232]
    {
        return Err(refusal());
    }
    let index = raw[232] as usize;
    let (input, claimed) = entry(&raw, index)?;
    let mut output = [0u8; 8];
    let written = MANIFEST_APP
        .execute(
            kernel.id,
            kernel.semantic_version,
            kernel.abi_version,
            kernel.mode,
            input,
            &mut output,
        )
        .map_err(|_| refusal())?;
    if written != output.len() {
        return Err(refusal());
    }
    let replay = MANIFEST_APP
        .resolve_optimistic_replay(
            kernel.id,
            kernel.semantic_version,
            kernel.abi_version,
            kernel.mode,
        )
        .ok_or_else(refusal)?;
    let claim_matches = replay
        .replay
        .replay(input, &[], claimed, &[])
        .map_err(|_| refusal())?;
    if claim_matches != (output.as_slice() == claimed) {
        return Err(refusal());
    }
    let challenge_matches = leaf(data[1], index, input, &output) == raw[200..232];
    raw[234] = if !claim_matches && challenge_matches {
        CLAIM_CHEATER
    } else {
        CLAIM_HONEST
    };
    raw[6] = 6;
    Ok(())
}

fn settle(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    exact_data(data, 2)?;
    let [executor, challenger, document, bond] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    let case_id = data[1];
    let (template_key, case_seed) = {
        let raw = document.try_borrow_data()?;
        (
            <[u8; 32]>::try_from(&raw[8..40]).map_err(|_| refusal())?,
            [raw[7]],
        )
    };
    if case_seed[0] != case_id {
        return Err(refusal());
    }
    check_pda(
        program,
        document,
        &[b"dcg-test-document", &template_key, &case_seed],
        true,
    )?;
    check_pda(
        program,
        bond,
        &[b"dcg-test-bond", document.key.as_ref(), &case_seed],
        true,
    )?;
    let mut doc = document.try_borrow_mut_data()?;
    let mut escrow = bond.try_borrow_mut_data()?;
    if doc.len() != DOCUMENT_BYTES
        || doc[..4] != *b"DDOC"
        || doc[6] != 6
        || doc[7] != case_id
        || doc[72..104] != executor.key.to_bytes()
        || doc[244..276] != challenger.key.to_bytes()
        || escrow.len() != BOND_BYTES
        || escrow[..4] != *b"DBND"
        || escrow[7] != case_id
        || escrow[6] != 0
    {
        return Err(refusal());
    }
    let stake = u64::from_le_bytes(escrow[8..16].try_into().unwrap());
    if stake > bond.lamports() || !executor.is_writable || !challenger.is_writable {
        return Err(refusal());
    }
    let winner = if doc[234] == CLAIM_CHEATER {
        challenger
    } else if doc[234] == CLAIM_HONEST {
        executor
    } else {
        return Err(refusal());
    };
    let winner_balance = winner.lamports().checked_add(stake).ok_or(refusal())?;
    **bond.try_borrow_mut_lamports()? -= stake;
    **winner.try_borrow_mut_lamports()? = winner_balance;
    escrow[6] = 1;
    doc[6] = 7;
    Ok(())
}

fn close(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    exact_data(data, 2)?;
    let [authority, refund, template, document, bond] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !authority.is_signer || !authority.is_writable || !refund.is_writable {
        return Err(refusal());
    }
    let case_id = data[1];
    let kernel = checked_template(program, template, authority.key, case_id, true)?;
    let executor = {
        let raw = document.try_borrow_data()?;
        Pubkey::new_from_array(raw[72..104].try_into().map_err(|_| refusal())?)
    };
    checked_document(program, template, document, &executor, case_id, true)?;
    let case_seed = [case_id];
    check_pda(
        program,
        bond,
        &[b"dcg-test-bond", document.key.as_ref(), &case_seed],
        true,
    )?;
    let doc = document.try_borrow_data()?;
    let document_status = doc[6];
    if doc[40..72] != authority.key.to_bytes()
        || doc[72..104] != authority.key.to_bytes()
        || !matches!(document_status, 4 | 7)
        || kernel.mode != MODE_OPTIMISTIC_V1
    {
        return Err(refusal());
    }
    drop(doc);
    let template_balance = template.lamports();
    let document_balance = document.lamports();
    let bond_balance = bond.lamports();
    let refund_balance = refund
        .lamports()
        .checked_add(template_balance)
        .and_then(|sum| sum.checked_add(document_balance))
        .and_then(|sum| sum.checked_add(bond_balance))
        .ok_or(refusal())?;
    if refund.key == template.key || refund.key == document.key || refund.key == bond.key {
        return Err(refusal());
    }
    {
        let raw = bond.try_borrow_data()?;
        let closeable = (document_status == 4 && raw.get(6) == Some(&0))
            || (document_status == 7 && raw.get(6) == Some(&1));
        if raw.len() != BOND_BYTES || raw[..4] != *b"DBND" || raw[7] != case_id || !closeable {
            return Err(refusal());
        }
    }
    template.try_borrow_mut_data()?.fill(0);
    document.try_borrow_mut_data()?.fill(0);
    bond.try_borrow_mut_data()?.fill(0);
    **template.try_borrow_mut_lamports()? = 0;
    **document.try_borrow_mut_lamports()? = 0;
    **bond.try_borrow_mut_lamports()? = 0;
    **refund.try_borrow_mut_lamports()? = refund_balance;
    Ok(())
}

/// Bytes used by the SBF harness when it seals the alternate four-leaf trace.
pub fn leaf_for_test(case_id: u8, index: usize, input: &[u8], output: &[u8]) -> [u8; 32] {
    leaf(case_id, index, input, output)
}

/// Root of the four-entry trace used by the SBF harness.
pub fn root_for_test(leaves: &[[u8; 32]; ENTRY_COUNT], case_id: u8) -> [u8; 32] {
    let left = node(case_id, 1, 0, &leaves[0], &leaves[1]);
    let right = node(case_id, 1, 2, &leaves[2], &leaves[3]);
    node(case_id, 2, 0, &left, &right)
}

/// Authenticated child roots for the next bisection round in the fixed test
/// trace. This helper is used to construct the challenge transaction only.
pub fn children_for_test(
    case_id: u8,
    level: u8,
    start: u8,
    leaves: &[[u8; 32]; ENTRY_COUNT],
) -> ([u8; 32], [u8; 32]) {
    match level {
        2 => (
            node(case_id, 1, 0, &leaves[0], &leaves[1]),
            node(case_id, 1, 2, &leaves[2], &leaves[3]),
        ),
        1 if start == 0 => (leaves[0], leaves[1]),
        1 => (leaves[2], leaves[3]),
        _ => ([0; 32], [0; 32]),
    }
}
