//! The two trusted roles of the builder interface (spec revision 4, §16.1,
//! §16.2): DCF1 holds a rotatable admin, the registry-admission authority
//! (tags 156-158) and the template-seal authority (tag 176); DTA1 records
//! that authority's approval of one sealed PT2S at one exact content hash.
//!
//! DCF1 (PDA `"dcg-config"`, 128 bytes):
//! ```text
//!   0 "DCF1" | 4 version:u16 = 1 | 6 reserved:u16 | 8 admin[32]
//!  40 registry_authority[32] | 72 template_seal_authority[32]
//! 104 created_slot:u64 | 112 rotations:u32 | 116 reserved[12]
//! ```
//! DTA1 (PDA `"dcg-template-seal" | PT2S | PT2S_sha256`, 112 bytes):
//! ```text
//!   0 "DTA1" | 4 version:u16 = 1 | 6 state:u8 (1 approved, 2 revoked) | 7 zero
//!   8 PT2S[32] | 40 PT2S_sha256[32] | 72 sealer[32] | 104 slot:u64
//! ```
//! This module is the one place the authority checks live.

use super::{
    address, d32, no, registry, u16_at, u32_at, CL_AUTHORITY, CL_MALFORMED, CL_OVERFLOW,
    PLAN_BINDING, REGISTRY_ACCOUNT,
};
use crate::account_provenance::{expect_derived, expect_derived_with_bump, AccountKind, RoleFlags};
use crate::compatibility::{ApplicationHooks, REVISION8_COMPATIBILITY};
use crate::hash;
use crate::pt2p_onchain as S;
use solana_program::{
    account_info::AccountInfo, bpf_loader_upgradeable, clock::Clock, entrypoint::ProgramResult,
    program::invoke_signed, program_error::ProgramError, pubkey::Pubkey, system_instruction,
    system_program, sysvar::Sysvar,
};

pub const TAG_CONFIG_INIT: u8 = 174;
pub const TAG_CONFIG_SET: u8 = 175;
pub const TAG_TEMPLATE_SEAL: u8 = 176;
/// Close an abandoned, not-yet-published PT1X base (and its optional PT2S).
pub const TAG_CLOSE_UNPUBLISHED_TEMPLATE: u8 = 197;
pub const CONFIG_AUTHORITY: u32 = 792;
pub const TEMPLATE_SEAL: u32 = 793;
pub const CONFIG_BYTES: usize = 128;
pub const SEAL_BYTES: usize = 112;
pub const ROLE_ADMIN: u8 = 0;
pub const ROLE_REGISTRY: u8 = 1;
pub const ROLE_TEMPLATE_SEAL: u8 = 2;
pub const SEAL_APPROVED: u8 = 1;
pub const SEAL_REVOKED: u8 = 2;
/// **`retire`**, new in revision 8 (spec §1.7, §1.6's tag-176 row, and the
/// "Open for C4" gap it had no number for). The three actions are one trusted
/// role's three statements about one template, and the numbering is the obvious
/// one: **1 approve** (42 bytes, the only form that carries anything), **2
/// revoke** and **3 retire** (2 bytes each, and they carry nothing because
/// neither publishes a limit or a registry — they only write one state byte).
///
/// The 2-byte **approve** of revision 4-7 is **refused 793** on a revision-8
/// program: a DTU1 with no limits is not a template, DCG has no protocol-wide
/// windows to fall back on (the user, 2026-09-26), and admitting a v7-shaped
/// approval would create a template that no v8 document can ever be admitted
/// under. The reader split is the data length, exactly as for DCR2 v5/v6 and
/// DCRZ v1/v2, and no v7 *record* changes meaning: `approved` still reads a
/// DTA1 written by either form.
pub const SEAL_RETIRED: u8 = 3;
/// tag + `action:u8` + the five `u64` limits: 42 bytes for action 1.
pub const SEAL_DATA_APPROVE: usize = 42;
/// tag + `action:u8`: 2 bytes for actions 2 and 3.
pub const SEAL_DATA_ADMIN: usize = 2;

/// A DCF1 at its PDA; returns `(admin, registry_authority, template_seal_authority)`.
pub fn view(
    program: &Pubkey,
    account: &AccountInfo,
) -> Result<([u8; 32], [u8; 32], [u8; 32]), ProgramError> {
    let raw = account.try_borrow_data()?;
    if account.owner != program
        || *account.key != address::config(program).0
        || raw.len() != CONFIG_BYTES
        || raw[..4] != *b"DCF1"
        || u16_at(&raw, 4, CONFIG_AUTHORITY)? != 1
        || raw[6..8] != [0; 2]
        || raw[116..128] != [0; 12]
    {
        return Err(no(CONFIG_AUTHORITY));
    }
    let k = |at: usize| -> [u8; 32] { raw[at..at + 32].try_into().unwrap() };
    Ok((k(8), k(40), k(72)))
}

/// The signer holds the DCF1 role (a zero key disables the role): the one
/// registry-authority check of tags 156-158 (771, as ESL1).
pub fn registry_authority(
    program: &Pubkey,
    signer: &AccountInfo,
    config: &AccountInfo,
) -> ProgramResult {
    let (_, key, _) = view(program, config).map_err(|_| no(super::REGISTRY_AUTHORITY))?;
    if !signer.is_signer || key == [0; 32] || signer.key.to_bytes() != key {
        return Err(no(super::REGISTRY_AUTHORITY));
    }
    Ok(())
}

/// The upgrade authority of an upgradeable-loader ProgramData account:
/// bincode `u32 3 | slot:u64 | Option<Pubkey>` (tag byte 12, key 13..45).
pub fn programdata_upgrade_authority(raw: &[u8]) -> Result<Option<[u8; 32]>, u32> {
    if raw.len() < 45 || raw[..4] != 3u32.to_le_bytes() || raw[12] > 1 {
        return Err(CONFIG_AUTHORITY);
    }
    Ok(if raw[12] == 1 {
        Some(raw[13..45].try_into().unwrap())
    } else {
        None
    })
}

/// tag 174 ConfigInit: `admin[32] | registry_authority[32] |
/// template_seal_authority[32]`. Accounts: upgrade authority (s, w; pays),
/// DCF1 (w), this program's account, its ProgramData, system.
pub fn init(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let [authority, config, program_account, programdata, system] = accounts else {
        return Err(no(CONFIG_AUTHORITY));
    };
    if data.len() != 97 || data[1..33] == [0; 32] {
        return Err(no(CONFIG_AUTHORITY));
    }
    let (key, bump) = address::config(program);
    if *config.key != key
        || *program_account.key != *program
        || *program_account.owner != bpf_loader_upgradeable::id()
        || *programdata.owner != bpf_loader_upgradeable::id()
        || *programdata.key
            != Pubkey::find_program_address(&[program.as_ref()], &bpf_loader_upgradeable::id()).0
    {
        return Err(no(CONFIG_AUTHORITY));
    }
    {
        // UpgradeableLoaderState::Program { programdata_address }: u32 2 | key.
        let raw = program_account.try_borrow_data()?;
        if raw.len() < 36
            || raw[..4] != 2u32.to_le_bytes()
            || raw[4..36] != programdata.key.to_bytes()
        {
            return Err(no(CONFIG_AUTHORITY));
        }
        let upgrade = programdata_upgrade_authority(&programdata.try_borrow_data()?).map_err(no)?;
        if !authority.is_signer || upgrade != Some(authority.key.to_bytes()) {
            return Err(no(CONFIG_AUTHORITY));
        }
    }
    registry::create_pda(
        program,
        authority,
        config,
        system,
        &[address::CONFIG_SEED, &[bump]],
        CONFIG_BYTES,
        CONFIG_BYTES,
        CONFIG_AUTHORITY,
        CONFIG_AUTHORITY,
    )?;
    let mut raw = config.try_borrow_mut_data()?;
    raw[..4].copy_from_slice(b"DCF1");
    raw[4..6].copy_from_slice(&1u16.to_le_bytes());
    raw[8..104].copy_from_slice(&data[1..97]);
    raw[104..112].copy_from_slice(&Clock::get()?.slot.to_le_bytes());
    Ok(())
}

/// tag 175 ConfigSetAuthority: `role:u8 | key[32]`. Accounts: admin (s),
/// DCF1 (w), and for a nonzero new admin that admin (s).
pub fn set_authority(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if data.len() != 34 || data[1] > ROLE_TEMPLATE_SEAL || !matches!(accounts.len(), 2 | 3) {
        return Err(no(CONFIG_AUTHORITY));
    }
    let (admin, config) = (&accounts[0], &accounts[1]);
    let (current, _, _) = view(program, config)?;
    let (role, key) = (data[1], &data[2..34]);
    if current == [0; 32]
        || !admin.is_signer
        || admin.key.to_bytes() != current
        || !config.is_writable
    {
        return Err(no(CONFIG_AUTHORITY));
    }
    if role == ROLE_ADMIN && key != [0; 32] {
        let cosigned = accounts
            .get(2)
            .is_some_and(|a| a.is_signer && a.key.as_ref() == key);
        if !cosigned {
            return Err(no(CONFIG_AUTHORITY));
        }
    } else if accounts.len() != 2 {
        return Err(no(CONFIG_AUTHORITY));
    }
    let mut raw = config.try_borrow_mut_data()?;
    let at = 8 + 32 * role as usize;
    raw[at..at + 32].copy_from_slice(key);
    let rotations = u32::from_le_bytes(raw[112..116].try_into().unwrap())
        .checked_add(1)
        .ok_or(no(CONFIG_AUTHORITY))?;
    raw[112..116].copy_from_slice(&rotations.to_le_bytes());
    Ok(())
}

/// Revision-8 tag 176 publishes one single-base PT1X/PT2S template. Its DTA1
/// approval and DTU1 use record are the only records created here; resource
/// sharing and refcount records are not part of this revision.

#[cfg(feature = "revision-7")]
pub fn template_seal(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    template_seal_with_hooks(
        program,
        accounts,
        data,
        &crate::compatibility::REVISION8_COMPATIBILITY,
    )
}

#[cfg(feature = "revision-8")]
pub fn template_seal(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    template_seal_with_hooks(
        program,
        accounts,
        data,
        &crate::compatibility::REVISION8_COMPATIBILITY,
    )
}

pub fn template_seal_with_hooks(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    hooks: &dyn crate::compatibility::ApplicationHooks,
) -> ProgramResult {
    #[cfg(feature = "revision-7")]
    {
        let _ = hooks;
        template_seal_v7(program, accounts, data)
    }
    #[cfg(feature = "revision-8")]
    {
        template_seal_v8_single(program, accounts, data, hooks)
    }
}

/// Revision-8 single-base TemplateSeal. One PT1X is bound to one PT2S at tag
/// 143; this seal publishes the pair without resource counters or geometry
/// sharing. Action 1 takes eleven accounts. The safety actions take only the
/// five records/accounts they update.
#[cfg(feature = "revision-8")]
fn template_seal_v8_single(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    hooks: &dyn crate::compatibility::ApplicationHooks,
) -> ProgramResult {
    let action = *data.get(1).ok_or(no(TEMPLATE_SEAL))?;
    match action {
        SEAL_APPROVED if data.len() == SEAL_DATA_APPROVE && accounts.len() == 11 => {}
        SEAL_REVOKED | SEAL_RETIRED if data.len() == SEAL_DATA_ADMIN && accounts.len() == 5 => {}
        _ => return Err(no(TEMPLATE_SEAL)),
    }
    let (sealer, config, record, pt2s, use_record) = (
        &accounts[0],
        &accounts[1],
        &accounts[2],
        &accounts[3],
        &accounts[4],
    );
    let (_, _, key) = view(program, config)?;
    if key == [0; 32] || !sealer.is_signer || !sealer.is_writable || sealer.key.to_bytes() != key {
        return Err(no(CONFIG_AUTHORITY));
    }
    let digest = {
        let s = pt2s.try_borrow_data()?;
        if pt2s.owner != program
            || s.len() < S::OFF_PWR1
            || s[..4] != *S::MAGIC
            || s[S::OFF_STATE] != S::STATE_SEALED
        {
            return Err(no(PLAN_BINDING));
        }
        let pwr1_len = u16_at(&s, S::OFF_PWR1_LEN, PLAN_BINDING)? as usize;
        if s.len() != S::OFF_PWR1 + pwr1_len {
            return Err(no(PLAN_BINDING));
        }
        let compiler =
            crate::pt2p::Program::decode(&s[S::OFF_PWR1..]).map_err(|_| no(PLAN_BINDING))?;
        if super::plan::compiler_version(&compiler) != Some(1) {
            return Err(no(PLAN_BINDING));
        }
        hash::sha256(&[&s])
    };
    let (seal_key, seal_bump) = address::template_seal(program, pt2s.key, &digest);
    let (use_key, use_bump) = address::template_use(program, pt2s.key, &digest);
    if *record.key != seal_key
        || !record.is_writable
        || *use_record.key != use_key
        || !use_record.is_writable
    {
        return Err(no(CL_MALFORMED));
    }
    let seal_state = if record.data_is_empty() {
        0
    } else {
        let raw = record.try_borrow_data()?;
        if record.owner != program
            || raw.len() != SEAL_BYTES
            || raw[..4] != *b"DTA1"
            || u16_at(&raw, 4, TEMPLATE_SEAL)? != 1
            || raw[7] != 0
            || raw[8..40] != pt2s.key.to_bytes()
            || raw[40..72] != digest
        {
            return Err(no(TEMPLATE_SEAL));
        }
        raw[6]
    };
    let stored = if use_record.data_is_empty() {
        None
    } else {
        Some(template_record(program, use_record, pt2s.key, &digest)?)
    };

    if action != SEAL_APPROVED {
        if !matches!(seal_state, SEAL_APPROVED | SEAL_REVOKED) {
            return Err(no(TEMPLATE_SEAL));
        }
        let Some(use_view) = stored else {
            return Err(no(TEMPLATE_SEAL));
        };
        match action {
            SEAL_REVOKED => {
                if !matches!(use_view.state, DTU1_STATE_LIVE | DTU1_STATE_REVOKED) {
                    return Err(no(TEMPLATE_SEAL));
                }
                use_record.try_borrow_mut_data()?[6] = DTU1_STATE_REVOKED;
            }
            SEAL_RETIRED => {
                if !matches!(use_view.state, DTU1_STATE_LIVE | DTU1_STATE_RETIRED) {
                    return Err(no(TEMPLATE_SEAL));
                }
                use_record.try_borrow_mut_data()?[6] = DTU1_STATE_RETIRED;
            }
            _ => unreachable!(),
        }
        let mut raw = record.try_borrow_mut_data()?;
        raw[6] = if action == SEAL_RETIRED {
            SEAL_APPROVED
        } else {
            SEAL_REVOKED
        };
        raw[72..104].copy_from_slice(sealer.key.as_ref());
        raw[104..112].copy_from_slice(&Clock::get()?.slot.to_le_bytes());
        return Ok(());
    }

    let [_, _, _, _, _, pt1x, geometry, routes, payloads, system, registry_account] = accounts
    else {
        return Err(no(TEMPLATE_SEAL));
    };
    let limits = TemplateLimits::from_seal(data).map_err(|_| no(TEMPLATE_SEAL))?;
    let (
        pt1x_key,
        route_key,
        geometry_key,
        payload_key,
        pt2s_authority,
        pt1x_authority,
        lengths,
        positions,
        width,
    ) = {
        let s = pt2s.try_borrow_data()?;
        let (positions, _, _) = crate::pt2p::decode_clause12_v4(
            s.get(S::OFF_CLAUSE12..S::OFF_CLAUSE12 + crate::pt2p::CLAUSE12_V4_BYTES)
                .ok_or(no(PLAN_BINDING))?,
            None,
        )
        .map_err(no)?;
        let p1 = pt1x.try_borrow_data()?;
        (
            d32(&s, S::OFF_PT1S, PLAN_BINDING)?,
            d32(&s, S::OFF_KEYS, PLAN_BINDING)?,
            d32(&s, S::OFF_KEYS + 32, PLAN_BINDING)?,
            d32(&s, S::OFF_KEYS + 64, PLAN_BINDING)?,
            d32(&s, S::OFF_AUTHORITY, PLAN_BINDING)?,
            d32(&p1, 5, CL_MALFORMED)?,
            s.get(S::OFF_LENGTHS..S::OFF_LENGTHS + 12)
                .ok_or(no(PLAN_BINDING))?
                .to_vec(),
            positions,
            s.get(S::OFF_LOCATOR + 5).copied().ok_or(no(PLAN_BINDING))?,
        )
    };
    if pt1x.owner != program
        || geometry.owner != program
        || routes.owner != program
        || payloads.owner != program
        || pt1x.key.to_bytes() != pt1x_key
        || routes.key.to_bytes() != route_key
        || geometry.key.to_bytes() != geometry_key
        || payloads.key.to_bytes() != payload_key
        || pt1x.data_len() < crate::pt1_onchain::OFF_PAYLOAD_INDEX + 4
        || geometry.data_len() != u32::from_le_bytes(lengths[4..8].try_into().unwrap()) as usize
        || routes.data_len() != u32::from_le_bytes(lengths[0..4].try_into().unwrap()) as usize
        || payloads.data_len() != u32::from_le_bytes(lengths[8..12].try_into().unwrap()) as usize
        || *system.key != system_program::id()
    {
        return Err(no(CL_MALFORMED));
    }
    {
        let p = pt1x.try_borrow_data()?;
        if !crate::pt1_onchain::is_pt1x(&p)
            || !crate::pt1_onchain::is_sealed_template(&p)
            || p[4] != 6
            || &p[5..37] != pt2s_authority.as_slice()
            || p[crate::pt1_onchain::PT1X_BOUND_PT2S_AT
                ..crate::pt1_onchain::PT1X_BOUND_PT2S_AT + 32]
                != pt2s.key.to_bytes()
            || p[37..69] != route_key
            || p[69..101] != geometry_key
            || p[101..133] != payload_key
            || p[133..145] != lengths
        {
            return Err(no(CL_MALFORMED));
        }
    }
    if reject_self_payer_alias(pt2s.key, &pt2s_authority)
        || [pt1x, routes, geometry, payloads]
            .iter()
            .any(|a| reject_self_payer_alias(a.key, &pt1x_authority))
        || [pt2s, pt1x, routes, geometry, payloads]
            .iter()
            .any(|a| a.key == sealer.key)
    {
        return Err(no(TEMPLATE_SEAL));
    }
    super::result::close_capacity_bound(positions, width)?;
    registry::view(program, registry_account).map_err(|_| no(REGISTRY_ACCOUNT))?;
    let (_, admission_bump) =
        address::admission(program, registry_account.key, pt2s.key, positions);
    let stored_use = stored.as_ref();
    if (seal_state == 0) != stored_use.is_none() {
        return Err(no(TEMPLATE_SEAL));
    }
    let new_template = seal_state == 0;
    match seal_state {
        0 | SEAL_REVOKED => {}
        _ => return Err(no(TEMPLATE_SEAL)),
    }
    if let Some(use_view) = stored_use {
        if use_view.limits != limits || use_view.registry != registry_account.key.to_bytes() {
            return Err(no(TEMPLATE_SEAL));
        }
    }
    let now = Clock::get()?.slot;
    limits.check_with(now, hooks).map_err(no)?;
    if new_template {
        registry::create_pda(
            program,
            sealer,
            record,
            system,
            &[
                address::TEMPLATE_SEAL_SEED,
                pt2s.key.as_ref(),
                &digest,
                &[seal_bump],
            ],
            SEAL_BYTES,
            SEAL_BYTES,
            TEMPLATE_SEAL,
            TEMPLATE_SEAL,
        )?;
        registry::create_pda(
            program,
            sealer,
            use_record,
            system,
            &[
                address::TEMPLATE_USE_SEED,
                pt2s.key.as_ref(),
                &digest,
                &[use_bump],
            ],
            DTU1_BYTES,
            DTU1_BYTES,
            TEMPLATE_SEAL,
            TEMPLATE_SEAL,
        )?;
        let mut raw = use_record.try_borrow_mut_data()?;
        raw[..4].copy_from_slice(b"DTU1");
        raw[4..6].copy_from_slice(&DTU1_VERSION.to_le_bytes());
        raw[6] = DTU1_STATE_LIVE;
        raw[7] = use_bump;
        raw[16..48].copy_from_slice(sealer.key.as_ref());
        raw[48..80].copy_from_slice(registry_account.key.as_ref());
        raw[80..88].copy_from_slice(&now.to_le_bytes());
        raw[DTU1_MAX_CHALLENGE_AT..128].copy_from_slice(&limits.encode());
        raw[DTU1_PAYER_AT..DTU1_PAYER_AT + 32].copy_from_slice(sealer.key.as_ref());
        raw[DTU1_SEAL_BUMP_AT] = seal_bump;
        raw[DTU1_ADMISSION_BUMP_AT] = admission_bump;
    } else {
        let mut raw = use_record.try_borrow_mut_data()?;
        raw[6] = DTU1_STATE_LIVE;
        raw[DTU1_AUTHORITY_AT..DTU1_AUTHORITY_AT + 32].copy_from_slice(sealer.key.as_ref());
    }
    let mut raw = record.try_borrow_mut_data()?;
    raw[..4].copy_from_slice(b"DTA1");
    raw[4..6].copy_from_slice(&1u16.to_le_bytes());
    raw[6] = SEAL_APPROVED;
    raw[8..40].copy_from_slice(pt2s.key.as_ref());
    raw[40..72].copy_from_slice(&digest);
    raw[72..104].copy_from_slice(sealer.key.as_ref());
    raw[104..112].copy_from_slice(&now.to_le_bytes());
    Ok(())
}

fn reject_self_payer_alias(account: &Pubkey, payer: &[u8; 32]) -> bool {
    account.as_ref() == payer
}

#[cfg(feature = "revision-7")]
pub fn template_seal_v7(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let [sealer, config, record, pt2s, system] = accounts else {
        return Err(no(TEMPLATE_SEAL));
    };
    if data.len() != 2 || !matches!(data[1], SEAL_APPROVED | SEAL_REVOKED) {
        return Err(no(TEMPLATE_SEAL));
    }
    let (_, _, key) = view(program, config)?;
    if key == [0; 32] || !sealer.is_signer || sealer.key.to_bytes() != key {
        return Err(no(CONFIG_AUTHORITY));
    }
    let digest = {
        let s = pt2s.try_borrow_data()?;
        if pt2s.owner != program
            || s.len() < S::OFF_PWR1
            || s[..4] != *S::MAGIC
            || s[S::OFF_STATE] != S::STATE_SEALED
        {
            return Err(no(PLAN_BINDING));
        }
        hash::sha256(&[&s])
    };
    let (want, bump) = address::template_seal(program, pt2s.key, &digest);
    if *record.key != want || !record.is_writable {
        return Err(no(CL_MALFORMED));
    }
    if !record.data_is_empty() {
        expect_derived_with_bump(
            record,
            program,
            &[address::TEMPLATE_SEAL_SEED, pt2s.key.as_ref(), &digest],
            bump,
            AccountKind::exact(b"DTA1", SEAL_BYTES).with_version(4, 1),
            RoleFlags {
                writable: true,
                signer: false,
            },
        )
        .map_err(|_| no(TEMPLATE_SEAL))?;
    }
    let state = if record.data_is_empty() {
        0
    } else {
        let raw = record.try_borrow_data()?;
        if record.owner != program || raw.len() != SEAL_BYTES || raw[..4] != *b"DTA1" {
            return Err(no(TEMPLATE_SEAL));
        }
        raw[6]
    };
    match (data[1], state) {
        (SEAL_APPROVED, 0) => registry::create_pda(
            program,
            sealer,
            record,
            system,
            &[
                address::TEMPLATE_SEAL_SEED,
                pt2s.key.as_ref(),
                &digest,
                &[bump],
            ],
            SEAL_BYTES,
            SEAL_BYTES,
            TEMPLATE_SEAL,
            TEMPLATE_SEAL,
        )?,
        (SEAL_APPROVED, SEAL_REVOKED) | (SEAL_REVOKED, SEAL_APPROVED) => {}
        _ => return Err(no(TEMPLATE_SEAL)),
    }
    let mut raw = record.try_borrow_mut_data()?;
    raw[..4].copy_from_slice(b"DTA1");
    raw[4..6].copy_from_slice(&1u16.to_le_bytes());
    raw[6] = data[1];
    raw[8..40].copy_from_slice(pt2s.key.as_ref());
    raw[40..72].copy_from_slice(&digest);
    raw[72..104].copy_from_slice(sealer.key.as_ref());
    raw[104..112].copy_from_slice(&Clock::get()?.slot.to_le_bytes());
    Ok(())
}

/// UnifiedInit step 2b: DTA1 is the PDA of `(PT2S, sha256)`, program-owned,
/// approved (793).
pub fn approved(
    program: &Pubkey,
    record: &AccountInfo,
    pt2s: &Pubkey,
    digest: &[u8; 32],
) -> ProgramResult {
    expect_derived(
        record,
        program,
        &[address::TEMPLATE_SEAL_SEED, pt2s.as_ref(), digest],
        AccountKind::exact(b"DTA1", SEAL_BYTES).with_version(4, 1),
        RoleFlags {
            writable: false,
            signer: false,
        },
    )
    .map_err(|_| no(TEMPLATE_SEAL))?;
    let raw = record.try_borrow_data()?;
    if record.owner != program
        || raw.len() != SEAL_BYTES
        || raw[..4] != *b"DTA1"
        || raw[6] != SEAL_APPROVED
        || raw[8..40] != pt2s.to_bytes()
        || raw[40..72] != *digest
    {
        return Err(no(TEMPLATE_SEAL));
    }
    Ok(())
}

// ------------------------------------------------------------------ DTU1 (rev 8)

/// **DTU1**, the per-template use counter (spec §1.7, revision 8). PDA
/// `"dcg-template-use" | PT2S | PT2S_sha256`, created at the template seal:
/// ```text
///   0 "DTU1" | 4 version:u16 = 2 | 6 state:u8 (0 live, 1 retired, 2 revoked,
///     3 closed) | 7 use_bump:u8 | 8 documents:u32 | 12 zero[4] | 16 authority[32]
///  48 registry[32] | 80 seal_slot:u64
///  88 max_challenge_window_slots:u64  96 max_response_window_slots:u64
/// 104 max_document_lifetime_slots:u64 112 max_abandon_after_slots:u64
/// 120 min_abandon_after_slots:u64 | 128 payer[32] | 160 five PDA bumps | 168 end
/// ```
/// `documents` is +1 at `UnifiedInit` and −1 at `CloseDocumentV5`, so it is
/// the on-chain record of which documents hold this template's rent. `state` is
/// written by the retire, revoke and close actions, which are stream C4's.
///
/// **The five limits at 88 are the template owner's own windows, written once at
/// the seal and never changed** (spec §1.1's `TEMPLATE_LIMITS`, §1.7). They are
/// *appended* after `seal_slot`, so every offset above 88 keeps the value the
/// C1 stream already reads. Version 2 also records the original payer and the
/// PDA bumps tag 186 checks. The reason the limits live here and not in the PT2S is
/// §1.7's argument: a rent-exposure policy is not a property of the sealed plan
/// preimage, and the PT2S's SHA-256 is what DTA1, DTU1, DEA2 and every
/// document's descriptor commit.
pub const DTU1_BYTES: usize = 168;
pub const DTU1_VERSION: u16 = 2;
pub const DTU1_PAYER_AT: usize = 128;
pub const DTU1_BUMPS_AT: usize = 160;
pub const DTU1_SEAL_BUMP_AT: usize = DTU1_BUMPS_AT;
pub const DTU1_ADMISSION_BUMP_AT: usize = DTU1_BUMPS_AT + 2;
pub const DTU1_STATE_LIVE: u8 = 0;
pub const DTU1_STATE_RETIRED: u8 = 1;
pub const DTU1_STATE_REVOKED: u8 = 2;
/// 812 `TEMPLATE_USED`: the template has live documents on it, or it is closed.
/// Revision 7's own code for "this template cannot take what you are asking"
/// (tag 161 already refuses 812 on a closed template), reused as §3 states.
pub const TEMPLATE_USED: u32 = 812;

/// The five `u64` limits DTU1 carries from 88, in the order §1.1's table names
/// them. **There is no protocol-wide value for any of them**: DCG keeps only
/// the structural bounds in `check` below, and every magnitude is the template
/// owner's, because it is the owner's rent a long-lived document holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TemplateLimits {
    pub max_challenge_window_slots: u64,
    pub max_response_window_slots: u64,
    pub max_document_lifetime_slots: u64,
    pub max_abandon_after_slots: u64,
    pub min_abandon_after_slots: u64,
}

impl TemplateLimits {
    /// The five fields as the 40 bytes the seal's action-1 data carries, in
    /// the same order as DTU1's 88..128. **Byte-identical to the record's own
    /// tail**, which is why `create` copies it and the re-approval equality can
    /// be one 40-byte compare against the stored record.
    pub fn encode(&self) -> [u8; 40] {
        let mut out = [0u8; 40];
        for (i, limit) in [
            self.max_challenge_window_slots,
            self.max_response_window_slots,
            self.max_document_lifetime_slots,
            self.max_abandon_after_slots,
            self.min_abandon_after_slots,
        ]
        .into_iter()
        .enumerate()
        {
            out[8 * i..8 * i + 8].copy_from_slice(&limit.to_le_bytes());
        }
        out
    }

    /// The five fields out of a 42-byte seal argument (tag, action, 40 bytes).
    pub fn from_seal(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() != SEAL_DATA_APPROVE {
            return Err(no(TEMPLATE_SEAL));
        }
        let at = |i: usize| u64::from_le_bytes(data[2 + 8 * i..10 + 8 * i].try_into().unwrap());
        Ok(Self {
            max_challenge_window_slots: at(0),
            max_response_window_slots: at(1),
            max_document_lifetime_slots: at(2),
            max_abandon_after_slots: at(3),
            min_abandon_after_slots: at(4),
        })
    }

    /// The five fields, decoded from a validated DTU1 at 88.
    pub fn from_dtu1(raw: &[u8]) -> Result<Self, u32> {
        let u64_at = |at: usize| u64::from_le_bytes(raw[at..at + 8].try_into().unwrap());
        Ok(Self {
            max_challenge_window_slots: u64_at(DTU1_MAX_CHALLENGE_AT),
            max_response_window_slots: u64_at(DTU1_MAX_RESPONSE_AT),
            max_document_lifetime_slots: u64_at(DTU1_MAX_LIFETIME_AT),
            max_abandon_after_slots: u64_at(DTU1_MAX_ABANDON_AT),
            min_abandon_after_slots: u64_at(DTU1_MIN_ABANDON_AT),
        })
    }

    /// **The seal's own bounds on the five limits, and nothing else** (spec
    /// §1.1, `TEMPLATE_LIMITS`). Four rules, none of them a duration:
    ///
    /// 1. **every limit is nonzero** -- a zero window is not a window, and a
    ///    zero lifetime would put the clamp's ceiling at the init slot;
    /// 2. `min_abandon_after_slots <= max_abandon_after_slots`, so the record
    ///    cannot describe an empty range;
    /// 3. `max_abandon_after_slots <= max_document_lifetime_slots`, because a
    ///    grace window longer than the whole budget is not a grace window, and
    ///    this is the invariant the finalize budget subtraction needs;
    /// 4. **overflow safety, the one bound DCG keeps by name**: `limit +
    ///    seal_slot` must be representable, so every later `slot + window` at
    ///    the deadline writers has a real `u64` to check. The slot is the
    ///    seal's, and `init_slot >= seal_slot` for every document under the
    ///    template, so this is the widest add the record can ever produce.
    ///
    /// The refusal is 793, the code this module already answers a structurally
    /// wrong template record with. **No magnitude is checked**, and that is the
    /// whole point of the user's decision: the four protocol-wide constants are
    /// withdrawn, so a template may hold its counters for five minutes or for
    /// five centuries, and both are DCG's business to allow.
    pub fn check(&self, seal_slot: u64) -> Result<(), u32> {
        self.check_with(seal_slot, &REVISION8_COMPATIBILITY)
    }

    pub fn check_with(&self, seal_slot: u64, hooks: &dyn ApplicationHooks) -> Result<(), u32> {
        hooks.check_template_limits(self, seal_slot)
    }

    /// **The worst-case rent hold for one document under this template**, in
    /// slots: the total lifetime, plus the window in which a challenge may still
    /// open after the finalize, plus the rounds of the last challenge measured
    /// in the per-round response window. It is a **function of the template's
    /// own limits** and there is no protocol-wide figure, which is exactly what
    /// the user decided: the exposure is the number the template owner
    /// published, checked by whoever admits a document under it.
    pub fn worst_case_hold_slots(&self) -> u64 {
        self.max_document_lifetime_slots
            + self.max_challenge_window_slots
            + super::terms::CHALLENGE_ROUNDS_MAX * self.max_response_window_slots
    }
}

pub const DTU1_MAX_CHALLENGE_AT: usize = 88;
pub const DTU1_MAX_RESPONSE_AT: usize = 96;
pub const DTU1_MAX_LIFETIME_AT: usize = 104;
pub const DTU1_MAX_ABANDON_AT: usize = 112;
pub const DTU1_MIN_ABANDON_AT: usize = 120;
pub const DTU1_AUTHORITY_AT: usize = 16;
pub const DTU1_REGISTRY_AT: usize = 48;
pub const DTU1_DOCUMENTS_AT: usize = 8;
pub const DTU1_SEAL_SLOT_AT: usize = 80;

/// One validated read of DTU1: the counter, the state, and the limits.
struct TemplateView {
    documents: u32,
    state: u8,
    limits: TemplateLimits,
    /// DTU1 16..48, the sealer of the last approve. It is the fallback rent
    /// recipient for frozen records without a payer field.
    authority: [u8; 32],
    /// DTU1 48..80, the registry. It is here for the reason §1.7 gives, and two
    /// instructions now need it: the seal checks the presented registry against
    /// it, and tag 186 derives the admission record's address from it.
    registry: [u8; 32],
    payer: [u8; 32],
    use_bump: u8,
    seal_bump: u8,
    admission_bump: u8,
}

/// Return the registry pinned by a structurally valid DTU1, after requiring
/// that it still admits documents. Tag 159 uses this before it creates DEA2
/// so an alternate registry cannot strand a second admission allocation.
pub(super) fn live_template_registry(
    program: &Pubkey,
    record: &AccountInfo,
    pt2s: &Pubkey,
    digest: &[u8; 32],
) -> Result<[u8; 32], ProgramError> {
    let view = template_record(program, record, pt2s, digest)?;
    if view.state != DTU1_STATE_LIVE {
        return Err(no(TEMPLATE_SEAL));
    }
    Ok(view.registry)
}

/// DTU1 at the PDA of `(PT2S, digest)`: ownership, length, magic, version and
/// the two reserved runs, or 793 -- the code this module's own DTA1 view uses
/// for the same class of failure. `state` is *not* interpreted here.
fn template_record(
    program: &Pubkey,
    record: &AccountInfo,
    pt2s: &Pubkey,
    digest: &[u8; 32],
) -> Result<TemplateView, ProgramError> {
    expect_derived(
        record,
        program,
        &[address::TEMPLATE_USE_SEED, pt2s.as_ref(), digest],
        AccountKind::exact(b"DTU1", DTU1_BYTES)
            .with_version(4, DTU1_VERSION)
            .with_bump(7),
        RoleFlags {
            writable: false,
            signer: false,
        },
    )
    .map_err(|_| no(TEMPLATE_SEAL))?;
    let raw = record.try_borrow_data()?;
    let use_bump = raw.get(7).copied().ok_or(no(TEMPLATE_SEAL))?;
    if record.owner != program
        || raw.len() != DTU1_BYTES
        || raw[..4] != *b"DTU1"
        || u16_at(&raw, 4, TEMPLATE_SEAL)? != DTU1_VERSION
        || raw[12..16] != [0; 4]
        || raw[161] != 0
        || raw[163..168] != [0; 5]
        || raw[6] > DTU1_STATE_REVOKED
    {
        return Err(no(TEMPLATE_SEAL));
    }
    Ok(TemplateView {
        documents: u32_at(&raw, 8, TEMPLATE_SEAL)?,
        state: raw[6],
        limits: TemplateLimits::from_dtu1(&raw).map_err(no)?,
        authority: d32(&raw, DTU1_AUTHORITY_AT, TEMPLATE_SEAL)?,
        registry: d32(&raw, DTU1_REGISTRY_AT, TEMPLATE_SEAL)?,
        payer: d32(&raw, DTU1_PAYER_AT, TEMPLATE_SEAL)?,
        use_bump,
        seal_bump: raw[DTU1_SEAL_BUMP_AT],
        admission_bump: raw[DTU1_ADMISSION_BUMP_AT],
    })
}

/// `UnifiedInit` step 2c: DTU1 is live, and its `documents` is the value init
/// increments. Retired or revoked admits no new document, 793 -- the code the
/// DTA1 view above already answers with for "this template is not available".
pub fn template_use(
    program: &Pubkey,
    record: &AccountInfo,
    pt2s: &Pubkey,
    digest: &[u8; 32],
) -> Result<(u32, TemplateLimits), ProgramError> {
    let view = template_record(program, record, pt2s, digest)?;
    match view.state {
        DTU1_STATE_LIVE => Ok((view.documents, view.limits)),
        DTU1_STATE_RETIRED | DTU1_STATE_REVOKED => Err(no(TEMPLATE_SEAL)),
        _ => Err(no(TEMPLATE_SEAL)),
    }
}

/// **The limits alone, for the two deadline writers** (tags 162 and 165), which
/// need the template's lifetime limit and nothing else.
///
/// **`state` is deliberately not read here**, and that is a rule rather than an
/// omission: retire and revoke are statements about *admission*, so a document
/// that exists under a retired template must still be able to land and finalize
/// -- refusing here would strand the very rent the retirement was meant to
/// protect, and would make `abandon_deadline` unreadable to the one instruction
/// that keeps it inside the template's budget. The record cannot be *absent*
/// while a document is live, because tag 186 drains DTU1 only at
/// `documents == 0`.
pub fn template_limits(
    program: &Pubkey,
    record: &AccountInfo,
    pt2s: &Pubkey,
    digest: &[u8; 32],
) -> Result<TemplateLimits, ProgramError> {
    Ok(template_record(program, record, pt2s, digest)?.limits)
}

/// **`CloseDocumentV5`'s refcount decrement** (spec §1.3's row effects,
/// §1.7's counter). The close holds no PT2S meta, so the record is validated
/// and rewritten **at the PDA derived from DCM2's own `PT2S` (200) and
/// `PT2S_sha256` (232)** — the same two fields init wrote from the template
/// that admitted the document, and the same derivation tags 162 and 165 use. A
/// substituted or malformed counter is 793, never a decrement of someone else's.
///
/// Returns the new count. **`state` is not read**, for the same reason the two
/// deadline writers do not read it: a document under a retired or revoked
/// template must still be closable, or the retirement would strand the rent it
/// was meant to protect. State 3 is unreachable here by construction — tag 186
/// refuses at `documents != 0` — and a counter that reads 0 for a live document
/// is refused **598** (a checked subtraction, the code every checked arithmetic
/// in this format uses) rather than wrapping to `u32::MAX`.
pub fn template_release(
    program: &Pubkey,
    record: &AccountInfo,
    pt2s: &Pubkey,
    digest: &[u8; 32],
) -> Result<u32, ProgramError> {
    let view = template_record(program, record, pt2s, digest)?;
    let documents = view.documents.checked_sub(1).ok_or(no(CL_OVERFLOW))?;
    if !record.is_writable {
        return Err(no(CL_MALFORMED));
    }
    record.try_borrow_mut_data()?[DTU1_DOCUMENTS_AT..DTU1_DOCUMENTS_AT + 4]
        .copy_from_slice(&documents.to_le_bytes());
    Ok(documents)
}

#[cfg(all(test, feature = "legacy-basanos-fixtures"))]
mod tests {
    use super::*;
    use crate::unified::classes::tests::{golden, unhex};

    #[test]
    fn config_and_seal_vectors_decode() {
        let g = golden();
        let account = unhex(g["config"]["account"].as_str().unwrap());
        assert_eq!(account.len(), CONFIG_BYTES);
        assert_eq!(&account[..4], b"DCF1");
        let init = unhex(g["config"]["init_data"].as_str().unwrap());
        assert_eq!((init[0], init.len()), (TAG_CONFIG_INIT, 97));
        assert_eq!(account[8..104], init[1..97]);
        let rotate = unhex(g["config"]["rotate_data"].as_str().unwrap());
        assert_eq!(
            (rotate[0], rotate[1], rotate.len()),
            (TAG_CONFIG_SET, ROLE_TEMPLATE_SEAL, 34)
        );
        let rotated = unhex(g["config"]["rotated"].as_str().unwrap());
        assert_eq!(rotated[72..104], rotate[2..34]);
        assert_eq!(u32::from_le_bytes(rotated[112..116].try_into().unwrap()), 1);
        let seal = unhex(g["template_seal"]["account"].as_str().unwrap());
        assert_eq!(
            (seal.len(), &seal[..4], seal[6]),
            (SEAL_BYTES, &b"DTA1"[..], SEAL_APPROVED)
        );
        assert_eq!(
            unhex(g["template_seal"]["approve_data"].as_str().unwrap()),
            vec![TAG_TEMPLATE_SEAL, 1]
        );
        let mut pd = vec![0u8; 45];
        pd[..4].copy_from_slice(&3u32.to_le_bytes());
        pd[12] = 1;
        pd[13..45].copy_from_slice(&[9; 32]);
        assert_eq!(programdata_upgrade_authority(&pd), Ok(Some([9; 32])));
        pd[12] = 0;
        assert_eq!(programdata_upgrade_authority(&pd), Ok(None));
        pd[0] = 2;
        assert_eq!(programdata_upgrade_authority(&pd), Err(CONFIG_AUTHORITY));
    }
}

/// **tag 186 `CloseTemplateV5`** drains one published PT1X/PT2S template and
/// its base in a single instruction. Only the DTU1 authority may invoke it,
/// while the PT1X owner, PT2S owner and seal payer receive their recorded rent.
#[cfg(feature = "revision-8")]
pub fn close_template(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    close_template_v8_single(program, accounts, data)
}

/// tag 197 closes resources from a failed or abandoned setup before tag 176
/// publishes them. Forms: a fresh, zero-data program account whose own key signs
/// and retains its balance `[account(s,w), account(w), refund(w)]`; an unbound PT1X and its byte accounts
/// `[authority(s,w), PT1X(w), routes(w), geometry(w), payloads(w)]`; or that
/// same base plus its bound PT2S, empty approval/use PDAs and system program
/// (nine accounts). Published DTA1/DTU1 accounts must use tag 186.
#[cfg(feature = "revision-8")]
pub fn close_unpublished_template(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if data.len() != 1 || data[0] != TAG_CLOSE_UNPUBLISHED_TEMPLATE {
        return Err(no(CL_MALFORMED));
    }
    match accounts.len() {
        3 => {
            let [key, account, refund] = accounts else {
                return Err(no(CL_MALFORMED));
            };
            // This form is only for an unbound zero-data allocation. PT1X tag
            // 140 creates byte accounts with nonzero lengths and binds their
            // keys before publishing them; a four-byte prefix is not a marker
            // because legitimate payloads can begin with zeroes.
            if !key.is_signer
                || !key.is_writable
                || !account.is_writable
                || !refund.is_writable
                || key.key != account.key
                || refund.key != key.key
                || account.owner != program
                || account.data_len() != 0
            {
                return Err(no(CL_AUTHORITY));
            }
            // The zero-data allocation's own key is the only provable payee.
            // Keep its lamports at that key and return ownership to System;
            // no caller-selected third account receives rent.
            account.assign(&system_program::ID);
            Ok(())
        }
        5 => close_unpublished_pt1x(program, accounts),
        9 => close_unpublished_pt1x_pt2s(program, accounts),
        _ => Err(no(CL_MALFORMED)),
    }
}

#[cfg(feature = "revision-8")]
fn close_unpublished_pt1x(program: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let [authority, pt1x, routes, geometry, payloads] = accounts else {
        return Err(no(CL_MALFORMED));
    };
    if !authority.is_signer || !authority.is_writable {
        return Err(no(CL_AUTHORITY));
    }
    let (keys, lengths) = {
        let p = pt1x.try_borrow_data()?;
        if pt1x.owner != program
            || !crate::pt1_onchain::is_pt1x(&p)
            || p.len() < crate::pt1_onchain::OFF_PAYLOAD_INDEX + 4
            || !(1..=5).contains(&p[4])
            || p[5..37] != authority.key.to_bytes()
            || p[crate::pt1_onchain::PT1X_BOUND_PT2S_AT
                ..crate::pt1_onchain::PT1X_BOUND_PT2S_AT + 32]
                != [0; 32]
        {
            return Err(no(CL_AUTHORITY));
        }
        (p[37..133].to_vec(), p[133..145].to_vec())
    };
    let bound = [routes, geometry, payloads];
    for i in 0..3 {
        if bound[i].owner != program
            || bound[i].key.as_ref() != &keys[i * 32..(i + 1) * 32]
            || bound[i].data_len()
                != u32::from_le_bytes(lengths[4 * i..4 * i + 4].try_into().unwrap()) as usize
            || !bound[i].is_writable
            || bound[i].key == authority.key
        {
            return Err(no(PLAN_BINDING));
        }
    }
    if !pt1x.is_writable || pt1x.key == authority.key {
        return Err(no(CL_MALFORMED));
    }
    for account in [pt1x, routes, geometry, payloads] {
        super::result::drain(account, authority)?;
    }
    Ok(())
}

#[cfg(feature = "revision-8")]
fn close_unpublished_pt1x_pt2s(program: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let [authority, pt1x, routes, geometry, payloads, pt2s, approval, use_record, system] =
        accounts
    else {
        return Err(no(CL_MALFORMED));
    };
    if !authority.is_signer || !authority.is_writable || *system.key != system_program::id() {
        return Err(no(CL_AUTHORITY));
    }
    let (keys, lengths) = {
        let p = pt1x.try_borrow_data()?;
        if pt1x.owner != program
            || !crate::pt1_onchain::is_pt1x(&p)
            || p.len() < crate::pt1_onchain::OFF_PAYLOAD_INDEX + 4
            || p[4] != 6
            || p[5..37] != authority.key.to_bytes()
            || p[37..69] != routes.key.to_bytes()
            || p[69..101] != geometry.key.to_bytes()
            || p[101..133] != payloads.key.to_bytes()
            || p[crate::pt1_onchain::PT1X_BOUND_PT2S_AT
                ..crate::pt1_onchain::PT1X_BOUND_PT2S_AT + 32]
                != pt2s.key.to_bytes()
        {
            return Err(no(CL_AUTHORITY));
        }
        (p[37..133].to_vec(), p[133..145].to_vec())
    };
    if !pt1x.is_writable || pt1x.key == authority.key {
        return Err(no(CL_MALFORMED));
    }
    let resources = [routes, geometry, payloads];
    for i in 0..3 {
        if resources[i].owner != program
            || !resources[i].is_writable
            || resources[i].key.as_ref() != &keys[i * 32..(i + 1) * 32]
            || resources[i].data_len()
                != u32::from_le_bytes(lengths[4 * i..4 * i + 4].try_into().unwrap()) as usize
            || resources[i].key == authority.key
        {
            return Err(no(PLAN_BINDING));
        }
    }
    let pt2s_digest = {
        let s = pt2s.try_borrow_data()?;
        if pt2s.owner != program
            || s.len() < S::OFF_PWR1
            || s[..4] != *S::MAGIC
            || !matches!(
                s[S::OFF_STATE],
                S::STATE_HASHING | S::STATE_SEALING_PXR | S::STATE_SEALED
            )
            || s[S::OFF_PT1S..S::OFF_PT1S + 32] != pt1x.key.to_bytes()
            || s[S::OFF_AUTHORITY..S::OFF_AUTHORITY + 32] != authority.key.to_bytes()
            || s[S::OFF_KEYS..S::OFF_KEYS + 96] != keys
            || s[S::OFF_LENGTHS..S::OFF_LENGTHS + 12] != lengths
        {
            return Err(no(PLAN_BINDING));
        }
        let pwr1_len = u16_at(&s, S::OFF_PWR1_LEN, PLAN_BINDING)? as usize;
        if s.len() != S::OFF_PWR1 + pwr1_len
            || crate::pt2p::Program::decode(&s[S::OFF_PWR1..]).is_err()
        {
            return Err(no(PLAN_BINDING));
        }
        hash::sha256(&[&s])
    };
    if !pt2s.is_writable || pt2s.key == authority.key {
        return Err(no(CL_MALFORMED));
    }
    let (seal_key, seal_bump) = address::template_seal(program, pt2s.key, &pt2s_digest);
    let (use_key, use_bump) = address::template_use(program, pt2s.key, &pt2s_digest);
    if *approval.key != seal_key
        || *use_record.key != use_key
        || !approval.is_writable
        || !use_record.is_writable
        || !approval.data_is_empty()
        || !use_record.data_is_empty()
        || approval.owner != &system_program::ID
        || use_record.owner != &system_program::ID
    {
        return Err(no(TEMPLATE_SEAL));
    }
    // An unpublished template has no registry recorded in DTU1. Tag 197
    // returns only the seal-created PDAs; the published close owns any DEA2.
    for (account, seed, bump) in [
        (approval, address::TEMPLATE_SEAL_SEED, seal_bump),
        (use_record, address::TEMPLATE_USE_SEED, use_bump),
    ] {
        if account.lamports() != 0 {
            invoke_signed(
                &system_instruction::transfer(account.key, authority.key, account.lamports()),
                &[account.clone(), authority.clone(), system.clone()],
                &[&[seed, pt2s.key.as_ref(), &pt2s_digest, &[bump]]],
            )?;
        }
    }
    for account in [pt2s, pt1x, routes, geometry, payloads] {
        super::result::drain(account, authority)?;
    }
    Ok(())
}

/// tag 186 closes one PT1X/PT2S template as one base. Accounts:
/// closer(s), DTU1, DTA1, PT2S, PT1X, routes, geometry, payloads,
/// PT1X-authority refund, PT2S-authority refund, template-sealer refund,
/// registry, DEA2, DEA2-payer refund, system program.
#[cfg(feature = "revision-8")]
fn close_template_v8_single(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if data.len() != 1 || accounts.len() != 15 {
        return Err(no(CL_MALFORMED));
    }
    let [closer, use_record, approval, pt2s, pt1x, routes, geometry, payloads, pt1x_payer, pt2s_payer, use_payer, registry_account, admission, admission_payer, system] =
        accounts
    else {
        return Err(no(CL_MALFORMED));
    };
    if !closer.is_signer || *system.key != system_program::id() {
        return Err(no(CL_MALFORMED));
    }
    let (
        digest,
        pt2s_authority,
        pt1x_key,
        route_key,
        geometry_key,
        payload_key,
        lengths,
        positions,
    ) = {
        let s = pt2s.try_borrow_data()?;
        if pt2s.owner != program
            || s.len() < S::OFF_PWR1
            || s[..4] != *S::MAGIC
            || s[S::OFF_STATE] != S::STATE_SEALED
        {
            return Err(no(PLAN_BINDING));
        }
        let pwr1_len = u16_at(&s, S::OFF_PWR1_LEN, PLAN_BINDING)? as usize;
        if s.len() != S::OFF_PWR1 + pwr1_len
            || crate::pt2p::Program::decode(&s[S::OFF_PWR1..]).is_err()
        {
            return Err(no(PLAN_BINDING));
        }
        let (positions, _, _) = crate::pt2p::decode_clause12_v4(
            s.get(S::OFF_CLAUSE12..S::OFF_CLAUSE12 + crate::pt2p::CLAUSE12_V4_BYTES)
                .ok_or(no(PLAN_BINDING))?,
            None,
        )
        .map_err(no)?;
        (
            hash::sha256(&[&s]),
            d32(&s, S::OFF_AUTHORITY, PLAN_BINDING)?,
            d32(&s, S::OFF_PT1S, PLAN_BINDING)?,
            d32(&s, S::OFF_KEYS, PLAN_BINDING)?,
            d32(&s, S::OFF_KEYS + 32, PLAN_BINDING)?,
            d32(&s, S::OFF_KEYS + 64, PLAN_BINDING)?,
            s.get(S::OFF_LENGTHS..S::OFF_LENGTHS + 12)
                .ok_or(no(PLAN_BINDING))?
                .to_vec(),
            positions,
        )
    };
    let view = template_record(program, use_record, pt2s.key, &digest)?;
    if closer.key.to_bytes() != view.authority {
        return Err(no(CL_AUTHORITY));
    }
    if !matches!(
        view.state,
        DTU1_STATE_LIVE | DTU1_STATE_RETIRED | DTU1_STATE_REVOKED
    ) || view.documents != 0
    {
        return Err(no(TEMPLATE_USED));
    }
    if pt2s_payer.key.to_bytes() != pt2s_authority
        || pt1x.key.to_bytes() != pt1x_key
        || routes.key.to_bytes() != route_key
        || geometry.key.to_bytes() != geometry_key
        || payloads.key.to_bytes() != payload_key
        || registry_account.key.to_bytes() != view.registry
        || *approval.key
            != Pubkey::create_program_address(
                &[
                    address::TEMPLATE_SEAL_SEED,
                    pt2s.key.as_ref(),
                    &digest,
                    &[view.seal_bump],
                ],
                program,
            )
            .map_err(|_| no(TEMPLATE_SEAL))?
        || ![
            use_record,
            approval,
            pt2s,
            pt1x,
            routes,
            geometry,
            payloads,
            pt1x_payer,
            pt2s_payer,
            use_payer,
            admission,
            admission_payer,
        ]
        .iter()
        .all(|a| a.is_writable)
    {
        return Err(no(CL_MALFORMED));
    }
    if use_payer.key.to_bytes() != view.payer {
        return Err(no(CL_AUTHORITY));
    }
    for account in [pt1x, routes, geometry, payloads] {
        if account.owner != program {
            return Err(no(CL_MALFORMED));
        }
    }
    let pt1x_authority = {
        let p = pt1x.try_borrow_data()?;
        if !crate::pt1_onchain::is_pt1x(&p)
            || p[4] != 6
            || p[crate::pt1_onchain::PT1X_BOUND_PT2S_AT
                ..crate::pt1_onchain::PT1X_BOUND_PT2S_AT + 32]
                != pt2s.key.to_bytes()
            || p[37..69] != route_key
            || p[69..101] != geometry_key
            || p[101..133] != payload_key
            || p[133..145] != lengths
        {
            return Err(no(PLAN_BINDING));
        }
        d32(&p, 5, CL_MALFORMED)?
    };
    if pt1x_payer.key.to_bytes() != pt1x_authority || pt1x_authority != pt2s_authority {
        return Err(no(CL_AUTHORITY));
    }
    let resource_lens = [
        u32::from_le_bytes(lengths[0..4].try_into().unwrap()) as usize,
        u32::from_le_bytes(lengths[4..8].try_into().unwrap()) as usize,
        u32::from_le_bytes(lengths[8..12].try_into().unwrap()) as usize,
    ];
    if [routes, geometry, payloads]
        .iter()
        .zip(resource_lens)
        .any(|(a, n)| a.data_len() != n)
        || pt1x.owner != program
        || pt1x.data_len() < crate::pt1_onchain::OFF_PAYLOAD_INDEX + 4
    {
        return Err(no(PLAN_BINDING));
    }
    {
        let raw = approval.try_borrow_data()?;
        if approval.owner != program
            || raw.len() != SEAL_BYTES
            || raw[..4] != *b"DTA1"
            || u16_at(&raw, 4, TEMPLATE_SEAL)? != 1
            || !matches!(raw[6], SEAL_APPROVED | SEAL_REVOKED)
            || raw[7] != 0
            || raw[8..40] != pt2s.key.to_bytes()
            || raw[40..72] != digest
        {
            return Err(no(TEMPLATE_SEAL));
        }
    }
    let admission_key = Pubkey::create_program_address(
        &[
            address::ADMISSION_SEED,
            &view.registry,
            pt2s.key.as_ref(),
            &positions.to_le_bytes(),
            &[view.admission_bump],
        ],
        program,
    )
    .map_err(|_| no(TEMPLATE_SEAL))?;
    if *admission.key != admission_key {
        return Err(no(CL_MALFORMED));
    }
    let admission_exists = !admission.data_is_empty();
    if admission_exists {
        if admission.owner != program {
            return Err(no(PLAN_BINDING));
        }
        let admitted = super::admission::view(program, admission, false)?;
        if admitted.registry != view.registry
            || admitted.pt2s != pt2s.key.to_bytes()
            || admitted.pt2s_sha256 != digest
            || admitted.position_count != positions
            || admission_payer.key.to_bytes() != admitted.payer
        {
            return Err(no(PLAN_BINDING));
        }
    } else if admission.owner != &system_program::ID {
        return Err(no(PLAN_BINDING));
    }
    let sources = [
        use_record, approval, pt2s, pt1x, routes, geometry, payloads, admission,
    ];
    let destinations = [
        use_payer,
        use_payer,
        pt2s_payer,
        pt1x_payer,
        pt1x_payer,
        pt1x_payer,
        pt1x_payer,
        admission_payer,
    ];
    if sources
        .iter()
        .zip(destinations)
        .any(|(source, destination)| source.key == destination.key)
        || [use_payer, pt1x_payer, pt2s_payer, admission_payer]
            .iter()
            .any(|payer| sources.iter().any(|source| source.key == payer.key))
    {
        return Err(no(TEMPLATE_SEAL));
    }

    if admission_exists {
        drain_template_account(admission, admission_payer, true)?;
    } else if admission.lamports() != 0 {
        let capacity = positions.to_le_bytes();
        let bump = [view.admission_bump];
        invoke_signed(
            &system_instruction::transfer(admission.key, use_payer.key, admission.lamports()),
            &[admission.clone(), use_payer.clone(), system.clone()],
            &[&[
                address::ADMISSION_SEED,
                &view.registry,
                pt2s.key.as_ref(),
                &capacity,
                &bump,
            ]],
        )?;
    }
    drain_template_account(pt2s, pt2s_payer, true)?;
    for account in [pt1x, routes, geometry, payloads] {
        drain_template_account(account, pt1x_payer, true)?;
    }
    drain_template_account(approval, use_payer, true)?;
    drain_template_account(use_record, use_payer, true)?;
    Ok(())
}

fn drain_template_account<'a>(
    from: &AccountInfo<'a>,
    to: &AccountInfo<'a>,
    _reject_self_drain: bool,
) -> Result<u64, ProgramError> {
    super::result::drain(from, to)
}
