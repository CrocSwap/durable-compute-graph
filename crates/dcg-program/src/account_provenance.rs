// SPDX-License-Identifier: GPL-3.0-only

//! Shared validation for program-owned account addresses.
//!
//! Callers must construct `seeds` from a separately checked parent record,
//! the required signer, or fixed program constants. This module deliberately
//! does not read seed material from `account`; doing so would make the target
//! account its own authority.

use solana_program::{
    account_info::AccountInfo,
    entrypoint::ProgramResult,
    program::{invoke, invoke_signed},
    program_error::ProgramError,
    pubkey::Pubkey,
    rent::Rent,
    system_instruction, system_program,
    sysvar::Sysvar,
};

/// Runtime shape expected for a program-owned PDA.
#[derive(Clone, Copy, Debug)]
pub struct AccountKind {
    /// Required leading discriminator. Empty means the kind has no magic.
    pub magic: &'static [u8],
    /// Inclusive minimum account data length.
    pub min_len: usize,
    /// Inclusive maximum account data length.
    pub max_len: usize,
    /// Optional offset of a stored canonical bump byte.
    pub bump_offset: Option<usize>,
    /// Optional little-endian u16 version field `(offset, value)`.
    pub version: Option<(usize, u16)>,
}

impl AccountKind {
    pub const fn exact(magic: &'static [u8], len: usize) -> Self {
        Self {
            magic,
            min_len: len,
            max_len: len,
            bump_offset: None,
            version: None,
        }
    }

    pub const fn variable(magic: &'static [u8], min_len: usize, max_len: usize) -> Self {
        Self {
            magic,
            min_len,
            max_len,
            bump_offset: None,
            version: None,
        }
    }

    pub const fn with_bump(mut self, offset: usize) -> Self {
        self.bump_offset = Some(offset);
        self
    }

    pub const fn with_version(mut self, offset: usize, value: u16) -> Self {
        self.version = Some((offset, value));
        self
    }
}

/// Minimum privilege shape required for a role in one instruction.
///
/// A read-only operation may receive an account that is writable in the
/// frozen account list; it must not reject that honest input. Writers pass
/// `writable: true`, and signer-authorized roles pass `signer: true`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RoleFlags {
    pub writable: bool,
    pub signer: bool,
}

/// A bump paired with the PDA found by the canonical search (or with the
/// account address validated using a stored bump). Its fields are private so
/// creation callers cannot pass an instruction byte as a bump.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CanonicalBump {
    value: u8,
    address: Pubkey,
}

impl CanonicalBump {
    /// Run Solana's full canonical search once and retain both outputs for a
    /// later account check or signed creation.
    pub fn find(seeds: &[&[u8]], program: &Pubkey) -> Self {
        let (address, value) = Pubkey::find_program_address(seeds, program);
        Self { value, address }
    }

    /// The canonical bump byte, for storing in the created account.
    pub const fn value(self) -> u8 {
        self.value
    }

    /// The PDA returned by the full canonical search or validated read.
    pub const fn address(&self) -> &Pubkey {
        &self.address
    }
}

/// Validate a program-owned account whose identity is an exact independently
/// authenticated key (for example, a signer-created account recorded by its
/// parent). Use `expect_derived` when the role is a PDA.
pub fn expect_keyed(
    account: &AccountInfo,
    program: &Pubkey,
    expected: &Pubkey,
    kind: AccountKind,
    role: RoleFlags,
) -> ProgramResult {
    if account.key != expected
        || account.owner != program
        || account.executable
        || (role.writable && !account.is_writable)
        || (role.signer && !account.is_signer)
        || account.data_len() < kind.min_len
        || account.data_len() > kind.max_len
    {
        return Err(ProgramError::InvalidAccountData);
    }
    let data = account.try_borrow_data()?;
    if (!kind.magic.is_empty()
        && (data.len() < kind.magic.len() || &data[..kind.magic.len()] != kind.magic))
        || kind.version.is_some_and(|(offset, version)| {
            data.get(offset..offset.saturating_add(2)) != Some(version.to_le_bytes().as_slice())
        })
    {
        return Err(ProgramError::InvalidAccountData);
    }
    Ok(())
}

/// Check that `account` is the canonical PDA for independent `seeds` and has
/// the requested owner, data kind, size and runtime privileges. Program data
/// accounts must not be executable.
pub fn expect_derived(
    account: &AccountInfo,
    program: &Pubkey,
    seeds: &[&[u8]],
    kind: AccountKind,
    role: RoleFlags,
) -> Result<CanonicalBump, ProgramError> {
    let bump = CanonicalBump::find(seeds, program);
    expect_keyed(account, program, bump.address(), kind, role)?;
    if kind.bump_offset.is_some_and(|offset| {
        account
            .try_borrow_data()
            .ok()
            .and_then(|data| data.get(offset).copied())
            != Some(bump.value())
    }) {
        return Err(ProgramError::InvalidAccountData);
    }
    Ok(bump)
}

/// Check a PDA with a bump obtained from a trusted canonical derivation. This
/// performs one address derivation and deliberately does not search for the
/// canonical bump again. Use when the bump is stored by an existing creator or
/// was just obtained by the caller's canonical PDA validation, and the caller
/// has validated the independent seed source.
pub fn expect_derived_with_bump(
    account: &AccountInfo,
    program: &Pubkey,
    seeds: &[&[u8]],
    bump: u8,
    kind: AccountKind,
    role: RoleFlags,
) -> Result<CanonicalBump, ProgramError> {
    let bump_seed = [bump];
    let mut derived_seeds = seeds.to_vec();
    derived_seeds.push(&bump_seed);
    let expected = Pubkey::create_program_address(&derived_seeds, program)
        .map_err(|_| ProgramError::InvalidAccountData)?;
    expect_keyed(account, program, &expected, kind, role)?;
    if kind.bump_offset.is_some_and(|offset| {
        account
            .try_borrow_data()
            .ok()
            .and_then(|data| data.get(offset).copied())
            != Some(bump)
    }) {
        return Err(ProgramError::InvalidAccountData);
    }
    Ok(CanonicalBump {
        value: bump,
        address: expected,
    })
}

/// Check a fresh System-owned PDA before the program creates or assigns it.
/// Pre-funded empty PDAs are accepted when `allow_prefunded` is true.
pub fn expect_system_derived(
    account: &AccountInfo,
    program: &Pubkey,
    seeds: &[&[u8]],
    expected_bump: Option<u8>,
    role: RoleFlags,
    allow_prefunded: bool,
) -> Result<CanonicalBump, ProgramError> {
    let bump = CanonicalBump::find(seeds, program);
    if account.key != bump.address() || expected_bump.is_some_and(|given| given != bump.value()) {
        return Err(ProgramError::InvalidAccountData);
    }
    expect_system_account_shape(account, role, allow_prefunded)?;
    Ok(bump)
}

/// Validate a pre-funded System-owned PDA against a bump saved by a trusted
/// creator. This avoids repeating the canonical search in the later creation
/// instruction while still checking the exact derived key and empty shape.
pub fn expect_system_derived_with_bump(
    account: &AccountInfo,
    program: &Pubkey,
    seeds: &[&[u8]],
    bump: u8,
    role: RoleFlags,
    allow_prefunded: bool,
) -> Result<CanonicalBump, ProgramError> {
    let bump_seed = [bump];
    let mut derived_seeds = seeds.to_vec();
    derived_seeds.push(&bump_seed);
    let address = Pubkey::create_program_address(&derived_seeds, program)
        .map_err(|_| ProgramError::InvalidAccountData)?;
    if account.key != &address {
        return Err(ProgramError::InvalidAccountData);
    }
    expect_system_account_shape(account, role, allow_prefunded)?;
    Ok(CanonicalBump {
        value: bump,
        address,
    })
}

/// App-dispatch variant of `expect_system_derived`: it enforces minimum role
/// privileges, so an otherwise read-only role can accept a writable meta.
pub fn expect_system_derived_role(
    account: &AccountInfo,
    program: &Pubkey,
    seeds: &[&[u8]],
    role: RoleFlags,
    allow_prefunded: bool,
) -> Result<CanonicalBump, ProgramError> {
    let bump = CanonicalBump::find(seeds, program);
    if account.key != bump.address()
        || account.owner != &system_program::id()
        || account.executable
        || (role.writable && !account.is_writable)
        || (role.signer && !account.is_signer)
        || !account.data_is_empty()
        || (!allow_prefunded && account.lamports() != 0)
    {
        return Err(ProgramError::InvalidAccountData);
    }
    Ok(bump)
}

/// Validate a target's System-owned empty-account shape after the caller has
/// checked its exact expected PDA address.
pub fn expect_system_account_shape(
    account: &AccountInfo,
    role: RoleFlags,
    allow_prefunded: bool,
) -> ProgramResult {
    if account.owner != &system_program::id()
        || account.executable
        || account.is_writable != role.writable
        || account.is_signer != role.signer
        || !account.data_is_empty()
        || (!allow_prefunded && account.lamports() != 0)
    {
        return Err(ProgramError::InvalidAccountData);
    }
    Ok(())
}

fn validate_creation_target(
    target: &AccountInfo,
    bump: CanonicalBump,
    allow_prefunded: bool,
) -> ProgramResult {
    if target.key != bump.address()
        || !target.is_writable
        || target.is_signer
        || target.executable
        || target.owner != &system_program::id()
        || (!allow_prefunded && target.lamports() != 0)
        || !target.data_is_empty()
    {
        return Err(ProgramError::InvalidAccountData);
    }
    Ok(())
}

/// Create a fresh account at the canonical address for `seeds`.
///
/// The target must be a writable, empty System-owned account with zero
/// lamports. The payer must be a writable signer and the supplied System
/// Program account must be the executable canonical System Program.
pub fn create_derived_account<'a>(
    program: &Pubkey,
    payer: &AccountInfo<'a>,
    target: &AccountInfo<'a>,
    system: &AccountInfo<'a>,
    seeds: &[&[u8]],
    expected_bump: CanonicalBump,
    data_len: usize,
    rent_size: usize,
) -> ProgramResult {
    let bump_seed = [expected_bump.value()];
    validate_creation_target(target, expected_bump, false)?;
    if !payer.is_signer
        || !payer.is_writable
        || payer.executable
        || *system.key != system_program::id()
        || !system.executable
        || system.is_writable
        || system.is_signer
    {
        return Err(ProgramError::InvalidAccountData);
    }
    let lamports = Rent::get()?.minimum_balance(rent_size);
    let mut signer_seeds = seeds.to_vec();
    signer_seeds.push(&bump_seed);
    invoke_signed(
        &system_instruction::create_account(
            payer.key,
            target.key,
            lamports,
            data_len as u64,
            program,
        ),
        &[payer.clone(), target.clone(), system.clone()],
        &[&signer_seeds],
    )
}

/// Allocate and assign a derived account while preserving pre-funding support.
/// This is the creation path for formats that permit a System-owned empty PDA
/// to arrive with lamports already deposited.
pub fn allocate_derived_account<'a>(
    program: &Pubkey,
    payer: &AccountInfo<'a>,
    target: &AccountInfo<'a>,
    system: &AccountInfo<'a>,
    seeds: &[&[u8]],
    expected_bump: CanonicalBump,
    data_len: usize,
    rent_size: usize,
) -> ProgramResult {
    let bump_seed = [expected_bump.value()];
    validate_creation_target(target, expected_bump, true)?;
    if !payer.is_signer
        || !payer.is_writable
        || payer.executable
        || *system.key != system_program::id()
        || !system.executable
        || system.is_writable
        || system.is_signer
    {
        return Err(ProgramError::InvalidAccountData);
    }
    let need = Rent::get()?.minimum_balance(rent_size);
    if target.lamports() < need {
        invoke(
            &system_instruction::transfer(payer.key, target.key, need - target.lamports()),
            &[payer.clone(), target.clone(), system.clone()],
        )?;
    }
    let mut signer_seeds = seeds.to_vec();
    signer_seeds.push(&bump_seed);
    invoke_signed(
        &system_instruction::allocate(target.key, data_len as u64),
        &[target.clone(), system.clone()],
        &[&signer_seeds],
    )?;
    invoke_signed(
        &system_instruction::assign(target.key, program),
        &[target.clone(), system.clone()],
        &[&signer_seeds],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_program::clock::Epoch;

    fn account<'a>(
        key: &'a Pubkey,
        owner: &'a Pubkey,
        lamports: &'a mut u64,
        data: &'a mut [u8],
        writable: bool,
        signer: bool,
    ) -> AccountInfo<'a> {
        AccountInfo::new(
            key,
            signer,
            writable,
            lamports,
            data,
            owner,
            false,
            Epoch::default(),
        )
    }

    #[test]
    fn derived_gate_checks_address_kind_version_bump_and_privileges() {
        let program = Pubkey::new_unique();
        let parent = Pubkey::new_unique();
        let (key, bump) = Pubkey::find_program_address(&[b"child", parent.as_ref()], &program);
        let mut lamports = 1;
        let mut bytes = [0u8; 8];
        bytes[..4].copy_from_slice(b"TEST");
        bytes[4..6].copy_from_slice(&1u16.to_le_bytes());
        bytes[6] = bump;
        let info = account(&key, &program, &mut lamports, &mut bytes, true, false);
        let kind = AccountKind::exact(b"TEST", 8)
            .with_version(4, 1)
            .with_bump(6);
        assert_eq!(
            expect_derived(
                &info,
                &program,
                &[b"child", parent.as_ref()],
                kind,
                RoleFlags {
                    writable: true,
                    signer: false
                },
            )
            .map(CanonicalBump::value),
            Ok(bump)
        );
        assert!(expect_derived(
            &info,
            &program,
            &[b"child", Pubkey::new_unique().as_ref()],
            kind,
            RoleFlags {
                writable: true,
                signer: false
            },
        )
        .is_err());
        assert_eq!(
            expect_derived(
                &info,
                &program,
                &[b"child", parent.as_ref()],
                kind,
                RoleFlags {
                    writable: false,
                    signer: false
                },
            )
            .map(CanonicalBump::value),
            Ok(bump),
            "read roles accept writable metas from frozen account lists"
        );
        info.try_borrow_mut_data().unwrap()[..4].copy_from_slice(b"OTHR");
        assert!(expect_derived(
            &info,
            &program,
            &[b"child", parent.as_ref()],
            kind,
            RoleFlags {
                writable: true,
                signer: false
            },
        )
        .is_err());
        let mut readonly_lamports = 1;
        let mut readonly_bytes = [0u8; 8];
        readonly_bytes[..4].copy_from_slice(b"TEST");
        readonly_bytes[4..6].copy_from_slice(&1u16.to_le_bytes());
        readonly_bytes[6] = bump;
        let readonly_info = account(
            &key,
            &program,
            &mut readonly_lamports,
            &mut readonly_bytes,
            false,
            false,
        );
        assert!(expect_derived(
            &readonly_info,
            &program,
            &[b"child", parent.as_ref()],
            kind,
            RoleFlags {
                writable: true,
                signer: false
            },
        )
        .is_err());
        {
            let mut data = info.try_borrow_mut_data().unwrap();
            data[..4].copy_from_slice(b"TEST");
            data[4..6].copy_from_slice(&2u16.to_le_bytes());
        }
        assert!(expect_derived(
            &info,
            &program,
            &[b"child", parent.as_ref()],
            kind,
            RoleFlags {
                writable: true,
                signer: false
            },
        )
        .is_err());
        {
            let mut data = info.try_borrow_mut_data().unwrap();
            data[4..6].copy_from_slice(&1u16.to_le_bytes());
            data[6] ^= 1;
        }
        assert!(expect_derived(
            &info,
            &program,
            &[b"child", parent.as_ref()],
            kind,
            RoleFlags {
                writable: true,
                signer: false
            },
        )
        .is_err());
        info.try_borrow_mut_data().unwrap()[6] = bump;
        assert!(expect_derived(
            &info,
            &program,
            &[b"child", parent.as_ref()],
            kind,
            RoleFlags {
                writable: true,
                signer: true
            },
        )
        .is_err());
        let wrong_owner = Pubkey::new_unique();
        let mut wrong_owner_lamports = 1;
        let mut same_shape = info.try_borrow_data().unwrap().to_vec();
        let wrong_owner_info = account(
            &key,
            &wrong_owner,
            &mut wrong_owner_lamports,
            &mut same_shape,
            true,
            false,
        );
        assert!(expect_derived(
            &wrong_owner_info,
            &program,
            &[b"child", parent.as_ref()],
            kind,
            RoleFlags {
                writable: true,
                signer: false
            },
        )
        .is_err());
    }

    #[test]
    fn creation_rejects_an_account_at_a_noncanonical_bump_address() {
        let program = Pubkey::new_unique();
        let parent = Pubkey::new_unique();
        let seeds: &[&[u8]] = &[b"child", parent.as_ref()];
        let canonical = CanonicalBump::find(seeds, &program);
        let noncanonical = (0..canonical.value())
            .rev()
            .find_map(|value| {
                Pubkey::create_program_address(&[seeds[0], seeds[1], &[value]], &program).ok()
            })
            .expect("a second valid bump exists for this deterministic test seed");
        assert_ne!(&noncanonical, canonical.address());
        let system = system_program::id();
        let mut lamports = 0;
        let mut data = [];
        let target = account(
            &noncanonical,
            &system,
            &mut lamports,
            &mut data,
            true,
            false,
        );
        let payer_key = Pubkey::new_unique();
        let mut payer_lamports = 1;
        let mut payer_data = [];
        let payer = account(
            &payer_key,
            &system,
            &mut payer_lamports,
            &mut payer_data,
            true,
            true,
        );
        let mut system_lamports = 1;
        let mut system_data = [];
        let system_account = account(
            &system,
            &system,
            &mut system_lamports,
            &mut system_data,
            false,
            false,
        );
        assert_eq!(
            create_derived_account(
                &program,
                &payer,
                &target,
                &system_account,
                seeds,
                canonical,
                8,
                8,
            ),
            Err(ProgramError::InvalidAccountData),
            "creation requires the full-search address paired with its canonical bump"
        );
    }
}
