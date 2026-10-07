// SPDX-License-Identifier: GPL-3.0-only

//! SVM boundary for authenticated kernel account spans.
//!
//! The pure kernel contract sees only `AccountSpan` values. This adapter
//! verifies every key, owner, signer/writable role, and checked region bound
//! before borrowing account data. Aliasing policy is deliberately strict:
//! overlapping regions are refused, and any duplicate account key involving
//! a writable span is refused. Disjoint read-only regions of one account are
//! allowed.

use crate::kernel::{AccountSpan, AccountSpanBinding, SpanOwner};
use core::cell::Ref;
use solana_program::{account_info::AccountInfo, program_error::ProgramError, pubkey::Pubkey};

fn refusal(code: u32) -> ProgramError {
    ProgramError::Custom(code)
}

/// Borrow a statically described set of account regions for the duration of
/// `f`. All account identities, roles, bounds, and pairwise alias rules are
/// checked before the first data borrow is taken.
pub(crate) fn with_account_spans<R>(
    program: &Pubkey,
    accounts: &[AccountInfo<'_>],
    bindings: &[AccountSpanBinding],
    f: impl FnOnce(&[AccountSpan<'_>]) -> Result<R, ProgramError>,
) -> Result<R, ProgramError> {
    // DCR1 refusal codes, kept at their historical values.
    const DCR1_BAD: u32 = 730;
    const DCR1_AUTH: u32 = 731;

    if bindings.is_empty() || bindings.len() > 16 {
        return Err(refusal(DCR1_BAD));
    }

    let mut selected = Vec::with_capacity(bindings.len());
    let mut ranges = Vec::with_capacity(bindings.len());
    for binding in bindings {
        let account = accounts
            .get(binding.account_index as usize)
            .ok_or_else(|| refusal(DCR1_BAD))?;
        if binding
            .key
            .is_some_and(|expected| account.key.to_bytes() != expected)
        {
            return Err(refusal(DCR1_AUTH));
        }
        let owner_matches = match binding.owner {
            SpanOwner::Program => account.owner == program,
            SpanOwner::Exact(expected) => account.owner.to_bytes() == expected,
        };
        if !owner_matches
            || account.is_signer != binding.is_signer
            || account.is_writable != binding.is_writable
        {
            return Err(refusal(DCR1_AUTH));
        }
        let end = binding
            .offset
            .checked_add(binding.length)
            .ok_or_else(|| refusal(DCR1_BAD))?;
        if end as usize > account.data_len() {
            return Err(refusal(DCR1_BAD));
        }
        selected.push(account);
        ranges.push((binding.offset, end));
    }

    for left in 0..bindings.len() {
        for right in left + 1..bindings.len() {
            if selected[left].key != selected[right].key {
                continue;
            }
            let overlaps = ranges[left].0 < ranges[right].1 && ranges[right].0 < ranges[left].1;
            if overlaps || bindings[left].is_writable || bindings[right].is_writable {
                return Err(refusal(DCR1_BAD));
            }
        }
    }

    let mut guards: Vec<Ref<'_, [u8]>> = Vec::with_capacity(selected.len());
    for account in &selected {
        guards.push(Ref::map(account.try_borrow_data()?, |data| &data[..]));
    }
    let spans: Vec<AccountSpan<'_>> = bindings
        .iter()
        .zip(&selected)
        .zip(&ranges)
        .zip(&guards)
        .map(|(((binding, account), (start, end)), guard)| AccountSpan {
            key: account.key.to_bytes(),
            owner: account.owner.to_bytes(),
            is_signer: account.is_signer,
            is_writable: account.is_writable,
            schema: binding.schema,
            offset: *start,
            data: &guard[*start as usize..*end as usize],
        })
        .collect();
    f(&spans)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::VersionedId;
    use solana_program::account_info::AccountInfo;

    const PROGRAM: Pubkey = Pubkey::new_from_array([7; 32]);
    const KEY: Pubkey = Pubkey::new_from_array([8; 32]);
    const OTHER: Pubkey = Pubkey::new_from_array([9; 32]);

    fn account_info<'a>(
        key: &'a Pubkey,
        owner: &'a Pubkey,
        lamports: &'a mut u64,
        data: &'a mut [u8],
        signer: bool,
        writable: bool,
    ) -> AccountInfo<'a> {
        AccountInfo::new(key, signer, writable, lamports, data, owner, false, 0)
    }

    fn binding(offset: u32, length: u32) -> AccountSpanBinding {
        AccountSpanBinding {
            account_index: 0,
            key: Some(KEY.to_bytes()),
            owner: SpanOwner::Program,
            is_signer: false,
            is_writable: false,
            schema: VersionedId { id: 1, version: 1 },
            offset,
            length,
        }
    }

    #[test]
    fn forms_bounded_read_only_regions_after_identity_and_role_checks() {
        let mut lamports = 1;
        let mut data = [1, 2, 3, 4, 5, 6];
        let info = account_info(&KEY, &PROGRAM, &mut lamports, &mut data, false, false);
        with_account_spans(&PROGRAM, &[info], &[binding(1, 3)], |spans| {
            assert_eq!(spans.len(), 1);
            assert_eq!(spans[0].key, KEY.to_bytes());
            assert_eq!(spans[0].owner, PROGRAM.to_bytes());
            assert_eq!(spans[0].schema, VersionedId { id: 1, version: 1 });
            assert_eq!(spans[0].offset, 1);
            assert_eq!(spans[0].data, &[2, 3, 4]);
            assert!(!spans[0].is_signer && !spans[0].is_writable);
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn rejects_wrong_owner_and_wrong_role() {
        let mut lamports = 1;
        let mut data = [1, 2, 3, 4];
        let wrong_owner = account_info(&KEY, &OTHER, &mut lamports, &mut data, false, false);
        assert_eq!(
            with_account_spans(&PROGRAM, &[wrong_owner], &[binding(0, 2)], |_| Ok(())),
            Err(ProgramError::Custom(731))
        );

        let mut lamports = 1;
        let mut data = [1, 2, 3, 4];
        let wrong_role = account_info(&KEY, &PROGRAM, &mut lamports, &mut data, false, true);
        assert_eq!(
            with_account_spans(&PROGRAM, &[wrong_role], &[binding(0, 2)], |_| Ok(())),
            Err(ProgramError::Custom(731))
        );
    }

    #[test]
    fn rejects_out_of_bounds_and_overlapping_aliases_but_allows_disjoint_read_aliases() {
        let mut lamports = 1;
        let mut data = [1, 2, 3, 4, 5, 6];
        let info = account_info(&KEY, &PROGRAM, &mut lamports, &mut data, false, false);
        assert_eq!(
            with_account_spans(&PROGRAM, &[info.clone()], &[binding(5, 2)], |_| Ok(())),
            Err(ProgramError::Custom(730))
        );
        assert_eq!(
            with_account_spans(
                &PROGRAM,
                &[info.clone()],
                &[binding(0, 3), binding(2, 2)],
                |_| Ok(())
            ),
            Err(ProgramError::Custom(730))
        );
        with_account_spans(
            &PROGRAM,
            &[info],
            &[binding(0, 2), binding(2, 2)],
            |spans| {
                assert_eq!(spans[0].data, &[1, 2]);
                assert_eq!(spans[1].data, &[3, 4]);
                Ok(())
            },
        )
        .unwrap();
    }
}
