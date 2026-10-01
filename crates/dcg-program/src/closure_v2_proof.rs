// SPDX-License-Identifier: GPL-3.0-only

//! Typed proof helpers shared by closure-v2 dispute handlers.
//!
//! The legacy DCR1 instruction handlers are intentionally not part of DCG's
//! revision-8 surface. These pure-ish helpers are the reachable subset needed
//! by the generic dispute engine: finalized-leaf authentication and PT1
//! producer-route validation.

use crate::{
    account_provenance::{expect_derived, AccountKind, RoleFlags},
    closure_v2::{self, Coordinate as TreeCoordinate},
    hash, position_template as pt,
};
use solana_program::{
    account_info::AccountInfo, entrypoint::ProgramResult, program_error::ProgramError,
    pubkey::Pubkey,
};

const PROOF: u32 = 734;
const ROUTE: u32 = 738;
const LEAF_DOMAIN: &[u8] = b"basanos/dcg-hclosure-leaf/2";
const ROW_BYTES: usize = 120;
const WRITE_ROW_BYTES: usize = 48;

/// A proof coordinate independent of DCG's private tree implementation type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Coordinate {
    pub position: u32,
    pub segment: u16,
    pub entry: u32,
}

fn no(code: u32) -> ProgramError {
    ProgramError::Custom(code)
}

fn u16_at(raw: &[u8], at: usize) -> Result<u16, ProgramError> {
    let end = at.checked_add(2).ok_or(no(PROOF))?;
    Ok(u16::from_le_bytes(
        raw.get(at..end)
            .ok_or(no(PROOF))?
            .try_into()
            .map_err(|_| no(PROOF))?,
    ))
}

fn u32_at(raw: &[u8], at: usize) -> Result<u32, ProgramError> {
    let end = at.checked_add(4).ok_or(no(PROOF))?;
    Ok(u32::from_le_bytes(
        raw.get(at..end)
            .ok_or(no(PROOF))?
            .try_into()
            .map_err(|_| no(PROOF))?,
    ))
}

fn u64_at(raw: &[u8], at: usize) -> Result<u64, ProgramError> {
    let end = at.checked_add(8).ok_or(no(PROOF))?;
    Ok(u64::from_le_bytes(
        raw.get(at..end)
            .ok_or(no(PROOF))?
            .try_into()
            .map_err(|_| no(PROOF))?,
    ))
}

fn check_derived(
    account: &AccountInfo,
    program: &Pubkey,
    seeds: &[&[u8]],
    magic: &'static [u8],
    min_len: usize,
) -> ProgramResult {
    expect_derived(
        account,
        program,
        seeds,
        AccountKind::variable(magic, min_len, usize::MAX),
        RoleFlags {
            writable: false,
            signer: false,
        },
    )
    .map(|_| ())
    .map_err(|_| no(PROOF))
}

fn page_leaf(page: &[u8], local: u32) -> Result<&[u8], ProgramError> {
    let count = u32_at(page, 48)?;
    if local >= count || u32_at(page, 52)? != count {
        return Err(no(PROOF));
    }
    let at = 96usize
        .checked_add((local as usize).checked_mul(32).ok_or(no(PROOF))?)
        .ok_or(no(PROOF))?;
    let end = at.checked_add(32).ok_or(no(PROOF))?;
    page.get(at..end).ok_or(no(PROOF))
}

fn checked_page(
    program: &Pubkey,
    account: &AccountInfo,
    descriptor: &[u8; 32],
    position: u32,
    segment: u16,
    local: u32,
) -> ProgramResult {
    check_derived(
        account,
        program,
        &[
            b"dcg-hcl-page",
            descriptor,
            &position.to_le_bytes(),
            &segment.to_le_bytes(),
        ],
        b"DLP2",
        96,
    )?;
    let page = account.try_borrow_data()?;
    if page.len() < 96
        || u16_at(&page, 4)? != 1
        || u16_at(&page, 6)? != 1
        || &page[8..40] != descriptor
        || u32_at(&page, 40)? != position
        || u16_at(&page, 44)? != segment
        || u32_at(&page, 48)? == 0
        || u32_at(&page, 52)? != u32_at(&page, 48)?
        || page.len()
            != closure_v2::page_bytes(u32_at(&page, 48)?, u32_at(&page, 56)?)
                .map_err(|_| no(PROOF))?
        || page[64..96] == [0; 32]
    {
        return Err(no(PROOF));
    }
    page_leaf(&page, local)?;
    Ok(())
}

/// Verify the duplicate-last leaf tree, including interval and height domain
/// fields. A caller cannot replace a duplicate-last sibling.
fn verify_leaf_path(
    descriptor: &[u8; 32],
    position: u32,
    segment: u16,
    count: u32,
    local: u32,
    leaf: &[u8],
    siblings: &[u8],
    expected_segment_root: &[u8],
) -> ProgramResult {
    if count == 0 || local >= count || siblings.len() % 32 != 0 {
        return Err(no(PROOF));
    }
    let mut width = count;
    let mut index = local;
    let mut span = 1u32;
    let mut first = local;
    let mut end = local.checked_add(1).ok_or(no(PROOF))?;
    let mut digest: [u8; 32] = leaf.try_into().map_err(|_| no(PROOF))?;
    let mut at = 0usize;
    let mut height = 0u8;
    while width > 1 {
        let sibling_index = index ^ 1;
        let sibling_first = sibling_index.checked_mul(span).ok_or(no(PROOF))?;
        let sibling_end = sibling_first.checked_add(span).ok_or(no(PROOF))?.min(count);
        let odd = sibling_index >= width;
        let sibling = if odd {
            digest
        } else {
            let sibling_end = at.checked_add(32).ok_or(no(PROOF))?;
            let bytes = siblings.get(at..sibling_end).ok_or(no(PROOF))?;
            at = sibling_end;
            bytes.try_into().map_err(|_| no(PROOF))?
        };
        let (left, right, parent_first, parent_end) = if index & 1 == 0 {
            (digest, sibling, first, if odd { end } else { sibling_end })
        } else {
            (sibling, digest, sibling_first, end)
        };
        height = height.checked_add(1).ok_or(no(PROOF))?;
        digest = hash::sha256(&[
            b"basanos/dcg-hclosure-node/2",
            descriptor,
            &[1],
            &position.to_le_bytes(),
            &parent_first.to_le_bytes(),
            &parent_end.to_le_bytes(),
            &[height, 1],
            &left,
            &right,
        ]);
        first = parent_first;
        end = parent_end;
        index /= 2;
        width = width.checked_add(1).ok_or(no(PROOF))? / 2;
        span = span.checked_mul(2).ok_or(no(PROOF))?;
    }
    if at != siblings.len() {
        return Err(no(PROOF));
    }
    let root = hash::sha256(&[
        b"basanos/dcg-hclosure-segment-root/2",
        descriptor,
        &position.to_le_bytes(),
        &segment.to_le_bytes(),
        &count.to_le_bytes(),
        &digest,
        &[1],
    ]);
    if root != expected_segment_root {
        return Err(no(PROOF));
    }
    Ok(())
}

/// Authenticate a stored DCL2 leaf from any finalized position and page.
/// The compact path proves the page's segment root; DSR2 and DPR2 then bind
/// that root to the document's canonical segment table and position root.
#[allow(clippy::too_many_arguments)]
pub fn verify_finalized_leaf(
    program: &Pubkey,
    document: &AccountInfo,
    positions: &AccountInfo,
    page_account: &AccountInfo,
    roots_account: &AccountInfo,
    descriptor: &[u8; 32],
    coordinate: Coordinate,
    leaf: &[u8; 32],
    siblings: &[u8],
) -> ProgramResult {
    check_derived(
        document,
        program,
        &[b"dcg-hcl-document", descriptor],
        b"DCM2",
        40,
    )?;
    check_derived(
        positions,
        program,
        &[b"dcg-hcl-positions", descriptor],
        b"DPR2",
        48,
    )?;
    let doc = document.try_borrow_data()?;
    let pos = positions.try_borrow_data()?;
    if doc.len() < 40 || &doc[..4] != b"DCM2" || &doc[8..40] != descriptor {
        return Err(no(PROOF));
    }
    let segments = u16_at(&doc, 76)? as usize;
    let version = u16_at(&doc, 4)?;
    let header = closure_v2::dcm2_header(version).ok_or(no(PROOF))?;
    let stride = segments
        .checked_mul(6)
        .and_then(|n| n.checked_add(if version == 1 { 0 } else { 32 }))
        .ok_or(no(PROOF))?;
    let positions_count = usize::try_from(u32_at(&doc, 72)?).map_err(|_| no(PROOF))?;
    let expected_len = header
        .checked_add(
            stride
                .checked_mul(if version == 1 { 1 } else { positions_count })
                .ok_or(no(PROOF))?,
        )
        .ok_or(no(PROOF))?;
    let expected_positions_len = positions_count
        .checked_mul(32)
        .and_then(|n| n.checked_add(48))
        .ok_or(no(PROOF))?;
    if segments == 0
        || doc.len() != expected_len
        || u16_at(&doc, 6)? & 1 == 0
        || coordinate.position >= u32_at(&doc, 84)?
        || coordinate.position as usize >= positions_count
        || pos.len() != expected_positions_len
        || &pos[..4] != b"DPR2"
        || u16_at(&pos, 4)? != 1
        || u16_at(&pos, 6)? != 0
        || &pos[8..40] != descriptor
        || u32_at(&pos, 40)? != u32_at(&doc, 72)?
        || u32_at(&pos, 44)? <= coordinate.position
    {
        return Err(no(PROOF));
    }
    let table = if version == 1 {
        &doc[192..]
    } else {
        let base = header
            .checked_add(
                (coordinate.position as usize)
                    .checked_mul(stride)
                    .ok_or(no(PROOF))?,
            )
            .ok_or(no(PROOF))?;
        let table_start = base.checked_add(32).ok_or(no(PROOF))?;
        let table_end = base.checked_add(stride).ok_or(no(PROOF))?;
        doc.get(table_start..table_end).ok_or(no(PROOF))?
    };
    let segment_index = table
        .chunks_exact(6)
        .position(|row| u16_at(row, 0).ok() == Some(coordinate.segment))
        .ok_or(no(PROOF))?;
    checked_page(
        program,
        page_account,
        descriptor,
        coordinate.position,
        coordinate.segment,
        coordinate.entry,
    )?;
    let page = page_account.try_borrow_data()?;
    let count = u32_at(&page, 48)?;
    if count != u32_at(table, segment_index * 6 + 2)? || page_leaf(&page, coordinate.entry)? != leaf
    {
        return Err(no(PROOF));
    }
    let segment_roots: Vec<[u8; 32]> = if segments == 1 {
        if roots_account.key != page_account.key {
            return Err(no(PROOF));
        }
        vec![page[64..96].try_into().map_err(|_| no(PROOF))?]
    } else {
        check_derived(
            roots_account,
            program,
            &[
                b"dcg-hcl-roots",
                descriptor,
                &coordinate.position.to_le_bytes(),
            ],
            b"DSR2",
            48,
        )?;
        let roots = roots_account.try_borrow_data()?;
        if roots.len() != 48 + segments * 32
            || &roots[..4] != b"DSR2"
            || &roots[8..40] != descriptor
            || u32_at(&roots, 40)? != coordinate.position
            || u16_at(&roots, 6)? as usize != segments
            || &page[64..96] != &roots[48 + segment_index * 32..48 + (segment_index + 1) * 32]
        {
            return Err(no(PROOF));
        }
        roots[48..]
            .chunks_exact(32)
            .map(|row| row.try_into().map_err(|_| no(PROOF)))
            .collect::<Result<_, _>>()?
    };
    let table_root: &[u8; 32] = if version == 1 {
        doc[152..184].try_into().map_err(|_| no(PROOF))?
    } else {
        let base = header
            .checked_add(
                (coordinate.position as usize)
                    .checked_mul(stride)
                    .ok_or(no(PROOF))?,
            )
            .ok_or(no(PROOF))?;
        let end = base.checked_add(32).ok_or(no(PROOF))?;
        doc.get(base..end)
            .ok_or(no(PROOF))?
            .try_into()
            .map_err(|_| no(PROOF))?
    };
    let calculated =
        closure_v2::position_root(descriptor, coordinate.position, table_root, &segment_roots)?;
    let at = 48usize
        .checked_add(
            (coordinate.position as usize)
                .checked_mul(32)
                .ok_or(no(PROOF))?,
        )
        .ok_or(no(PROOF))?;
    let end = at.checked_add(32).ok_or(no(PROOF))?;
    if pos.get(at..end).ok_or(no(PROOF))? != calculated {
        return Err(no(PROOF));
    }
    verify_leaf_path(
        descriptor,
        coordinate.position,
        coordinate.segment,
        count,
        coordinate.entry,
        leaf,
        siblings,
        &page[64..96],
    )
}

/// Parse only the coordinate and write table of an already staged DCL2 leaf.
/// The descriptor is supplied by the separately validated document record.
pub(crate) fn preimage_fields<'a>(
    preimage: &'a [u8],
    descriptor: &[u8; 32],
) -> Result<(u32, u16, u32, u16, u16, &'a [u8]), ProgramError> {
    let base = LEAF_DOMAIN.len();
    if preimage.len() < base + 120
        || &preimage[..base] != LEAF_DOMAIN
        || &preimage[base..base + 32] != descriptor
        || preimage[base + 51] != 0
        || preimage[base + 118..base + 120] != [0; 2]
    {
        return Err(no(PROOF));
    }
    let writes = u16_at(preimage, base + 116)? as usize;
    let writes_bytes = writes.checked_mul(WRITE_ROW_BYTES).ok_or(no(PROOF))?;
    let expected_len = base
        .checked_add(120)
        .and_then(|n| n.checked_add(writes_bytes))
        .ok_or(no(PROOF))?;
    if preimage.len() != expected_len {
        return Err(no(PROOF));
    }
    Ok((
        u32_at(preimage, base + 32)?,
        u16_at(preimage, base + 36)?,
        u32_at(preimage, base + 38)?,
        u16_at(preimage, base + 44)?,
        u16_at(preimage, base + 48)?,
        &preimage[base + 120..],
    ))
}

/// Verify a PT1 producer-bound read's route, producer coordinate, committed
/// write row, and input digest, without looking up the finalized leaf.
#[allow(clippy::too_many_arguments)]
pub fn verify_producer_route<'t>(
    template: &'t pt::Template<'t>,
    clause: pt::Clause12<'t>,
    consumer_position: u32,
    consumer_entry: u32,
    route: pt::InstantiatedRoute,
    read_row: &[u8],
    input: &[u8],
    producer_preimage: &[u8],
    descriptor: &[u8; 32],
) -> Result<Coordinate, ProgramError> {
    if route.direction != 0
        || route.binding_kind != 1
        || route.read_class != 0
        || route.producer_position > consumer_position
        || (route.producer_position == consumer_position && route.producer_entry >= consumer_entry)
        || read_row.len() != ROW_BYTES
        || read_row[2] != 0
        || read_row[3] != 1
        || read_row[4..8] != [0; 4]
        || read_row[20..24] != [0; 4]
        || read_row[88..120] != [0; 32]
        || u16_at(read_row, 0)? != route.region_id
        || u64_at(read_row, 8)? != route.effective_offset
        || u32_at(read_row, 16)? != route.byte_length
        || input.len() != route.byte_length as usize
    {
        return Err(no(ROUTE));
    }
    let location = template.coordinate(route.producer_entry).map_err(no)?;
    let (position, segment, local, kernel, _, writes) =
        preimage_fields(producer_preimage, descriptor)?;
    let producer = template.entry(route.producer_entry).map_err(no)?;
    if route.producer_write_ordinal as u16 >= producer.write_count
        || writes.len() != producer.write_count as usize * WRITE_ROW_BYTES
    {
        return Err(no(ROUTE));
    }
    let producer_inst = template
        .instantiate_with(clause, route.producer_entry, route.producer_position)
        .map_err(no)?;
    let declared_write = producer_inst
        .route(producer.read_count + route.producer_write_ordinal as u16)
        .map_err(no)?;
    let write_at = (route.producer_write_ordinal as usize)
        .checked_mul(WRITE_ROW_BYTES)
        .ok_or(no(ROUTE))?;
    let write_end = write_at.checked_add(WRITE_ROW_BYTES).ok_or(no(ROUTE))?;
    let write = writes.get(write_at..write_end).ok_or(no(ROUTE))?;
    if position != route.producer_position
        || segment != location.segment
        || local != location.local
        || kernel != producer.kernel_index
        || u16_at(producer_preimage, LEAF_DOMAIN.len() + 42)? != location.operation_ordinal
        || declared_write.direction != 1
        || declared_write.region_id != route.region_id
        || declared_write.effective_offset != route.effective_offset
        || declared_write.byte_length != route.byte_length
        || u16_at(write, 0)? != route.region_id
        || write[2..4] != [0; 2]
        || u32_at(write, 4)? != route.byte_length
        || u64_at(write, 8)? != route.effective_offset
    {
        return Err(no(ROUTE));
    }
    let leaf = hash::sha256(&[producer_preimage]);
    let coordinate = Coordinate {
        position,
        segment,
        entry: local,
    };
    let digest = closure_v2::write_digest(
        descriptor,
        TreeCoordinate {
            position: coordinate.position,
            segment: coordinate.segment,
            entry: coordinate.entry,
        },
        route.region_id,
        route.effective_offset,
        input,
    )
    .map_err(|_| no(ROUTE))?;
    if read_row[24..56] != digest || read_row[56..88] != leaf || write[16..48] != digest {
        return Err(no(PROOF));
    }
    Ok(coordinate)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::str::FromStr;

    const DOCUMENT: &[u8] = include_bytes!("../tests/fixtures/closure_v2_generic/document.bin");
    const POSITIONS: &[u8] = include_bytes!("../tests/fixtures/closure_v2_generic/positions.bin");
    const PAGE: &[u8] = include_bytes!("../tests/fixtures/closure_v2_generic/page-1-1.bin");
    const ROOTS: &[u8] = include_bytes!("../tests/fixtures/closure_v2_generic/roots-1.bin");
    const RESPONSE: &[u8] = include_bytes!("../tests/fixtures/closure_v2_generic/entry-119.dgr1");

    #[test]
    fn finalized_leaf_rejects_a_substituted_document_address() {
        let program = Pubkey::new_unique();
        let descriptor = [7u8; 32];
        let wrong_document_key = Pubkey::new_unique();
        let arbitrary_key = Pubkey::new_unique();
        let mut lamports = [1u64; 5];
        let mut document_data = [0u8; 40];
        document_data[..4].copy_from_slice(b"DCM2");
        let mut positions_data = [0u8; 48];
        let mut page_data = [0u8; 96];
        let mut roots_data = [0u8; 48];
        let document = AccountInfo::new(
            &wrong_document_key,
            false,
            false,
            &mut lamports[0],
            &mut document_data,
            &program,
            false,
            0,
        );
        let positions = AccountInfo::new(
            &arbitrary_key,
            false,
            false,
            &mut lamports[1],
            &mut positions_data,
            &program,
            false,
            0,
        );
        let page = AccountInfo::new(
            &arbitrary_key,
            false,
            false,
            &mut lamports[2],
            &mut page_data,
            &program,
            false,
            0,
        );
        let roots = AccountInfo::new(
            &arbitrary_key,
            false,
            false,
            &mut lamports[3],
            &mut roots_data,
            &program,
            false,
            0,
        );
        let result = verify_finalized_leaf(
            &program,
            &document,
            &positions,
            &page,
            &roots,
            &descriptor,
            Coordinate {
                position: 0,
                segment: 0,
                entry: 0,
            },
            &[0; 32],
            &[],
        );
        assert_eq!(result, Err(no(PROOF)));
    }

    #[test]
    fn captured_finalized_leaf_rejects_substitution_for_every_proof_account() {
        assert_eq!(&RESPONSE[..4], b"DGR1");
        let response_version = u16::from_le_bytes(RESPONSE[4..6].try_into().unwrap());
        let head = match response_version {
            1 => 28usize,
            2 => 36usize,
            _ => panic!("unsupported captured envelope version"),
        };
        let read_count = u16::from_le_bytes(RESPONSE[6..8].try_into().unwrap()) as usize;
        let target_len = u32::from_le_bytes(RESPONSE[8..12].try_into().unwrap()) as usize;
        let target_at = head.checked_add(4 * read_count).unwrap();
        let target_end = target_at.checked_add(target_len).unwrap();
        let preimage = &RESPONSE[target_at..target_end];
        let descriptor: [u8; 32] = DOCUMENT[8..40].try_into().unwrap();
        let (position, segment, entry, _, _, _) = preimage_fields(preimage, &descriptor).unwrap();
        let coordinate = Coordinate {
            position,
            segment,
            entry,
        };
        assert_eq!((coordinate.position, coordinate.segment), (1, 1));
        let leaf = hash::sha256(&[preimage]);
        let siblings = captured_page_siblings(PAGE, coordinate, &descriptor);
        assert!(!siblings.is_empty());

        for substitution in [None, Some(0), Some(1), Some(2), Some(3)] {
            let expected = if substitution.is_none() {
                Ok(())
            } else {
                Err(no(PROOF))
            };
            assert_eq!(
                verify_captured_fixture(substitution, &descriptor, coordinate, &leaf, &siblings),
                expected,
                "substituted proof-account role {substitution:?}"
            );
        }

        let mut malformed_siblings = siblings;
        malformed_siblings[0] ^= 1;
        assert_eq!(
            verify_captured_fixture(None, &descriptor, coordinate, &leaf, &malformed_siblings),
            Err(no(PROOF))
        );
    }

    #[derive(Clone)]
    struct Node {
        digest: [u8; 32],
        first: u32,
        end: u32,
    }

    fn captured_page_siblings(
        page: &[u8],
        coordinate: Coordinate,
        descriptor: &[u8; 32],
    ) -> Vec<u8> {
        let count = u32::from_le_bytes(page[48..52].try_into().unwrap());
        let mut level = (0..count)
            .map(|index| {
                let at = 96 + index as usize * 32;
                Node {
                    digest: page[at..at + 32].try_into().unwrap(),
                    first: index,
                    end: index + 1,
                }
            })
            .collect::<Vec<_>>();
        let mut index = coordinate.entry as usize;
        let mut siblings = Vec::new();
        let mut height = 0u8;
        while level.len() > 1 {
            let sibling_index = index ^ 1;
            if let Some(sibling) = level.get(sibling_index) {
                siblings.extend_from_slice(&sibling.digest);
            }
            height += 1;
            let mut next = Vec::with_capacity((level.len() + 1) / 2);
            for pair in level.chunks(2) {
                let right = pair.get(1).unwrap_or(&pair[0]);
                let first = pair[0].first;
                let end = right.end;
                let digest = hash::sha256(&[
                    b"basanos/dcg-hclosure-node/2",
                    descriptor,
                    &[1],
                    &coordinate.position.to_le_bytes(),
                    &first.to_le_bytes(),
                    &end.to_le_bytes(),
                    &[height, 1],
                    &pair[0].digest,
                    &right.digest,
                ]);
                next.push(Node { digest, first, end });
            }
            level = next;
            index /= 2;
        }
        siblings
    }

    fn verify_captured_fixture(
        substitution: Option<usize>,
        descriptor: &[u8; 32],
        coordinate: Coordinate,
        leaf: &[u8; 32],
        siblings: &[u8],
    ) -> ProgramResult {
        const PROGRAM_ID: &str = "3Vf8AkJCAQXvEZa18bge4zNc9jZAgEHyRJ4FU8y7umhf";
        const DOCUMENT_KEY: &str = "CaX5pPCxJULRddkFdxphMZPXEcBxcpfPEZk9yyxUiZvz";
        const POSITIONS_KEY: &str = "5b2gPmUEaKyPUSiSrvwFqy4Bd9CBrwqxm4iifzyX2veT";
        const PAGE_KEY: &str = "3p14yJKYfeYmqpf4b73YrWjVpTrUnsNYpf7aLArqdmdP";
        const ROOTS_KEY: &str = "AJ3vviijrFDKQEHAJxEizaiEppsM36aF4XU6Cbs6gvJU";

        let program = Pubkey::from_str(PROGRAM_ID).unwrap();
        let mut keys = [
            Pubkey::from_str(DOCUMENT_KEY).unwrap(),
            Pubkey::from_str(POSITIONS_KEY).unwrap(),
            Pubkey::from_str(PAGE_KEY).unwrap(),
            Pubkey::from_str(ROOTS_KEY).unwrap(),
        ];
        if let Some(role) = substitution {
            keys[role] = Pubkey::new_unique();
        }
        let mut document_data = DOCUMENT.to_vec();
        let mut positions_data = POSITIONS.to_vec();
        let mut page_data = PAGE.to_vec();
        let mut roots_data = ROOTS.to_vec();
        let mut document_lamports = 1;
        let mut positions_lamports = 1;
        let mut page_lamports = 1;
        let mut roots_lamports = 1;
        let document = AccountInfo::new(
            &keys[0],
            false,
            false,
            &mut document_lamports,
            &mut document_data,
            &program,
            false,
            0,
        );
        let positions = AccountInfo::new(
            &keys[1],
            false,
            false,
            &mut positions_lamports,
            &mut positions_data,
            &program,
            false,
            0,
        );
        let page = AccountInfo::new(
            &keys[2],
            false,
            false,
            &mut page_lamports,
            &mut page_data,
            &program,
            false,
            0,
        );
        let roots = AccountInfo::new(
            &keys[3],
            false,
            false,
            &mut roots_lamports,
            &mut roots_data,
            &program,
            false,
            0,
        );
        verify_finalized_leaf(
            &program, &document, &positions, &page, &roots, descriptor, coordinate, leaf, siblings,
        )
    }
}
