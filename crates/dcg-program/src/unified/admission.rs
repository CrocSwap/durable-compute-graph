//! DEA2: the class-admission record of one `(DRP2, PT2S)` pair (spec §5).
//!
//! ```text
//!   0 "DEA2" | 4 version:u16 = 2 (revision 7), 3 (revision 8) | 6 flags:u16
//!   8 registry[32] | 40 table_root[32] | 72 PT2S[32] | 104 PT2S_sha256[32]
//! 136 position_count:u32 | 140 base_classes:u32 | 144 generated_classes:u32
//! 148 admitted:u32 | 152 n_max:u32 | 156 rs1_height:u8 | 157 zero[3]
//! 160 zero[32] (revision 7) | payer[32], the AdmissionBeginV2 signer (revision 8)
//! 192 bitmap, ceil((B + L·G)/8) bytes; bit i = class i admitted
//! ```
//! PDA `"dcg-envelope-admission-v2" | registry | PT2S | P:u32`. Summary
//! classes are document-specific and are checked by UnifiedInit instead.

use super::classes::{self, rs1_height};
use super::registry::{self, find_row, HEADER as DRP2_HEADER};
use super::{no, plan, u16_at, u32_at, ADMISSION_STATE, PLAN_BINDING, REGISTRY_ROOT};
use crate::hash;
use crate::kernel::{ApplicationManifest, CommittedReplayWitness, LegacyFormBinding};
use crate::pt2p::Pt2p;
use solana_program::{
    account_info::AccountInfo, entrypoint::ProgramResult, program_error::ProgramError,
    pubkey::Pubkey,
};

fn check_app_binding(
    manifest: &crate::kernel::ApplicationManifest,
    machine_selector: Option<u8>,
    form_id: u16,
) -> ProgramResult {
    if manifest.admits_legacy_form(machine_selector, form_id) {
        Ok(())
    } else {
        Err(no(super::APP_KERNEL_UNAVAILABLE))
    }
}

/// The plan and manifest facts needed to decide whether one routed app
/// opening can be admitted by the revision-8 adapter. Keeping the final
/// decision in one pure function makes each unsupported provenance refusal
/// independently testable without duplicating the adapter's checks.
#[derive(Clone, Copy)]
struct AppRouteFacts {
    route_count: usize,
    input_span_count: usize,
    read_count: u16,
    route_ordinal: u16,
    route_direction: u8,
    binding_kind: u8,
    consumer_position: u32,
    producer_position: u32,
    consumer_segment: u16,
    producer_segment: u16,
    consumer_local: u32,
    producer_local: u32,
    input_end: u32,
    read_route_bytes: u32,
    producer_has_binding: bool,
    producer_write_direction: u8,
    read_region: u16,
    write_region: u16,
    read_offset: u64,
    write_offset: u64,
    read_bytes: u32,
    write_bytes: u32,
    producer_output_bytes: u32,
    consumer_arw1_bytes: usize,
    producer_arw1_bytes: usize,
    segment_entries: u32,
}

fn app_route_opening_bound(facts: AppRouteFacts) -> Result<usize, u32> {
    let fail = || super::APP_KERNEL_UNAVAILABLE;
    if facts.route_count != 1
        || facts.input_span_count != 1
        || facts.route_ordinal >= facts.read_count
        || facts.route_direction != 0
        || facts.binding_kind != 1
        || facts.producer_position != facts.consumer_position
        || facts.read_route_bytes < facts.input_end
        || facts.producer_segment != facts.consumer_segment
        || facts.producer_local >= facts.consumer_local
        || !facts.producer_has_binding
        || facts.producer_write_direction != 1
        || facts.read_region != facts.write_region
        || facts.read_offset != facts.write_offset
        || facts.read_bytes != facts.write_bytes
        || facts.producer_output_bytes != facts.read_bytes
    {
        return Err(fail());
    }

    let path_height = if facts.segment_entries <= 1 {
        0usize
    } else {
        (32 - (facts.segment_entries - 1).leading_zeros()) as usize
    };
    facts
        .consumer_arw1_bytes
        .checked_add(14)
        .and_then(|n| n.checked_add(facts.producer_arw1_bytes))
        .and_then(|n| n.checked_add(32usize.checked_mul(path_height)?))
        .filter(|&n| n <= crate::kernel::CommittedReplayWitness::MAX_WITNESS_BYTES)
        .ok_or_else(fail)
}

/// Bound the largest opening the fixed revision-8 adapter can accept at this
/// exact plan coordinate. This is shared by tag 160 and the fix-point backstop.
pub(crate) fn app_opening_bound(
    x: &Pt2p<'_>,
    position: u32,
    index: u32,
    machine: u8,
    manifest: &ApplicationManifest,
) -> Result<usize, u32> {
    let fail = || super::APP_KERNEL_UNAVAILABLE;
    let entry = x.entry(position, index).map_err(|_| fail())?;
    let binding = manifest
        .resolve_legacy_form(machine, entry.kernel_index)
        .ok_or_else(fail)?;
    // Manifest routes select the plan reads that become application inputs;
    // other plan reads remain outside the app replay contract. Every selected
    // ordinal must exist at this particular plan coordinate.
    if binding
        .input_routes
        .iter()
        .any(|route| route.ordinal >= entry.read_count)
    {
        return Err(fail());
    }
    let consumer_bytes = ApplicationManifest::max_arw1_bytes(binding).ok_or_else(fail)?;
    if consumer_bytes > CommittedReplayWitness::MAX_WITNESS_BYTES {
        return Err(fail());
    }
    if binding.input_routes.is_empty() {
        return Ok(consumer_bytes);
    }
    if binding.input_routes.len() != 1 || binding.input_spans.len() != 1 {
        return Err(fail());
    }

    let coordinate = x.coordinate(position, index).map_err(|_| fail())?;
    let route_binding = binding.input_routes[0];
    if route_binding.length == 0 {
        return Err(fail());
    }
    let input_end = route_binding
        .offset
        .checked_add(route_binding.length)
        .ok_or_else(fail)?;
    if input_end > binding.input_spans[0].max_bytes {
        return Err(fail());
    }
    let target = entry;
    let route = x
        .route(&target, route_binding.ordinal)
        .map_err(|_| fail())?;
    let producer = x
        .entry(position, route.producer_entry)
        .map_err(|_| fail())?;
    let producer_coordinate = x
        .coordinate(position, route.producer_entry)
        .map_err(|_| fail())?;
    let producer_binding = manifest
        .resolve_legacy_form(machine, producer.kernel_index)
        .ok_or_else(fail)?;
    let producer_route_ordinal = producer
        .read_count
        .checked_add(route.producer_write_ordinal as u16)
        .ok_or_else(fail)?;
    let producer_route = x
        .route(&producer, producer_route_ordinal)
        .map_err(|_| fail())?;

    let segment_index = (0..x.segment_count)
        .find(|&i| {
            x.segment_row(position, i as usize)
                .is_ok_and(|row| row.0 == coordinate.segment)
        })
        .ok_or_else(fail)?;
    let entries = x
        .segment_row(position, segment_index as usize)
        .map_err(|_| fail())?
        .1;
    let producer_bytes = ApplicationManifest::max_arw1_bytes(producer_binding).ok_or_else(fail)?;
    app_route_opening_bound(AppRouteFacts {
        route_count: binding.input_routes.len(),
        input_span_count: binding.input_spans.len(),
        read_count: target.read_count,
        route_ordinal: route_binding.ordinal,
        route_direction: route.direction,
        binding_kind: route.binding_kind,
        consumer_position: position,
        producer_position: route.producer_position,
        consumer_segment: coordinate.segment,
        producer_segment: producer_coordinate.segment,
        consumer_local: coordinate.local,
        producer_local: producer_coordinate.local,
        input_end,
        read_route_bytes: route.byte_length,
        producer_has_binding: true,
        producer_write_direction: producer_route.direction,
        read_region: route.region_id,
        write_region: producer_route.region_id,
        read_offset: route.effective_offset,
        write_offset: producer_route.effective_offset,
        read_bytes: route.byte_length,
        write_bytes: producer_route.byte_length,
        producer_output_bytes: producer_binding.claimed_output_bytes as u32,
        consumer_arw1_bytes: consumer_bytes,
        producer_arw1_bytes: producer_bytes,
        segment_entries: entries,
    })
}

fn validate_app_bound_class(
    x: &Pt2p<'_>,
    key: classes::ClassKey,
    form: u16,
    machine: u8,
    _binding: &LegacyFormBinding,
    manifest: &ApplicationManifest,
) -> Result<(), u32> {
    let fail = || super::APP_KERNEL_UNAVAILABLE;
    match key {
        classes::ClassKey::Base(old) => {
            // Base classes can be absent in replaced windows. Check every
            // extant instance so a position-specific producer or path height
            // cannot become an executor timeout after admission.
            for position in 0..x.position_count {
                if let Some(index) = x.old_to_new(old, position).map_err(|_| fail())? {
                    let entry = x.entry(position, index).map_err(|_| fail())?;
                    if entry.kernel_index == form {
                        app_opening_bound(x, position, index, machine, manifest)?;
                    }
                }
            }
        }
        // This adapter is bound to the frozen legacy-form rows. Generated
        // forms do not have a compatible coordinate contract yet.
        classes::ClassKey::Gen { .. } => return Err(fail()),
    }
    Ok(())
}

pub const HEADER: usize = 192;
#[cfg(feature = "revision-7")]
pub const VERSION: u16 = 2;
#[cfg(feature = "revision-8")]
pub const VERSION: u16 = 3;
pub const MAX_STEP: u16 = 256;
const FLAG_COMPLETE: u16 = 1;
const FLAG_APP_BOUND: u16 = 2;

pub fn bytes(classes: u32) -> usize {
    HEADER + (classes as usize).div_ceil(8)
}

#[derive(Clone, Copy, Debug)]
pub struct View {
    pub registry: [u8; 32],
    pub root: [u8; 32],
    pub pt2s: [u8; 32],
    pub pt2s_sha256: [u8; 32],
    pub position_count: u32,
    pub base_classes: u32,
    pub generated_classes: u32,
    pub admitted: u32,
    pub n_max: u32,
    pub rs1_height: u8,
    pub complete: bool,
    pub app_bound: bool,
    pub payer: [u8; 32],
}

/// A DEA2 at its PDA with a consistent header (782 otherwise). With
/// `popcount` the bitmap is also counted (UnifiedInit; handlers that only
/// set bits keep the count by construction).
pub fn view(program: &Pubkey, account: &AccountInfo, popcount: bool) -> Result<View, ProgramError> {
    if account.owner != program {
        return Err(no(ADMISSION_STATE));
    }
    let raw = account.try_borrow_data()?;
    let bad = || no(ADMISSION_STATE);
    if raw.len() < HEADER
        || raw[..4] != *b"DEA2"
        || u16_at(&raw, 4, ADMISSION_STATE)? != VERSION
        || u16_at(&raw, 6, ADMISSION_STATE)? & !(FLAG_COMPLETE | FLAG_APP_BOUND) != 0
        || raw[157..160] != [0; 3]
        || (VERSION == 2 && raw[160..192] != [0; 32])
        || (VERSION == 3 && raw[160..192] == [0; 32])
    {
        return Err(bad());
    }
    let a = |at: usize| -> [u8; 32] { raw[at..at + 32].try_into().unwrap() };
    let v = View {
        registry: a(8),
        root: a(40),
        pt2s: a(72),
        pt2s_sha256: a(104),
        position_count: u32_at(&raw, 136, ADMISSION_STATE)?,
        base_classes: u32_at(&raw, 140, ADMISSION_STATE)?,
        generated_classes: u32_at(&raw, 144, ADMISSION_STATE)?,
        admitted: u32_at(&raw, 148, ADMISSION_STATE)?,
        n_max: u32_at(&raw, 152, ADMISSION_STATE)?,
        rs1_height: raw[156],
        complete: u16_at(&raw, 6, ADMISSION_STATE)? & FLAG_COMPLETE != 0,
        app_bound: u16_at(&raw, 6, ADMISSION_STATE)? & FLAG_APP_BOUND != 0,
        payer: if VERSION == 3 {
            raw[160..192].try_into().unwrap()
        } else {
            [0; 32]
        },
    };
    let total = v
        .base_classes
        .checked_add(v.generated_classes)
        .ok_or(bad())?;
    let (key, _) = super::address::admission(
        program,
        &Pubkey::new_from_array(v.registry),
        &Pubkey::new_from_array(v.pt2s),
        v.position_count,
    );
    if *account.key != key
        || raw.len() != bytes(total)
        || v.admitted > total
        || v.complete != (v.admitted == total)
        || (total % 8 != 0 && raw[raw.len() - 1] >> (total % 8) != 0)
    {
        return Err(bad());
    }
    if popcount && raw[HEADER..].iter().map(|b| b.count_ones()).sum::<u32>() != v.admitted {
        return Err(bad());
    }
    Ok(v)
}

/// tag 159 AdmissionBeginV2 (permissionless). Data: the tag alone.
/// Accounts: payer(s,w), DEA2 PDA(w), DRP2, PT2S, base routes, base geometry, system.
pub fn begin(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let expected_accounts = if cfg!(feature = "revision-8") { 8 } else { 7 };
    if accounts.len() != expected_accounts || data.len() != 1 {
        return Err(no(ADMISSION_STATE));
    }
    plan::bind_pt2s(program, &accounts[3], &accounts[4], &accounts[5], None)?;
    let (positions, base, generated, n_max, height, digest) = {
        let s = accounts[3].try_borrow_data()?;
        let (routes, geometry) = (
            accounts[4].try_borrow_data()?,
            accounts[5].try_borrow_data()?,
        );
        let x = plan::view(&s, &routes, &geometry, &[], None)?;
        let total = classes::class_count(&x).map_err(|_| no(PLAN_BINDING))?;
        (
            x.position_count,
            x.base_entries,
            total - x.base_entries,
            x.n_of(x.position_count - 1),
            rs1_height(x.position_count),
            hash::sha256(&[&s]),
        )
    };
    #[cfg(feature = "revision-8")]
    {
        let bound_registry =
            super::config::live_template_registry(program, &accounts[7], accounts[3].key, &digest)?;
        if bound_registry != accounts[2].key.to_bytes() {
            return Err(no(super::config::TEMPLATE_SEAL));
        }
    }
    let reg = registry::frozen(program, &accounts[2], None)?;
    let (key, bump) =
        super::address::admission(program, accounts[2].key, accounts[3].key, positions);
    if *accounts[1].key != key {
        return Err(no(ADMISSION_STATE));
    }
    let size = bytes(base + generated);
    registry::create_pda(
        program,
        &accounts[0],
        &accounts[1],
        &accounts[6],
        &[
            super::address::ADMISSION_SEED,
            accounts[2].key.as_ref(),
            accounts[3].key.as_ref(),
            &positions.to_le_bytes(),
            &[bump],
        ],
        size,
        size,
        ADMISSION_STATE,
        ADMISSION_STATE,
    )?;
    let mut raw = accounts[1].try_borrow_mut_data()?;
    raw[..4].copy_from_slice(b"DEA2");
    raw[4..6].copy_from_slice(&VERSION.to_le_bytes());
    raw[8..40].copy_from_slice(accounts[2].key.as_ref());
    raw[40..72].copy_from_slice(&reg.root);
    raw[72..104].copy_from_slice(accounts[3].key.as_ref());
    raw[104..136].copy_from_slice(&digest);
    raw[136..140].copy_from_slice(&positions.to_le_bytes());
    raw[140..144].copy_from_slice(&base.to_le_bytes());
    raw[144..148].copy_from_slice(&generated.to_le_bytes());
    raw[152..156].copy_from_slice(
        &u32::try_from(n_max)
            .map_err(|_| no(PLAN_BINDING))?
            .to_le_bytes(),
    );
    raw[156] = height;
    #[cfg(feature = "revision-8")]
    raw[160..192].copy_from_slice(accounts[0].key.as_ref());
    Ok(())
}

/// tag 160 AdmissionStepV2 (permissionless). Data: `first:u32 | count:u16`,
/// `1 <= count <= 256`. Accounts: DEA2(w), DRP2, PT2S, PT1S, base routes,
/// base geometry. The PT1S (named by the PT2S) supplies the payload index a
/// base class shape needs (spec §3.1 `payload`); the spec's account list
/// omits it (reported). Classes run in index order; an empty class sets its
/// bit; the first refusal returns its §3.2 code and changes nothing.
pub fn step(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    step_with_manifest(program, accounts, data, None)
}

pub fn step_with_manifest(
    program: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    manifest: Option<&'static crate::kernel::ApplicationManifest>,
) -> ProgramResult {
    if accounts.len() != 6 || data.len() != 7 || !accounts[0].is_writable {
        return Err(no(ADMISSION_STATE));
    }
    let first = u32_at(data, 1, ADMISSION_STATE)?;
    let count = u16_at(data, 5, ADMISSION_STATE)?;
    if count == 0 || count > MAX_STEP {
        return Err(no(ADMISSION_STATE));
    }
    let v = view(program, &accounts[0], false)?;
    let end = first.checked_add(count as u32).ok_or(no(ADMISSION_STATE))?;
    if v.complete || end > v.base_classes + v.generated_classes {
        return Err(no(ADMISSION_STATE));
    }
    if let Some(manifest) = manifest {
        // The app image's resource declarations are part of admission. A
        // kernel whose declared per-invocation CU ceiling exceeds the
        // transaction profile cannot be selected by a committed document.
        manifest
            .validate()
            .map_err(|_| no(super::APP_KERNEL_UNAVAILABLE))?;
    }
    if accounts[1].key.as_ref() != v.registry {
        return Err(no(REGISTRY_ROOT));
    }
    registry::frozen(program, &accounts[1], Some(&v.root))?;
    if accounts[2].key.as_ref() != v.pt2s {
        return Err(no(PLAN_BINDING));
    }
    plan::bind_pt2s(program, &accounts[2], &accounts[4], &accounts[5], None)?;
    let mut set: Vec<u32> = Vec::with_capacity(count as usize);
    let mut app_bound = false;
    {
        let s = accounts[2].try_borrow_data()?;
        if hash::sha256(&[&s]) != v.pt2s_sha256 {
            return Err(no(PLAN_BINDING));
        }
        let index_at = plan::bind_pt1s(program, &accounts[2], &accounts[3])?;
        let pt1s = accounts[3].try_borrow_data()?;
        let (routes, geometry) = (
            accounts[4].try_borrow_data()?,
            accounts[5].try_borrow_data()?,
        );
        let x = plan::view(&s, &routes, &geometry, &[], Some(&pt1s[index_at..]))?;
        if x.position_count != v.position_count {
            return Err(no(PLAN_BINDING));
        }
        let rows_raw = accounts[1].try_borrow_data()?;
        let rows = &rows_raw[DRP2_HEADER..];
        let machine_selector = registry::machine_selector(&rows_raw[56..120]);
        let bitmap = accounts[0].try_borrow_data()?;
        for i in first..end {
            if bitmap[HEADER + i as usize / 8] >> (i % 8) & 1 == 1 {
                continue;
            }
            let key = classes::key_of(&x, i).map_err(|_| no(PLAN_BINDING))?;
            if let Some(shape) = classes::class_shape(&x, key).map_err(|_| no(PLAN_BINDING))? {
                if let Some(manifest) = manifest {
                    check_app_binding(manifest, machine_selector, shape.form)?;
                    if let Some(machine) = machine_selector {
                        if let Some(binding) = manifest.resolve_legacy_form(machine, shape.form) {
                            validate_app_bound_class(
                                &x, key, shape.form, machine, binding, manifest,
                            )
                            .map_err(no)?;
                            app_bound = true;
                        }
                    }
                }
                let row = find_row(rows, shape.form).map_err(no)?;
                let hooks: &dyn crate::compatibility::ApplicationHooks = manifest
                    .map(|app| app.hooks)
                    .unwrap_or(&crate::compatibility::REVISION8_COMPATIBILITY);
                let code = registry::check_with(row.as_ref(), &shape, hooks);
                if code != 0 {
                    return Err(no(code));
                }
            }
            set.push(i);
        }
    }
    let mut raw = accounts[0].try_borrow_mut_data()?;
    let mut admitted = v.admitted;
    for i in set {
        raw[HEADER + i as usize / 8] |= 1 << (i % 8);
        admitted += 1;
    }
    raw[148..152].copy_from_slice(&admitted.to_le_bytes());
    let mut flags = u16_at(&raw, 6, ADMISSION_STATE)?;
    if app_bound {
        flags |= FLAG_APP_BOUND;
    }
    if admitted == v.base_classes + v.generated_classes {
        flags |= FLAG_COMPLETE;
    }
    raw[6..8].copy_from_slice(&flags.to_le_bytes());
    Ok(())
}

#[cfg(all(test, feature = "test-kernel"))]
mod tests {
    use super::*;

    #[test]
    fn required_app_binding_is_an_admission_refusal() {
        let manifest = &crate::kernel::test_kernel::MANIFEST_APP;
        #[cfg(all(
            not(feature = "sbf-real-lifecycle-test"),
            not(feature = "sbf-unbound-form-test")
        ))]
        {
            assert_eq!(check_app_binding(manifest, Some(1), 22), Ok(()));
            assert_eq!(
                check_app_binding(manifest, Some(1), 23),
                Err(no(super::super::APP_KERNEL_UNAVAILABLE))
            );
            assert_eq!(
                check_app_binding(manifest, None, 22),
                Err(no(super::super::APP_KERNEL_UNAVAILABLE))
            );
        }
        #[cfg(all(
            feature = "sbf-real-lifecycle-test",
            not(feature = "sbf-unbound-form-test")
        ))]
        {
            assert_eq!(check_app_binding(manifest, Some(1), 22), Ok(()));
            assert_eq!(check_app_binding(manifest, Some(1), 30), Ok(()));
            assert_eq!(check_app_binding(manifest, Some(1), 257), Ok(()));
            assert_eq!(check_app_binding(manifest, None, 22), Ok(()));
        }
        #[cfg(feature = "sbf-unbound-form-test")]
        {
            assert_eq!(check_app_binding(manifest, Some(1), u16::MAX), Ok(()));
            assert_eq!(
                check_app_binding(manifest, Some(1), 22),
                Err(no(super::super::APP_KERNEL_UNAVAILABLE))
            );
            assert_eq!(
                check_app_binding(manifest, Some(1), 257),
                Err(no(super::super::APP_KERNEL_UNAVAILABLE))
            );
        }
    }
}

#[cfg(test)]
mod app_route_admission_tests {
    use super::*;

    fn valid_route() -> AppRouteFacts {
        AppRouteFacts {
            route_count: 1,
            input_span_count: 1,
            read_count: 1,
            route_ordinal: 0,
            route_direction: 0,
            binding_kind: 1,
            consumer_position: 5,
            producer_position: 5,
            consumer_segment: 2,
            producer_segment: 2,
            consumer_local: 9,
            producer_local: 8,
            input_end: 3,
            read_route_bytes: 8,
            producer_has_binding: true,
            producer_write_direction: 1,
            read_region: 4,
            write_region: 4,
            read_offset: 24,
            write_offset: 24,
            read_bytes: 8,
            write_bytes: 8,
            producer_output_bytes: 8,
            consumer_arw1_bytes: 44,
            producer_arw1_bytes: 268,
            segment_entries: 8,
        }
    }

    #[test]
    fn app_admission_accepts_a_bounded_same_segment_route() {
        assert_eq!(app_route_opening_bound(valid_route()), Ok(422));
    }

    #[test]
    fn app_admission_accepts_one_selected_route_from_multiple_plan_reads() {
        let mut facts = valid_route();
        facts.read_count = 8;
        facts.route_ordinal = 7;
        assert_eq!(app_route_opening_bound(facts), Ok(422));
    }

    #[test]
    fn app_admission_refuses_a_selected_ordinal_outside_plan_reads() {
        let mut facts = valid_route();
        facts.read_count = 7;
        facts.route_ordinal = 7;
        assert_eq!(
            app_route_opening_bound(facts),
            Err(super::super::APP_KERNEL_UNAVAILABLE)
        );
    }

    #[test]
    fn app_admission_refuses_cross_segment_routes() {
        let mut facts = valid_route();
        facts.producer_segment = facts.consumer_segment + 1;
        assert_eq!(
            app_route_opening_bound(facts),
            Err(super::super::APP_KERNEL_UNAVAILABLE)
        );
    }

    #[test]
    fn app_admission_refuses_cross_position_routes() {
        let mut facts = valid_route();
        facts.producer_position -= 1;
        assert_eq!(
            app_route_opening_bound(facts),
            Err(super::super::APP_KERNEL_UNAVAILABLE)
        );
    }

    #[test]
    fn app_admission_refuses_document_inputs() {
        let mut facts = valid_route();
        facts.binding_kind = 2;
        assert_eq!(
            app_route_opening_bound(facts),
            Err(super::super::APP_KERNEL_UNAVAILABLE)
        );
    }

    #[test]
    fn app_admission_refuses_multi_route_forms() {
        let mut facts = valid_route();
        facts.route_count = 2;
        facts.input_span_count = 2;
        facts.read_count = 2;
        assert_eq!(
            app_route_opening_bound(facts),
            Err(super::super::APP_KERNEL_UNAVAILABLE)
        );
    }

    #[test]
    fn app_admission_refuses_unbound_producers() {
        let mut facts = valid_route();
        facts.producer_has_binding = false;
        assert_eq!(
            app_route_opening_bound(facts),
            Err(super::super::APP_KERNEL_UNAVAILABLE)
        );
    }

    #[test]
    fn app_admission_refuses_route_paths_over_the_witness_cap() {
        let mut facts = valid_route();
        facts.segment_entries = 1 << 20;
        assert_eq!(
            app_route_opening_bound(facts),
            Err(super::super::APP_KERNEL_UNAVAILABLE)
        );
    }
}
