//! Cross-check the extracted pure region folds against Basanos's shared v1
//! golden. The synthetic account bodies and account-content folds match the
//! existing Basanos region-seal vector generator.

use dcg_program::{hash::sha256, region_commitment};

const GOLDEN: &str = include_str!("../../../tests/golden/dcg/lifecycle/region_content_v1.tsv");
const SUPPLY_FRAME_DOMAIN: &[u8] = b"basanos/dcg-supply-frame/1";
const SUPPLY_FRAME_BYTES: usize = 1024;

fn golden_value(case: &str, field: &str) -> String {
    GOLDEN
        .lines()
        .skip(1)
        .filter_map(|line| {
            let mut fields = line.split('\t');
            let row_case = fields.next()?;
            let row_field = fields.next()?;
            let value = fields.next()?;
            (row_case == case && row_field == field).then(|| value.to_owned())
        })
        .next()
        .unwrap_or_else(|| panic!("missing region-content vector {case}/{field}"))
}

fn hex32(text: &str) -> [u8; 32] {
    assert_eq!(text.len(), 64, "expected a 32-byte hexadecimal digest");
    let mut out = [0u8; 32];
    for index in 0..32 {
        out[index] = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).unwrap();
    }
    out
}

/// Basanos's deterministic vector-byte generator.
fn blob(seed: &[u8], length: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut counter = 0u32;
    while out.len() < length {
        out.extend_from_slice(&sha256(&[
            b"basanos/dcg-vector-blob/1",
            seed,
            &counter.to_le_bytes(),
        ]));
        counter += 1;
    }
    out.truncate(length);
    out
}

/// Basanos's existing supply-content fold, kept test-local because the
/// extracted DCG module intentionally owns only the outer region fold.
fn account_content_digest(region_id: u16, first_region_offset: u64, body: &[u8]) -> [u8; 32] {
    let supplied_len = (body.len() as u64).to_le_bytes();
    let mut running = sha256(&[
        SUPPLY_FRAME_DOMAIN,
        &region_id.to_le_bytes(),
        &first_region_offset.to_le_bytes(),
        &supplied_len,
    ]);
    let mut offset = 0usize;
    let mut frame_index = 0u32;
    while offset < body.len() {
        let end = (offset + SUPPLY_FRAME_BYTES).min(body.len());
        let frame = &body[offset..end];
        running = sha256(&[
            SUPPLY_FRAME_DOMAIN,
            &running,
            &frame_index.to_le_bytes(),
            &(frame.len() as u32).to_le_bytes(),
            frame,
        ]);
        offset = end;
        frame_index += 1;
    }
    running
}

fn account_fold(region_id: u16, first_region_offset: u64, body: &[u8]) -> (u64, u64, [u8; 32]) {
    (
        first_region_offset,
        body.len() as u64,
        account_content_digest(region_id, first_region_offset, body),
    )
}

fn region_root(region_id: u16, byte_length: u64, cells: &[(u64, u64, [u8; 32])]) -> [u8; 32] {
    let mut running = region_commitment::seed_v1(region_id, byte_length, cells.len() as u32);
    for (region_offset, account_byte_length, content_digest) in cells {
        running = region_commitment::fold_account_v1(
            &running,
            *region_offset,
            *account_byte_length,
            content_digest,
        );
    }
    running
}

#[test]
fn region_content_folds_reproduce_the_shared_basanos_golden() {
    let account_bytes = 1_048_576usize;
    let account_count = 84usize;
    let mut cells = Vec::with_capacity(account_count);
    for index in 0..account_count {
        let body = blob(
            format!("region/fly-static/{index}").as_bytes(),
            account_bytes,
        );
        cells.push(account_fold(3, (index * account_bytes) as u64, &body));
    }
    assert_eq!(
        golden_value("fly_static_84", "account_count"),
        account_count.to_string()
    );
    assert_eq!(
        golden_value("fly_static_84", "byte_length"),
        (account_count * account_bytes).to_string()
    );
    let root = region_root(3, (account_count * account_bytes) as u64, &cells);
    assert_eq!(
        root,
        hex32(&golden_value("fly_static_84", "initial_content"))
    );

    let mut swapped = cells.clone();
    swapped.swap(0, 1);
    let swapped_root = region_root(3, (account_count * account_bytes) as u64, &swapped);
    assert_eq!(
        swapped_root,
        hex32(&golden_value("fly_static_84_swapped", "initial_content"))
    );
    assert_ne!(swapped_root, root);

    let mut halved = Vec::with_capacity(account_count / 2);
    for index in (0..account_count).step_by(2) {
        let mut body = blob(
            format!("region/fly-static/{index}").as_bytes(),
            account_bytes,
        );
        body.extend_from_slice(&blob(
            format!("region/fly-static/{}", index + 1).as_bytes(),
            account_bytes,
        ));
        let offset = (index * account_bytes) as u64;
        halved.push((
            offset,
            (2 * account_bytes) as u64,
            account_content_digest(3, offset, &body),
        ));
    }
    let halved_root = region_root(3, (account_count * account_bytes) as u64, &halved);
    assert_eq!(
        halved_root,
        hex32(&golden_value("fly_static_42", "initial_content"))
    );
    assert_ne!(halved_root, root);

    let single = blob(b"region/single", 65_536);
    let single_root = region_root(1, 65_536, &[account_fold(1, 0, &single)]);
    assert_eq!(
        single_root,
        hex32(&golden_value("single_account", "initial_content"))
    );
}

#[test]
fn region_content_domain_and_integer_bytes_are_versioned() {
    assert_eq!(
        region_commitment::REGION_CONTENT_DOMAIN_V1,
        b"basanos/dcg-region-content/1"
    );
    let expected = sha256(&[
        b"basanos/dcg-region-content/1",
        &3u16.to_le_bytes(),
        &88_080_384u64.to_le_bytes(),
        &84u32.to_le_bytes(),
    ]);
    assert_eq!(region_commitment::seed_v1(3, 88_080_384, 84), expected);
}
