use dcg_program::position_template as pt;

const ROUTES: &[u8] = include_bytes!("../../../tests/golden/dcg/form47_pxr1_routes_v1.bin");
const CAPTURED_DIRECTORY: &[u8] =
    include_bytes!("../../../tests/golden/dcg/pxr1_form47_k35_compiler_v1.bin");
const GEOMETRY: &[u8] = include_bytes!("../../../tests/golden/dcg/pt2_variable/two-geometry.bin");

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}

#[test]
fn compiler_v1_form47_route_golden_and_captured_directory_decode() {
    // This route set is emitted by the Python Form-47 compiler helper. Both
    // implementations consume the same checked-in bytes.
    assert_eq!(pt::decode_clause5(ROUTES), Err(pt::MALFORMED));
    assert_eq!(pt::decode_clause5_v4(ROUTES), Ok(4));
    let (_, _, pxr) = pt::route_header_v4(ROUTES).unwrap();
    let pxr = pxr.unwrap();
    assert_eq!(pxr.token_count, 248_320);
    assert_eq!(pxr.row_count, 2);
    assert_eq!(pxr.row(0).unwrap().first_token, 0);
    assert_eq!(pxr.row(0).unwrap().token_count, 125_000);
    assert_eq!(pxr.row(1).unwrap().first_token, 125_000);
    assert_eq!(pxr.row(1).unwrap().token_count, 123_320);

    // The larger PXR1 directory comes from the retained K=35 compiler-v1
    // decision fixture and independently exercises the Rust decoder.
    let captured = pt::decode_pxr1(CAPTURED_DIRECTORY).unwrap();
    assert_eq!(captured.token_count, 248_320);
    assert_eq!(captured.row_count, 3_191);

    // The route golden carries the same small PXR1 shape with concrete
    // producer writes, so exercise the full Rust validator too.
    let clause12 = pt::decode_clause12_v2(GEOMETRY).unwrap();
    let validated = pt::validate_pxr1(ROUTES, clause12, 248_320).unwrap();
    assert_eq!(validated.row_count, 2);
}

#[test]
fn pxr1_rejects_reserved_bits_and_write_ordinal_255() {
    let mut wrong_offset = ROUTES.to_vec();
    let extension_offset = u32_at(&wrong_offset, 72) as usize;
    wrong_offset[72..76].copy_from_slice(&((extension_offset as u32) + 1).to_le_bytes());
    assert_eq!(pt::route_header_v4(&wrong_offset), Err(pt::MALFORMED));

    let truncated = &ROUTES[..ROUTES.len() - 1];
    assert_eq!(pt::route_header_v4(truncated), Err(pt::MALFORMED));

    let mut malformed = ROUTES.to_vec();
    let first_row = extension_offset + pt::PXR1_HEADER_BYTES;
    malformed[first_row + 12..first_row + 14].copy_from_slice(&255u16.to_le_bytes());
    assert_eq!(pt::route_header_v4(&malformed), Err(pt::MALFORMED));

    let mut reserved = ROUTES.to_vec();
    reserved[first_row + 14] = 1;
    assert_eq!(pt::route_header_v4(&reserved), Err(pt::MALFORMED));
}
