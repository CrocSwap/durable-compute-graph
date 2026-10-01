use dcg_kernels::*;

#[test]
fn add_and_identity() {
    let mut out = [0u8; 4];
    assert_eq!(execute(KERNEL_ADD_I32, &[&2i32.to_le_bytes(), &3i32.to_le_bytes()], &mut out), Ok(4));
    assert_eq!(i32::from_le_bytes(out), 5);
    assert_eq!(execute(KERNEL_ADD_I32, &[&i32::MAX.to_le_bytes(), &1i32.to_le_bytes()], &mut out), Err(ERR_OVERFLOW));
    assert_eq!(execute(KERNEL_IDENTITY_I32, &[&(-7i32).to_le_bytes()], &mut out), Ok(4));
    assert_eq!(i32::from_le_bytes(out), -7);
    assert_eq!(execute(KERNEL_IDENTITY_I32, &[&[1u8, 2]], &mut out), Err(ERR_BAD_INPUT));
    assert_eq!(execute(9, &[], &mut out), Err(ERR_UNKNOWN_KERNEL));
}
