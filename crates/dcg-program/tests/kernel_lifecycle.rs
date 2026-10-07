// SPDX-License-Identifier: GPL-3.0-only

//! The test kernel through the static registry, a commitment and the
//! `ResolutionBackend` trait (moved from the deleted revision-8
//! `lifecycle_property_harness.rs`, which carried it, review 10-07 L3).

#![cfg(feature = "test-kernel")]

use dcg_program::kernel::{
    test_kernel::{BYTE_SUM, MANIFEST_APP, MODE_OPTIMISTIC_V1},
    Commitment, Kernel, KernelId, ResolutionBackend, ResolutionStatus,
};

struct State {
    claim: Commitment,
    status: ResolutionStatus,
}

struct ObserveBackend;

impl ResolutionBackend for ObserveBackend {
    type State = State;
    type Transition = Vec<u8>;
    type Error = ();

    fn mode(&self) -> dcg_program::kernel::ModeId {
        MODE_OPTIMISTIC_V1
    }

    fn start(&self, claimed_output: Commitment) -> Result<Self::State, Self::Error> {
        Ok(State {
            claim: claimed_output,
            status: ResolutionStatus::Pending,
        })
    }

    fn advance(
        &self,
        state: &mut Self::State,
        observed_output: Self::Transition,
    ) -> Result<ResolutionStatus, Self::Error> {
        if state.status != ResolutionStatus::Pending {
            return Ok(state.status);
        }
        state.status = if Commitment::sha256(&observed_output) == state.claim {
            ResolutionStatus::Final
        } else {
            ResolutionStatus::Refuted
        };
        Ok(state.status)
    }
}

#[test]
fn test_kernel_runs_through_static_registry_commitment_and_lifecycle() {
    let app = &MANIFEST_APP;
    let kernel_id = KernelId(*b"dcg-test-sum-v1\0");
    let mut output = [0u8; 256];
    let written = app
        .execute(
            kernel_id,
            1,
            1,
            MODE_OPTIMISTIC_V1,
            &[1, 2, 3, 250],
            &mut output,
        )
        .unwrap();
    assert_eq!(written, 8);
    let transition = output[..written].to_vec();
    assert_eq!(
        u64::from_le_bytes(transition.as_slice().try_into().unwrap()),
        256
    );

    let backend = ObserveBackend;
    let mut honest = backend.start(Commitment::sha256(&transition)).unwrap();
    assert_eq!(backend.mode(), MODE_OPTIMISTIC_V1);
    assert_eq!(
        backend.advance(&mut honest, transition.clone()).unwrap(),
        ResolutionStatus::Final
    );

    let mut malformed = backend.start(Commitment::sha256(&[0u8; 8])).unwrap();
    assert_eq!(
        backend.advance(&mut malformed, transition).unwrap(),
        ResolutionStatus::Refuted
    );
    assert_eq!(BYTE_SUM.manifest().id, kernel_id);
}
