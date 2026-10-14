// SPDX-License-Identifier: GPL-3.0-only

//! A deterministic fuel meter for long-running stateful kernels (v0.3.0).
//!
//! A transition must be a pure function of its input, state and (with
//! `READS_RESOURCE`) resource, so a kernel may not stop when the transaction
//! runs low on compute: `sol_remaining_compute_units` is not available on
//! Fogo, and a stop that depended on it would make the state depend on the
//! budget. Instead the kernel charges abstract work units it defines (one per
//! rewrite, per node visited, per cache probe) against a fixed budget, and
//! when the budget runs out it saves its continuation in state and ends the
//! step. Every replay then stops at the same point.
//!
//! The budget comes from measurement, not from the meter: measure on the SBF
//! build the worst-case compute of one unit of each kind (ProgramTest or
//! Mollusk with the stock compute metering), then size the budget with
//! [`budget_units`] so a step that spends its whole budget, plus the
//! runtime's own overhead, stays under the kernel's declared compute units.
//! The measurement belongs to one image: requalify the budget after any
//! rebuild or toolchain change, since a step that exceeds its compute fails
//! every time it is retried and stalls the session. Give every unit a nonzero
//! cost (`try_charge(0)` always succeeds, so a zero-cost loop never ends).
//!
//! ```
//! use dcg_program::fuel::{budget_units, Fuel};
//!
//! // Declared 1,200,000 CU per step; 40,000 CU of DCG and kernel overhead
//! // measured outside the metered loop; the costliest unit measured at
//! // 900 CU; a 10% margin.
//! let units = budget_units(1_200_000, 40_000, 900, 1_000).unwrap();
//! let mut fuel = Fuel::new(units);
//! while fuel.try_charge(1) {
//!     // one unit of work
//! }
//! assert!(fuel.exhausted());
//! ```

/// Work units left in this step. Charging is all-or-nothing, so a kernel can
/// check that it can afford an operation before starting it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fuel {
    left: u64,
    spent: u64,
}

impl Fuel {
    /// A meter holding `units` for one step.
    pub const fn new(units: u64) -> Self {
        Self { left: units, spent: 0 }
    }

    /// Charge `units` if they are all available and return true; otherwise
    /// charge nothing and return false.
    #[inline]
    pub fn try_charge(&mut self, units: u64) -> bool {
        if units > self.left {
            return false;
        }
        self.left -= units;
        self.spent += units;
        true
    }

    /// Charge `units`, or return [`OutOfFuel`] without charging.
    #[inline]
    pub fn charge(&mut self, units: u64) -> Result<(), OutOfFuel> {
        if self.try_charge(units) { Ok(()) } else { Err(OutOfFuel) }
    }

    /// Units still available.
    pub const fn left(&self) -> u64 {
        self.left
    }

    /// Units charged so far in this step.
    pub const fn spent(&self) -> u64 {
        self.spent
    }

    /// Whether nothing is left.
    pub const fn exhausted(&self) -> bool {
        self.left == 0
    }
}

/// The step's budget ran out: save the continuation and end the step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutOfFuel;

/// Why a budget cannot be sized.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BudgetError {
    /// The per-unit cost is zero.
    ZeroUnitCost,
    /// The margin is 10,000 basis points or more.
    MarginTooLarge,
    /// The overhead leaves nothing of the declared compute.
    NoRoom,
    /// The declaration exceeds `MAX_DECLARED_KERNEL_COMPUTE_UNITS`.
    OverDeclared,
}

/// The number of work units one step may charge:
/// `floor((declared - overhead) * (1 - margin) / worst_unit_cu)`.
///
/// - `declared_cu`: the kernel's declared compute units for one step
///   (`ResourceLimits::max_compute_units`).
/// - `overhead_cu`: compute measured outside the metered work on SBF: DCG's
///   `ADVANCE` handling, binding, decoding the continuation, writing results.
/// - `worst_unit_cu`: the largest measured compute of one unit, across the
///   unit kinds and the inputs measured (worst case, not average).
/// - `margin_bps`: a safety margin in basis points of the remaining
///   compute; at least 1,000 (10%) is recommended.
pub fn budget_units(declared_cu: u64, overhead_cu: u64, worst_unit_cu: u64, margin_bps: u64) -> Result<u64, BudgetError> {
    if worst_unit_cu == 0 {
        return Err(BudgetError::ZeroUnitCost);
    }
    if margin_bps >= 10_000 {
        return Err(BudgetError::MarginTooLarge);
    }
    if declared_cu > crate::kernel::MAX_DECLARED_KERNEL_COMPUTE_UNITS {
        return Err(BudgetError::OverDeclared);
    }
    let room = declared_cu.checked_sub(overhead_cu).filter(|r| *r > 0).ok_or(BudgetError::NoRoom)?;
    let usable = room * (10_000 - margin_bps) / 10_000;
    let units = usable / worst_unit_cu;
    if units == 0 {
        return Err(BudgetError::NoRoom);
    }
    Ok(units)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn charging_is_all_or_nothing() {
        let mut fuel = Fuel::new(5);
        assert!(fuel.try_charge(3));
        assert!(!fuel.try_charge(3));
        assert_eq!((fuel.left(), fuel.spent()), (2, 3));
        assert_eq!(fuel.charge(2), Ok(()));
        assert_eq!(fuel.charge(1), Err(OutOfFuel));
        assert!(fuel.exhausted());
        assert!(fuel.try_charge(0));
    }

    #[test]
    fn budgets_follow_the_formula_and_refuse_nonsense() {
        assert_eq!(budget_units(1_200_000, 40_000, 900, 1_000), Ok(1_160));
        assert_eq!(budget_units(1_200_000, 40_000, 900, 0), Ok(1_288));
        assert_eq!(budget_units(100, 100, 1, 0), Err(BudgetError::NoRoom));
        assert_eq!(budget_units(100, 0, 200, 0), Err(BudgetError::NoRoom));
        assert_eq!(budget_units(100, 0, 0, 0), Err(BudgetError::ZeroUnitCost));
        assert_eq!(budget_units(100, 0, 1, 10_000), Err(BudgetError::MarginTooLarge));
        assert_eq!(budget_units(crate::kernel::MAX_DECLARED_KERNEL_COMPUTE_UNITS + 1, 0, 1, 0), Err(BudgetError::OverDeclared));
    }
}
