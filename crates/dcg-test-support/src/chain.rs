// SPDX-License-Identifier: GPL-3.0-only
//! The test bank and its senders.

use solana_account::Account;
use solana_instruction::{account_meta::AccountMeta, error::InstructionError, Instruction};
use solana_keypair::Keypair;
use solana_program_test::{ProgramTest, ProgramTestContext};
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;
use solana_transaction_error::TransactionError;

pub const SYSTEM: Pubkey = solana_program::system_program::ID;

/// A system-owned, empty, funded account: a signer's starting balance. This is
/// environment, not protocol state.
pub fn system_funded() -> Account {
    Account { lamports: 1_000_000_000_000, data: vec![], owner: SYSTEM, executable: false, rent_epoch: 0 }
}

/// The custom code of a refused instruction (0 when it did not refuse with one).
pub fn custom(result: Result<(), TransactionError>) -> u32 {
    match result {
        Err(TransactionError::InstructionError(_, InstructionError::Custom(code))) => code,
        _ => 0,
    }
}

/// The test bank. Every transaction gets a distinct compute-unit limit, so
/// equal instruction bodies never collide as already processed; the recent
/// blockhash is refreshed every 32 sends and on expiry.
pub struct Chain {
    pub ctx: ProgramTestContext,
    pub program: Pubkey,
    blockhash: Option<solana_hash::Hash>,
    uses: usize,
    serial: u64,
    /// Print compute units for these tags (empty: none).
    pub trace_cu_tags: Vec<u8>,
}

impl Chain {
    /// Start a bank with `funded` signers given starting balances.
    pub async fn start(mut test: ProgramTest, program: Pubkey, funded: &[Pubkey]) -> Chain {
        for key in funded {
            test.add_account(*key, system_funded());
        }
        let ctx = test.start_with_context().await;
        Chain { ctx, program, blockhash: None, uses: 0, serial: 0, trace_cu_tags: Vec::new() }
    }

    /// Send one instruction to the program under test.
    pub async fn send(
        &mut self,
        payer: &Keypair,
        extra_signers: &[&Keypair],
        data: Vec<u8>,
        metas: Vec<AccountMeta>,
    ) -> Result<(), TransactionError> {
        let ix = Instruction { program_id: self.program, accounts: metas, data };
        self.send_instructions(payer, extra_signers, vec![ix]).await
    }

    /// Send instructions (any programs) in one transaction.
    pub async fn send_instructions(
        &mut self,
        payer: &Keypair,
        extra_signers: &[&Keypair],
        ixs: Vec<Instruction>,
    ) -> Result<(), TransactionError> {
        if self.blockhash.is_none() || self.uses >= 32 {
            self.refresh().await;
        }
        self.serial += 1;
        let limit = 1_400_000 - (self.serial % 100_000) as u32;
        let first_tag = ixs.iter().find(|ix| ix.program_id == self.program).and_then(|ix| ix.data.first().copied());
        let make = |blockhash| {
            let mut all = vec![solana_compute_budget_interface::ComputeBudgetInstruction::set_compute_unit_limit(limit)];
            all.extend(ixs.iter().cloned());
            let mut signers = vec![payer];
            signers.extend_from_slice(extra_signers);
            Transaction::new_signed_with_payer(&all, Some(&payer.pubkey()), &signers, blockhash)
        };
        let mut outcome = self.ctx.banks_client.process_transaction_with_metadata(make(self.blockhash.unwrap())).await;
        if matches!(&outcome, Err(e) if matches!(e.clone().unwrap(), TransactionError::BlockhashNotFound))
            || matches!(&outcome, Ok(inner) if matches!(inner.result, Err(TransactionError::BlockhashNotFound)))
        {
            self.refresh().await;
            outcome = self.ctx.banks_client.process_transaction_with_metadata(make(self.blockhash.unwrap())).await;
        }
        let inner = outcome.unwrap_or_else(|e| panic!("the bank refused the transaction: {e:?}"));
        if let (Some(tag), Some(meta)) = (first_tag, inner.metadata.as_ref()) {
            if self.trace_cu_tags.contains(&tag) {
                eprintln!("CU tag {tag} cu {}", meta.compute_units_consumed);
            }
        }
        self.uses += 1;
        inner.result
    }

    async fn refresh(&mut self) {
        self.blockhash = Some(self.ctx.get_new_latest_blockhash().await.expect("a recent blockhash"));
        self.uses = 0;
    }

    /// A system transfer (funding a PDA the way the permissionless path does).
    pub async fn transfer(&mut self, payer: &Keypair, to: Pubkey, lamports: u64) {
        let ix = solana_program::system_instruction::transfer(&payer.pubkey(), &to, lamports);
        self.send_instructions(payer, &[], vec![ix]).await.expect("System Program transfer");
    }

    /// Create a fresh account owned by `owner` through the System Program.
    pub async fn allocate(&mut self, payer: &Keypair, account: &Keypair, owner: Pubkey, bytes: usize) {
        let lamports = solana_program::rent::Rent::default().minimum_balance(bytes);
        let ix = solana_program::system_instruction::create_account(
            &payer.pubkey(),
            &account.pubkey(),
            lamports,
            bytes as u64,
            &owner,
        );
        self.send_instructions(payer, &[account], vec![ix]).await.expect("System Program creates the account");
    }

    pub async fn account(&mut self, key: Pubkey) -> Option<Account> {
        self.ctx.banks_client.get_account(key).await.unwrap()
    }

    /// The data of an account that must exist.
    pub async fn data(&mut self, key: Pubkey) -> Vec<u8> {
        self.account(key).await.unwrap_or_else(|| panic!("account {key} exists")).data
    }

    pub async fn slot(&mut self) -> u64 {
        self.ctx.banks_client.get_sysvar::<solana_program::clock::Clock>().await.unwrap().slot
    }

    /// Advance the bank to `slot` (environment: the clock, not protocol state).
    pub async fn warp_to(&mut self, slot: u64) {
        self.ctx.warp_to_slot(slot).unwrap();
        self.refresh().await;
    }
}
