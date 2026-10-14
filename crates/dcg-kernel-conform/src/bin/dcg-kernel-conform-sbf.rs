// SPDX-License-Identifier: GPL-3.0-only

//! The kernel kit's same-source reference (v0.3.0 item 4): serves the
//! conformance protocol by running each request inside an SBF image under
//! ProgramTest, through the image's conformance entry
//! (`kernel_kit::conformance::serve_account_request`). Driving this and the
//! native `dcg-kernel-conform` with `python -m dcg.kernel_kit compare`
//! checks that a kernel's SBF build agrees with its native build, without a
//! Python mirror.
//!
//!     dcg-kernel-conform-sbf <dir with the .so> [--program dcg_program] [--tag 252]
//!
//! The image must route the tag to the conformance entry; DCG's own
//! `sbf-real-lifecycle-test` image does (`CONFORM_TAG`). A request whose
//! transaction fails (a kernel panic, the compute or heap limit) answers
//! `panic`. This checks the kernel, not account plumbing: it is not a
//! substitute for running the program's own instructions.

use std::io::{BufRead, Write};

use solana_account::{Account, AccountSharedData};
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_instruction::{account_meta::AccountMeta, Instruction};
use solana_program_test::ProgramTest;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;

const PROGRAM: Pubkey = Pubkey::new_from_array([0xC3; 32]);
const REQUEST: Pubkey = Pubkey::new_from_array([0xC4; 32]);
const ANSWER: Pubkey = Pubkey::new_from_array([0xC5; 32]);
const STATE: Pubkey = Pubkey::new_from_array([0xC6; 32]);
const RESOURCE: Pubkey = Pubkey::new_from_array([0xC7; 32]);

fn unhex(word: &str) -> Vec<u8> {
    if word == "-" {
        return Vec::new();
    }
    (0..word.len() / 2).map(|i| u8::from_str_radix(&word[2 * i..2 * i + 2], 16).expect("hex")).collect()
}

fn hex(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "-".into();
    }
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Move a stateful request's state and resource bytes into accounts: the
/// program then runs the kernel on them in place, without decoding hex.
/// Returns the rewritten line, the state bytes (or the zeroed state for
/// `init`) and the resource bytes, if any.
fn in_place(line: &str) -> (String, Option<Vec<u8>>, Option<Vec<u8>>) {
    let mut words: Vec<String> = line.split_whitespace().map(str::to_string).collect();
    match words.first().map(String::as_str) {
        Some("init") if words.len() == 5 => {
            let total: usize = words[4].split(',').map(|n| n.parse::<usize>().expect("a span length")).sum();
            (line.to_string(), Some(vec![0; total]), None)
        }
        Some("advance") if words.len() == 8 || words.len() == 9 => {
            let state = unhex(&words[6]);
            words[6] = "@".into();
            let mut resource = None;
            if words.len() == 9 {
                if let Some((head, bytes)) = words[8].split_once(':') {
                    resource = Some(unhex(bytes));
                    words[8] = format!("{head}:@");
                }
            }
            (words.join(" "), Some(state), resource)
        }
        _ => (line.to_string(), None, None),
    }
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let mut args = std::env::args().skip(1);
    let dir = args.next().expect("usage: dcg-kernel-conform-sbf <dir with the .so> [--program NAME] [--tag N]");
    let (mut name, mut tag) = ("dcg_program".to_string(), dcg_program::kernel_kit::conformance::CONFORM_TAG);
    while let Some(flag) = args.next() {
        let value = args.next().expect("a value after the flag");
        match flag.as_str() {
            "--program" => name = value,
            "--tag" => tag = value.parse().expect("a tag 0..=255"),
            other => panic!("unknown flag {other}"),
        }
    }
    // ProgramTest logs every instruction at debug level; quiet unless asked.
    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var("RUST_LOG", "error");
    }
    std::env::set_var("SBF_OUT_DIR", &dir);
    std::env::set_var("BPF_OUT_DIR", &dir);
    let mut test = ProgramTest::default();
    test.prefer_bpf(true);
    test.add_program(Box::leak(name.into_boxed_str()), PROGRAM, None);
    let mut ctx = test.start_with_context().await;
    let mut blockhash = ctx.banks_client.get_latest_blockhash().await.unwrap();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for (n, line) in std::io::stdin().lock().lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let (line, state, resource) = in_place(&line);
        let mut request = (line.len() as u32).to_le_bytes().to_vec();
        request.extend_from_slice(line.as_bytes());
        let answer_len = 4 + 3 * line.len() + 65_536;
        let mut accounts = vec![AccountMeta::new_readonly(REQUEST, false), AccountMeta::new(ANSWER, false)];
        if let Some(state) = &state {
            ctx.set_account(&STATE, &AccountSharedData::from(Account {
                lamports: 1_000_000_000_000,
                data: state.clone(),
                owner: PROGRAM,
                executable: false,
                rent_epoch: 0,
            }));
            accounts.push(AccountMeta::new(STATE, false));
        }
        if let Some(resource) = &resource {
            ctx.set_account(&RESOURCE, &AccountSharedData::from(Account {
                lamports: 1_000_000_000_000,
                data: resource.clone(),
                owner: solana_pubkey::Pubkey::default(),
                executable: false,
                rent_epoch: 0,
            }));
            accounts.push(AccountMeta::new_readonly(RESOURCE, false));
        }
        ctx.set_account(&REQUEST, &AccountSharedData::from(Account {
            lamports: 1_000_000_000_000,
            data: request,
            owner: solana_pubkey::Pubkey::default(),
            executable: false,
            rent_epoch: 0,
        }));
        ctx.set_account(&ANSWER, &AccountSharedData::from(Account {
            lamports: 1_000_000_000_000,
            data: vec![0; answer_len],
            owner: PROGRAM,
            executable: false,
            rent_epoch: 0,
        }));
        // The bank's clock moves on its own and an old blockhash eventually
        // fails; take the current one for every request (no wait).
        blockhash = ctx.banks_client.get_latest_blockhash().await.unwrap();
        // The price varies per request so identical requests are distinct
        // transactions under one blockhash.
        let ixs = [
            ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
            ComputeBudgetInstruction::request_heap_frame(256 * 1024),
            ComputeBudgetInstruction::set_compute_unit_price(n as u64 + 1),
            Instruction {
                program_id: PROGRAM,
                accounts,
                data: vec![tag],
            },
        ];
        let tx = Transaction::new_signed_with_payer(&ixs, Some(&ctx.payer.pubkey()), &[&ctx.payer], blockhash);
        let reply = match ctx.banks_client.process_transaction(tx).await {
            Ok(()) => {
                let raw = ctx.banks_client.get_account(ANSWER).await.unwrap().unwrap().data;
                let len = u32::from_le_bytes(raw[..4].try_into().unwrap()) as usize;
                let text = String::from_utf8_lossy(&raw[4..4 + len]).into_owned();
                if state.is_some() && text.contains(dcg_program::kernel_kit::conformance::STATE_TOKEN) {
                    let after = ctx.banks_client.get_account(STATE).await.unwrap().unwrap().data;
                    text.replace(dcg_program::kernel_kit::conformance::STATE_TOKEN, &hex(&after))
                } else {
                    text
                }
            }
            Err(_) => "panic".to_string(),
        };
        writeln!(out, "{reply}")?;
        out.flush()?;
    }
    Ok(())
}
