use std::{
    fs,
    path::{Path, PathBuf},
};
use syn::{
    visit::{self, Visit},
    Expr, ExprCall, ExprMethodCall, ImplItemFn, ItemFn, TraitItemFn,
};

// These low-level mutators have no identity inputs of their own. Their
// callers validate the exact account role before delegating the write.
const CALLER_GATED_WRITERS: &[(&str, &str)] = &[
    ("unified/bond.rs", "escrow_pot"),
    ("unified/bond.rs", "assign_to_program"),
    ("unified/bond.rs", "standard_payout"),
];

const GATES: &[&str] = &[
    "expect_derived",
    "expect_derived_with_bump",
    "expect_keyed",
    "expect_system_derived",
    "expect_system_account_shape",
    "create_derived_account",
    "allocate_derived_account",
    "validate_creation_target",
    "create_pda",
    "checked_session",
    "checked_session_from",
    "checked_resource",
    "checked_anchor",
    "stream_pda_check",
    "state_meta",
    "view_meta",
    "document",
    "document_v8",
    "document_v8_with_bump",
    "document_v8_stored",
    "live",
    "positions",
    "positions_with_bump",
    "positions_from_document",
    "view",
    "view_v8_status",
    "view_v8_status_with_bump",
    "record",
    "record_v8",
    "record_document",
    "read_settlement",
    "read_settlement_with_hooks",
    "validate_escrow",
    "validate_escrow_with_bump",
    "open_checks",
    "account",
    "sealed",
    "authenticate_document",
    "authenticate_result",
    "bind_bytes",
    "check_state",
    "check_order",
    "validate_pt1x_output_binding",
    "template_record",
    "close_unpublished_pt1x",
    "close_unpublished_pt1x_pt2s",
];

#[derive(Default)]
struct Calls {
    writes_account: bool,
    names: Vec<String>,
}

fn is_data_borrow_mut(node: &ExprMethodCall) -> bool {
    node.method == "borrow_mut"
        && matches!(node.receiver.as_ref(), Expr::Field(field) if matches!(&field.member, syn::Member::Named(name) if name == "data" || name == "lamports"))
}

fn macro_identifiers(tokens: &str) -> Vec<&str> {
    tokens
        .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
        .filter(|part| !part.is_empty())
        .collect()
}

fn macro_gate_calls(tokens: &str) -> Vec<String> {
    let bytes = tokens.as_bytes();
    let mut calls = Vec::new();
    let mut cursor = 0;
    while cursor < bytes.len() {
        if !bytes[cursor].is_ascii_alphabetic() && bytes[cursor] != b'_' {
            cursor += 1;
            continue;
        }
        let start = cursor;
        cursor += 1;
        while cursor < bytes.len()
            && (bytes[cursor].is_ascii_alphanumeric() || bytes[cursor] == b'_')
        {
            cursor += 1;
        }
        let name = &tokens[start..cursor];
        if !GATES.contains(&name) {
            continue;
        }
        let previous = bytes[..start]
            .iter()
            .rev()
            .find(|byte| !byte.is_ascii_whitespace())
            .copied();
        let next = bytes[cursor..]
            .iter()
            .find(|byte| !byte.is_ascii_whitespace())
            .copied();
        // `$account` in a macro rule is a metavariable, not a call to the
        // `account` provenance helper. Only count syntactic call positions.
        if previous != Some(b'$') && matches!(next, Some(b'(' | b'!')) {
            calls.push(name.to_owned());
        }
    }
    calls
}

fn audit_macro_tokens(tokens: &str, calls: &mut Calls) {
    let identifiers = macro_identifiers(tokens);
    if identifiers.iter().any(|name| {
        matches!(
            *name,
            "try_borrow_mut_data"
                | "try_borrow_mut_lamports"
                | "realloc"
                | "assign"
                | "borrow_mut"
                | "invoke"
                | "invoke_signed"
                | "invoke_unchecked"
                | "invoke_signed_unchecked"
        )
    }) {
        calls.writes_account = true;
    }
    calls.names.extend(macro_gate_calls(tokens));
}

fn is_self_keyed(node: &ExprCall) -> bool {
    let args: Vec<_> = node.args.iter().collect();
    if args.len() < 3 {
        return false;
    }
    let Expr::Path(account) = args[0] else {
        return false;
    };
    let Expr::Field(expected) = args[2] else {
        return false;
    };
    let account_name = account
        .path
        .segments
        .last()
        .map(|segment| segment.ident.to_string());
    matches!(&expected.member, syn::Member::Named(name) if name == "key")
        && matches!(expected.base.as_ref(), Expr::Path(base) if base.path.segments.last().map(|segment| segment.ident.to_string()) == account_name)
}

impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        let name = node.method.to_string();
        if matches!(
            name.as_str(),
            "try_borrow_mut_data" | "try_borrow_mut_lamports" | "realloc" | "assign"
        ) || is_data_borrow_mut(node)
        {
            self.writes_account = true;
        }
        if GATES.contains(&name.as_str()) {
            self.names.push(name);
        }
        visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        if let Expr::Path(path) = node.func.as_ref() {
            if let Some(segment) = path.path.segments.last() {
                let name = segment.ident.to_string();
                if matches!(
                    name.as_str(),
                    "invoke" | "invoke_signed" | "invoke_unchecked" | "invoke_signed_unchecked"
                ) {
                    self.writes_account = true;
                }
                if GATES.contains(&name.as_str())
                    && (name != "expect_keyed" || !is_self_keyed(node))
                {
                    self.names.push(name);
                }
            }
        }
        visit::visit_expr_call(self, node);
    }

    fn visit_expr_macro(&mut self, node: &'ast syn::ExprMacro) {
        audit_macro_tokens(&node.mac.tokens.to_string(), self);
        visit::visit_expr_macro(self, node);
    }
}

fn collect_rust_files(dir: &Path, root: &Path, out: &mut Vec<(String, String)>) {
    let mut entries: Vec<_> = fs::read_dir(dir)
        .expect("read source directory")
        .map(|entry| entry.expect("read source entry").path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            collect_rust_files(&path, root, out);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            let relative = path
                .strip_prefix(root)
                .expect("source is under src")
                .to_string_lossy()
                .replace('\\', "/");
            out.push((
                relative,
                fs::read_to_string(path).expect("read Rust source"),
            ));
        }
    }
}

fn rust_sources() -> Vec<(String, String)> {
    let source_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut sources = Vec::new();
    collect_rust_files(&source_root, &source_root, &mut sources);
    sources
}

fn audit_functions(file: &str, source: &str) -> Vec<String> {
    let syntax = syn::parse_file(source).expect("source file parses");
    let mut failures = Vec::new();

    fn audit_block(file: &str, function: &str, block: &syn::Block, failures: &mut Vec<String>) {
        let mut calls = Calls::default();
        calls.visit_block(block);
        if !calls.writes_account
            || calls
                .names
                .iter()
                .any(|name| GATES.contains(&name.as_str()))
        {
            return;
        }
        let function_name = function.split_whitespace().last().unwrap_or(function);
        if CALLER_GATED_WRITERS
            .iter()
            .any(|(path, name)| *path == file && *name == function_name)
        {
            return;
        }
        failures.push(format!("{file}::{function}"));
    }

    struct Functions<'a> {
        file: &'a str,
        failures: &'a mut Vec<String>,
    }
    impl<'ast> Visit<'ast> for Functions<'_> {
        fn visit_item_fn(&mut self, node: &'ast ItemFn) {
            // Keep the visibility in the audit output while checking every
            // function, including private and pub(crate) helpers.
            let visibility = match &node.vis {
                syn::Visibility::Public(_) => "pub",
                syn::Visibility::Restricted(_) => "restricted",
                syn::Visibility::Inherited => "private",
            };
            audit_block(
                self.file,
                &format!("{visibility} {}", node.sig.ident),
                &node.block,
                self.failures,
            );
            visit::visit_item_fn(self, node);
        }

        fn visit_impl_item_fn(&mut self, node: &'ast ImplItemFn) {
            let visibility = match &node.vis {
                syn::Visibility::Public(_) => "pub",
                syn::Visibility::Restricted(_) => "restricted",
                syn::Visibility::Inherited => "private",
            };
            audit_block(
                self.file,
                &format!("{visibility} impl {}", node.sig.ident),
                &node.block,
                self.failures,
            );
            visit::visit_impl_item_fn(self, node);
        }

        fn visit_trait_item_fn(&mut self, node: &'ast TraitItemFn) {
            if let Some(block) = &node.default {
                audit_block(
                    self.file,
                    &format!("trait default {}", node.sig.ident),
                    block,
                    self.failures,
                );
            }
            visit::visit_trait_item_fn(self, node);
        }

        fn visit_item_macro(&mut self, node: &'ast syn::ItemMacro) {
            let mut calls = Calls::default();
            audit_macro_tokens(&node.mac.tokens.to_string(), &mut calls);
            if calls.writes_account
                && !calls
                    .names
                    .iter()
                    .any(|name| GATES.contains(&name.as_str()))
            {
                let macro_name = node
                    .ident
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_else(|| "anonymous".to_owned());
                self.failures
                    .push(format!("{}::macro {macro_name}", self.file));
            }
            visit::visit_item_macro(self, node);
        }
    }

    Functions {
        file,
        failures: &mut failures,
    }
    .visit_file(&syntax);
    failures
}

#[test]
fn source_audit_matches_the_reviewed_writer_allowlist() {
    let mut failures = Vec::new();
    let sources = rust_sources();
    assert!(
        sources.len() > 10,
        "the source inventory should be discovered recursively under src/"
    );
    for (file, source) in &sources {
        failures.extend(audit_functions(file, source));
    }
    failures.sort();
    eprintln!(
        "account provenance source audit findings (must match the reviewed allowlist):\n{}",
        failures.join("\n")
    );
    assert_eq!(
        failures.iter().map(String::as_str).collect::<Vec<_>>(),
        CURRENT_AUDIT_FINDINGS
    );
}

// This sorted snapshot is the current set of writers without an in-function
// provenance gate. Some are internal transaction steps whose role validation
// happens at the dispatcher or caller; changing this inventory still requires
// an explicit review.
const CURRENT_AUDIT_FINDINGS: &[&str] = &[
    "closure_v2_accounts.rs::pub finalize_segment",
    "closure_v2_accounts.rs::pub land_leaves",
    "closure_v2_accounts.rs::pub publish_checkpoint",
    "closure_v2_accounts.rs::restricted create",
    "closure_v2_bootstrap.rs::private init_variable",
    "closure_v2_bootstrap.rs::pub collect_root",
    "closure_v2_bootstrap.rs::pub finalize_from_roots",
    "closure_v2_bootstrap.rs::pub grow_page",
    "closure_v2_bootstrap.rs::pub grow_root_group",
    "closure_v2_bootstrap.rs::pub grow_v2",
    "closure_v2_bootstrap.rs::pub init",
    "closure_v2_bootstrap.rs::pub init_page",
    "closure_v2_bootstrap.rs::pub init_root_group",
    "closure_v2_bootstrap.rs::pub init_small",
    "closure_v2_bootstrap.rs::pub init_v4",
    "closure_v2_bootstrap.rs::pub seal_v2",
    "closure_v2_bootstrap.rs::pub upload_v2",
    "closure_v2_generic.rs::private rule_v6", // execute authenticates the v5 DCR1 and v6 DCM2 PDAs, size and kind before this helper.
    "desc_upload.rs::private store_dcd1",
    "desc_upload.rs::pub process_alloc",
    "desc_upload.rs::pub process_upload",
    "disputes_v21.rs::private advance", // dispute_ctx authenticates run, template and dispute; the ruled sequence must equal the prefix.
    "disputes_v21.rs::private cache_answer", // dispute_ctx authenticates the target; the cache is an owned, derived D21C for this node.
    "disputes_v21.rs::private change_template_run_count", // init_run and close_run authenticate the tracked D21T before changing its count.
    "disputes_v21.rs::private close_dispute", // dispute_ctx binds D21R/D21D; each staged PDA and refund recipient is checked before close.
    "disputes_v21.rs::private close_into", // callers authenticate the account and refund key before this writable close helper.
    "disputes_v21.rs::private close_run", // run_checked and template authenticate both PDAs; the payer and terminal state are checked.
    "disputes_v21.rs::private commit", // run_checked binds D21R to D21T; only its recorded executor signer can commit.
    "disputes_v21.rs::private create_pda", // exact seed/bump, empty system owner and caller-signed payer precede allocation.
    "disputes_v21.rs::private finalize", // run_checked binds D21R to D21T; deadline and recorded executor key gate payout.
    "disputes_v21.rs::private moot", // dispute_ctx binds both PDAs; best-win sequence and challenger key gate the ruling.
    "disputes_v21.rs::private move_lamports", // callers authenticate program-owned source and recorded payout recipient before transfer.
    "disputes_v21.rs::private pay_pot", // dispute_ctx binds both PDAs; best sequence, paid flag and payee keys gate payout.
    "disputes_v21.rs::private pick", // dispute_ctx binds both PDAs; recorded challenger signer and phase gate the write.
    "disputes_v21.rs::private retire_template", // template authenticates D21T; recorded payer signer and tracking shape gate retirement.
    "disputes_v21.rs::private reveal_leaf", // dispute_ctx binds both PDAs; executor signer, phase and committed leaf hash gate reveal.
    "disputes_v21.rs::private rule", // authenticated Ctx supplies both PDAs; ruling state and recorded payee keys gate writes.
    "disputes_v21.rs::private stage_grow", // dispute_ctx and staging_role bind D21D/D21S; signer-funded growth is bounded.
    "disputes_v21.rs::private stage_write", // dispute_ctx and staging_role bind D21D/D21S; role signer and bounds gate writes.
    "envelope_seal.rs::private create_pda",
    "envelope_seal.rs::pub admission_step",
    "envelope_seal.rs::pub registry_freeze",
    "envelope_seal.rs::pub registry_write",
    "graph_v2.rs::private challenge", // run_checked binds DCR2 to DCT2; proved wrong step and challenger signer gate ruling.
    "graph_v2.rs::private choose", // checked run/dispute PDAs, recorded challenger signer and phase gate the choice.
    "graph_v2.rs::private close_run", // run_checked binds DCR2 to DCT2; recorded payer signer and terminal state gate close.
    "graph_v2.rs::private commit", // run_checked binds DCR2 to DCT2; executor signer and open status gate commit.
    "graph_v2.rs::private create_pda", // exact seed/bump, empty system owner and caller-signed payer precede allocation.
    "graph_v2.rs::private execute", // run_checked binds DCR2 to DCT2; signed caller and open consensus mode gate execution.
    "graph_v2.rs::private finalize", // run_checked binds DCR2 to DCT2; deadline and recorded executor key gate payout.
    "graph_v2.rs::private open_dispute", // run_checked and dispute_checked bind DCR2/DCD2; challenger signer and phase gate opening.
    "graph_v2.rs::private reveal_leaf", // checked run/dispute PDAs, executor signer and phase gate the leaf write.
    "graph_v2.rs::private reveal_region", // checked run/dispute PDAs, executor signer and committed root gate the region write.
    "graph_v2.rs::private rule_challenger", // checked run/dispute callers bind PDAs; recorded challenger key gates ruling and bond.
    "graph_v2.rs::private rule_executor", // checked run/dispute callers bind PDAs; recorded executor key gates bond payout.
    "graph_v2.rs::private sample_audit", // run_checked binds DCR2 to DCT2; slot-hash proof gates audit and bond.
    "graph_v2.rs::private settle_descent", // checked run/dispute PDAs, deadlines and payee keys gate timeout rulings.
    "graph_v2.rs::private take_bond", // callers authenticate the run or dispute PDA and recipient before moving excess rent.
    "pt1_onchain.rs::private init_pt1x",
    "pt1_onchain.rs::private init_with_magic",
    "pt1_onchain.rs::pub init_variant",
    "pt2p_onchain.rs::pub init",
    "root_only.rs::private producer_record_binds_coordinate_in_pda",
    "root_only.rs::pub increment_slots",
    "root_only_sealed.rs::pub bind_manifest",
    "root_only_sealed.rs::pub init_sealed",
    "seal.rs::pub process_begin",
    "seal.rs::pub process_step",
    "stateful.rs::private drain_to_refund",
    "stateful.rs::private encode_session",
    "stateful_v2.rs::private drain_to_refund",
    "stateful_v2.rs::private encode_session",
    "stateful_v2.rs::private grow_child_data",
    "stateful_v3.rs::private drain_to_refund",
    "stateful_v3.rs::private encode_session",
    "stateful_v3.rs::private grow_child_data",
    "stateful_v3.rs::private grow_headerless_state",
    "stateful_v3.rs::private initialize_resource_header",
    "stateful_v3.rs::private write_anchor",
    "test_lifecycle.rs::private admit",
    "test_lifecycle.rs::private bisect",
    "test_lifecycle.rs::private challenge",
    "test_lifecycle.rs::private close",
    "test_lifecycle.rs::private create_pda",
    "test_lifecycle.rs::private finalize",
    "test_lifecycle.rs::private land_roots",
    "test_lifecycle.rs::private replay",
    "test_lifecycle.rs::private resolve",
    "test_lifecycle.rs::private settle",
    "unified/challenge.rs::private assign_settlement_escrow",
    "unified/challenge.rs::private built_in_settlement",
    "unified/challenge.rs::pub rule",
    "unified/config.rs::private close_unpublished_pt1x_pt2s",
    "unified/result.rs::private close_conviction",
    "unified/result.rs::private conviction",
    "unified/result.rs::private drain_unchecked",
];

#[test]
fn self_keyed_gates_do_not_cover_writes_and_private_impl_methods_are_audited() {
    let source = r#"
        fn self_checked(account: &AccountInfo) {
            expect_keyed(account, program, account.key, kind, role).unwrap();
            account.try_borrow_mut_data().unwrap();
        }
        pub fn public_writer(account: &AccountInfo) {
            account.try_borrow_mut_data().unwrap();
        }
        pub(crate) fn crate_writer(account: &AccountInfo) {
            account.try_borrow_mut_data().unwrap();
        }
        impl Writer {
            pub fn public_method(&self) {
                self.data.borrow_mut();
            }
            pub(crate) fn crate_method(&self) {
                self.data.borrow_mut();
            }
            fn hidden(&self) {
                self.data.borrow_mut();
            }
        }
        trait DefaultWriter {
            fn default_write(&self) {
                self.lamports.borrow_mut();
            }
        }
        macro_rules! direct_write {
            ($account:ident) => { $account.try_borrow_mut_lamports().unwrap(); };
        }
        fn macro_writer(account: &AccountInfo) {
            direct_write!(account);
        }
    "#;
    assert_eq!(
        audit_functions("fixture.rs", source),
        vec![
            "fixture.rs::private self_checked".to_string(),
            "fixture.rs::pub public_writer".to_string(),
            "fixture.rs::restricted crate_writer".to_string(),
            "fixture.rs::pub impl public_method".to_string(),
            "fixture.rs::restricted impl crate_method".to_string(),
            "fixture.rs::private impl hidden".to_string(),
            "fixture.rs::trait default default_write".to_string(),
            "fixture.rs::macro direct_write".to_string(),
        ]
    );
}

#[test]
fn gaps_remain_explicit_and_route_tags_stay_revision_scoped() {
    let spec = include_str!("../../../docs/spec/account-provenance.md");
    assert!(spec.contains("Known gaps in the `revision-8` account lists"));
    assert!(spec.contains("self-seeded"));
    assert!(spec.contains("Caller-validated readers"));
    let lib = include_str!("../src/lib.rs");
    assert!(lib.contains("process_instruction_with_manifest"));
    assert!(lib.contains("131 | 132 | 156..=169"));
    assert!(!lib.contains("7 => desc_upload::process_upload"));
}
