use std::{
    fs,
    path::{Path, PathBuf},
};
use syn::{
    visit::{self, Visit},
    Expr, ExprCall, ExprMethodCall, ImplItemFn, ItemFn,
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
        && matches!(node.receiver.as_ref(), Expr::Field(field) if matches!(&field.member, syn::Member::Named(name) if name == "data"))
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
    }

    Functions {
        file,
        failures: &mut failures,
    }
    .visit_file(&syntax);
    failures
}

#[test]
fn source_audit_reports_direct_writers_without_enforcing_them() {
    let mut failures = Vec::new();
    let sources = rust_sources();
    assert!(
        sources.len() > 10,
        "the source inventory should be discovered recursively under src/"
    );
    for (file, source) in &sources {
        failures.extend(audit_functions(file, source));
    }
    assert!(failures.contains(&"account_provenance.rs::pub create_derived_account".to_owned()));
    assert!(failures.contains(&"stateful_v3.rs::private encode_session".to_owned()));
    assert!(failures.contains(&"closure_v2_accounts.rs::restricted create".to_owned()));
    eprintln!(
        "account provenance source audit findings (report only; not enforcement):\n{}",
        failures.join("\n")
    );
}

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
