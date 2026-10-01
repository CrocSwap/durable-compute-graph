use syn::{
    visit::{self, Visit},
    Expr, ExprCall, ExprMethodCall, ItemFn, Visibility,
};

const SOURCES: &[(&str, &str)] = &[
    ("stateful.rs", include_str!("../src/stateful.rs")),
    ("stateful_v2.rs", include_str!("../src/stateful_v2.rs")),
    ("stateful_v3.rs", include_str!("../src/stateful_v3.rs")),
    ("pt1_onchain.rs", include_str!("../src/pt1_onchain.rs")),
    ("pt2p_onchain.rs", include_str!("../src/pt2p_onchain.rs")),
    (
        "closure_v2_response.rs",
        include_str!("../src/closure_v2_response.rs"),
    ),
    (
        "unified/document.rs",
        include_str!("../src/unified/document.rs"),
    ),
    (
        "unified/challenge.rs",
        include_str!("../src/unified/challenge.rs"),
    ),
    (
        "unified/result.rs",
        include_str!("../src/unified/result.rs"),
    ),
    ("unified/bond.rs", include_str!("../src/unified/bond.rs")),
    (
        "unified/registry.rs",
        include_str!("../src/unified/registry.rs"),
    ),
    (
        "unified/config.rs",
        include_str!("../src/unified/config.rs"),
    ),
    (
        "unified/admission.rs",
        include_str!("../src/unified/admission.rs"),
    ),
];

// A mutation handler may call one of these shared gates directly. The list is
// intentionally explicit: adding a different wrapper requires reviewing and
// documenting its account identity source here.
const GATES: &[&str] = &[
    "expect_derived",
    "expect_keyed",
    "expect_system_derived",
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
    "positions",
    "positions_with_bump",
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
    "sealed_view",
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

// Existing account lists with no independent source are allowed only while
// their gap remains named in docs/spec/account-provenance.md.
const KNOWN_GAPS: &[(&str, &str)] = &[
    ("stateful.rs", "checked_session"),
    ("stateful_v2.rs", "checked_session"),
    ("stateful_v3.rs", "checked_session"),
    ("stateful_v3.rs", "process_with_kernel"),
    ("pt1_onchain.rs", "upload"),
    ("pt1_onchain.rs", "seal"),
    ("pt1_onchain.rs", "init_variant"),
    ("pt1_onchain.rs", "instantiate"),
    ("pt2p_onchain.rs", "hash"),
    ("pt2p_onchain.rs", "seal"),
];

#[derive(Default)]
struct Calls {
    writes_account: bool,
    names: Vec<String>,
}

impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        let name = node.method.to_string();
        if matches!(
            name.as_str(),
            "try_borrow_mut_data" | "try_borrow_mut_lamports" | "realloc" | "assign"
        ) {
            self.writes_account = true;
        }
        self.names.push(name);
        visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        if let Expr::Path(path) = node.func.as_ref() {
            if let Some(segment) = path.path.segments.last() {
                let name = segment.ident.to_string();
                if matches!(name.as_str(), "invoke" | "invoke_signed") {
                    self.writes_account = true;
                }
                self.names.push(name);
            }
        }
        visit::visit_expr_call(self, node);
    }
}

fn audit_public_functions(file: &str, source: &str) -> Vec<String> {
    let syntax = syn::parse_file(source).expect("source file parses");
    let mut failures = Vec::new();
    struct Functions<'a> {
        file: &'a str,
        failures: &'a mut Vec<String>,
    }
    impl<'ast> Visit<'ast> for Functions<'_> {
        fn visit_item_fn(&mut self, node: &'ast ItemFn) {
            if !matches!(&node.vis, Visibility::Public(_)) {
                return;
            }
            let mut calls = Calls::default();
            calls.visit_block(&node.block);
            if !calls.writes_account {
                return;
            }
            let function = node.sig.ident.to_string();
            let has_gate = calls
                .names
                .iter()
                .any(|name| GATES.contains(&name.as_str()));
            let recorded_gap = KNOWN_GAPS.contains(&(self.file, function.as_str()));
            if !has_gate && !recorded_gap {
                self.failures.push(format!("{}::{}", self.file, function));
            }
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
fn every_public_mutating_handler_uses_a_shared_gate_or_a_documented_gap() {
    let mut failures = Vec::new();
    for (file, source) in SOURCES {
        failures.extend(audit_public_functions(file, source));
    }
    assert!(
        failures.is_empty(),
        "public account writers bypass address provenance gates: {failures:#?}"
    );
}

#[test]
fn gaps_remain_explicit_and_route_tags_stay_revision_scoped() {
    let spec = include_str!("../../../docs/spec/account-provenance.md");
    assert!(spec.contains("Known gaps in the `revision-8` account lists"));
    assert!(spec.contains("self-seeded"));
    let lib = include_str!("../src/lib.rs");
    assert!(lib.contains("process_instruction_with_manifest"));
    assert!(lib.contains("131 | 132 | 156..=169"));
    assert!(!lib.contains("7 => desc_upload::process_upload"));
}
