//! The LX1 terminal replay and OUTPUT claim, driven through the machine trait
//! by a Rust port of the Python toy machine (`python/dcg/disputes_v21/lx_toy.py`),
//! reproduce the rulings of played Python disputes.

use dcg_disputes::lx::{
    const_leaf, locate, output_claim, replay, ConstOpening, KernelFailure, LxMachine, LxRefusal, LxRuling, Outputs, Scratch, Write,
};
use dcg_disputes::{Hash, Sha256};
use sha2::Digest;

struct Soft;
impl Sha256 for Soft {
    fn hash(&self, parts: &[&[u8]]) -> Hash {
        let mut h = sha2::Sha256::new();
        for p in parts {
            h.update(p);
        }
        h.finalize().into()
    }
}

const MOD: i64 = 1 << 31;

/// The Python toy machine: slots H, log[0..P), A, M, S; per position a start,
/// windows of max then sum over the earlier log, and a finish.
struct Toy {
    p: u64,
    w: u64,
    fail_finish: bool,
    /// The Python toy's `weights=True`: each start reads chunk `p mod 4` of
    /// constant 0 and chunk `p mod 3` of constant 2 (design §13).
    weights: bool,
}

impl Toy {
    fn a(&self) -> u32 {
        1 + self.p as u32
    }
    fn windows(&self, p: u64) -> u64 {
        p.div_ceil(self.w)
    }
    /// Σ_{t<m} floor(t / W).
    fn floor_sum(&self, m: u64) -> u64 {
        let k = m / self.w;
        self.w * k * k.saturating_sub(1) / 2 + k * (m - k * self.w)
    }
    fn logs(&self, p: u64, w: u64, out: &mut [u32], from: usize) -> usize {
        let (lo, hi) = (w * self.w, (p).min((w + 1) * self.w));
        for (n, j) in (lo..hi).enumerate() {
            out[from + n] = 1 + j as u32;
        }
        from + (hi - lo) as usize
    }
}

fn dec(v: Option<&[u8]>) -> Option<i64> {
    v.map(|b| i64::from_le_bytes(b.try_into().unwrap()))
}

impl LxMachine for Toy {
    fn positions(&self) -> u64 {
        self.p
    }
    fn height(&self) -> u16 {
        let n = self.a() as u64 + 3;
        (64 - (n - 1).leading_zeros()) as u16
    }
    fn transitions_in(&self, p: u64) -> u64 {
        2 + 2 * self.windows(p)
    }
    fn position_start(&self, p: u64) -> u64 {
        // Σ_{q<p} (2 + 2·ceil(q/W)) = 2p + 2·Σ_{t<p+W-1} floor(t/W).
        2 * p + 2 * self.floor_sum(p + self.w - 1)
    }
    fn slots(&self, p: u64, i: u64, r: &mut [u32], w: &mut [u32]) -> Option<(usize, usize)> {
        let (h, a) = (0u32, self.a());
        let (m, s) = (a + 1, a + 2);
        let nw = self.windows(p);
        if r.len() < 4 + self.w as usize || w.len() < 5 {
            return None;
        }
        Some(if i == 0 {
            r[0] = h;
            w[0] = a;
            (1, 1)
        } else if i <= nw {
            r[0] = m;
            w[0] = m;
            (self.logs(p, i - 1, r, 1), 1)
        } else if i <= 2 * nw {
            r[0] = m;
            r[1] = s;
            w[0] = s;
            (self.logs(p, i - 1 - nw, r, 2), 1)
        } else if i == 2 * nw + 1 {
            r[..4].copy_from_slice(&[h, a, m, s]);
            w[..5].copy_from_slice(&[h, 1 + p as u32, a, m, s]);
            (4, 5)
        } else {
            return None;
        })
    }
    fn constants(&self, p: u64, i: u64, _reads: &[Option<&[u8]>], out: &mut [(u32, u64)]) -> Option<usize> {
        if !self.weights || i != 0 {
            return Some(0);
        }
        out.get_mut(..2)?.copy_from_slice(&[(0, p % 4), (2, p % 3)]);
        Some(2)
    }
    fn apply(&self, p: u64, i: u64, r: &[Option<&[u8]>], c: &[&[u8]], out: &mut Outputs) -> Result<(), KernelFailure> {
        let nw = self.windows(p);
        if i == 0 {
            let w = if self.weights { dec(Some(&c[0][..8])).unwrap() - dec(Some(&c[1][..8])).unwrap() } else { 0 };
            let v = (3 * dec(r[0]).ok_or(KernelFailure)? + p as i64 + 1 + w).rem_euclid(MOD);
            return out.set(0, &v.to_le_bytes());
        }
        if i <= nw {
            let mut m = dec(r[0]);
            for v in &r[1..] {
                let v = dec(*v).ok_or(KernelFailure)?;
                m = Some(m.map_or(v, |m| m.max(v)));
            }
            return out.set(0, &m.ok_or(KernelFailure)?.to_le_bytes());
        }
        if i <= 2 * nw {
            let m = dec(r[0]).ok_or(KernelFailure)?;
            let mut acc = dec(r[1]).unwrap_or(0);
            for v in &r[2..] {
                acc += m - dec(*v).ok_or(KernelFailure)?;
            }
            return out.set(0, &acc.to_le_bytes());
        }
        if self.fail_finish {
            return Err(KernelFailure);
        }
        let a = dec(r[1]).ok_or(KernelFailure)?;
        let (m, s) = (dec(r[2]).unwrap_or(0), dec(r[3]).unwrap_or(0));
        let h = (a + s - m).rem_euclid(MOD).to_le_bytes();
        out.set(0, &h)?;
        out.set(1, &h)?;
        out.clear(2)?;
        out.clear(3)?;
        out.clear(4)
    }
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn h32(s: &serde_json::Value) -> Hash {
    hex(s.as_str().unwrap()).try_into().unwrap()
}

fn golden() -> serde_json::Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/golden/dcg/disputes_v21/lx.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn toy(g: &serde_json::Value) -> Toy {
    let t = &g["toy"];
    Toy { p: t["positions"].as_u64().unwrap(), w: t["window"].as_u64().unwrap(), fail_finish: false, weights: false }
}

struct Case {
    coordinate: u64,
    opened: Vec<(u32, Option<Vec<u8>>)>,
    siblings: Vec<Hash>,
    lo: Hash,
    hi: Hash,
    ruling: LxRuling,
}

fn cases(g: &serde_json::Value) -> Vec<Case> {
    g["replays"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| Case {
            coordinate: r["coordinate"].as_u64().unwrap(),
            opened: r["opened"]
                .as_array()
                .unwrap()
                .iter()
                .map(|e| (e[0].as_u64().unwrap() as u32, e[1].as_str().map(hex)))
                .collect(),
            siblings: r["siblings"].as_array().unwrap().iter().map(h32).collect(),
            lo: h32(&r["root_lo"]),
            hi: h32(&r["root_hi"]),
            ruling: if r["ruling"] == "E" { LxRuling::Executor } else { LxRuling::Challenger },
        })
        .collect()
}

fn run(m: &Toy, c: &Case, opened: &[(u32, Option<Vec<u8>>)], siblings: &[Hash]) -> Result<LxRuling, LxRefusal> {
    run_c(m, c, opened, siblings, &[], &[0; 32])
}

fn run_c(
    m: &Toy,
    c: &Case,
    opened: &[(u32, Option<Vec<u8>>)],
    siblings: &[Hash],
    consts: &[ConstOpening],
    constants_root: &Hash,
) -> Result<LxRuling, LxRefusal> {
    let view: Vec<(u32, Option<&[u8]>)> = opened.iter().map(|(s, v)| (*s, v.as_deref())).collect();
    let (mut reads, mut writes) = ([0u32; 16], [0u32; 8]);
    let mut nodes = [(0u64, [0u8; 32]); 32];
    let mut read_values: [Option<&[u8]>; 16] = [None; 16];
    let mut effects = [Write::Keep; 8];
    let mut out = [0u8; 256];
    let mut const_reads = [(0u32, 0u64); 4];
    let mut const_values: [&[u8]; 4] = [&[]; 4];
    let mut s = Scratch {
        reads: &mut reads,
        writes: &mut writes,
        nodes: &mut nodes,
        read_values: &mut read_values,
        write_effects: &mut effects,
        out: &mut out,
        const_reads: &mut const_reads,
        const_values: &mut const_values,
    };
    replay(&Soft, m, c.coordinate, &view, siblings, consts, constants_root, &c.lo, &c.hi, &mut s)
}

#[test]
fn coordinates_locate_like_the_python_schedule() {
    let g = golden();
    let m = toy(&g);
    let total = g["toy"]["total"].as_u64().unwrap();
    assert_eq!(m.position_start(m.positions()), total);
    let mut c = 0;
    for p in 0..m.positions() {
        assert_eq!(m.position_start(p), c, "position {p}");
        for i in 0..m.transitions_in(p) {
            assert_eq!(locate(&m, c), Some((p, i)));
            c += 1;
        }
    }
    assert_eq!(locate(&m, total), None);
    assert_eq!(m.height(), g["toy"]["height"].as_u64().unwrap() as u16);
}

#[test]
fn terminal_replays_rule_like_python() {
    let g = golden();
    let m = toy(&g);
    let cs = cases(&g);
    assert!(cs.len() >= 10);
    assert!(cs.iter().any(|c| c.ruling == LxRuling::Executor) && cs.iter().any(|c| c.ruling == LxRuling::Challenger));
    for c in &cs {
        assert_eq!(run(&m, c, &c.opened, &c.siblings), Ok(c.ruling), "coordinate {}", c.coordinate);
    }
}

#[test]
fn malformed_openings_are_refused_not_ruled() {
    let g = golden();
    let m = toy(&g);
    for c in cases(&g) {
        // A changed value does not rebuild the lower root.
        let mut bad = c.opened.clone();
        let k = bad.iter().position(|(_, v)| v.is_some()).unwrap();
        bad[k].1.as_mut().unwrap()[0] ^= 1;
        assert_eq!(run(&m, &c, &bad, &c.siblings), Err(LxRefusal::Proof));
        // A missing slot, an extra slot, or unsorted slots do not cover the transition.
        assert_eq!(run(&m, &c, &c.opened[1..], &c.siblings), Err(LxRefusal::Coverage));
        let mut extra = c.opened.clone();
        extra.push((m.a() + 3, None));
        assert!(run(&m, &c, &extra, &c.siblings).is_err());
        let mut swapped = c.opened.clone();
        swapped.swap(0, 1);
        assert_eq!(run(&m, &c, &swapped, &c.siblings), Err(LxRefusal::Coverage));
        // A missing sibling is refused.
        assert_eq!(run(&m, &c, &c.opened, &c.siblings[1..]), Err(LxRefusal::Proof));
        // Outside the schedule.
        let far = Case { coordinate: m.position_start(m.positions()), ..c };
        assert_eq!(run(&m, &far, &far.opened, &far.siblings), Err(LxRefusal::Coordinate));
    }
}

#[test]
fn a_kernel_failure_on_a_verified_opening_rules_for_the_challenger() {
    let g = golden();
    let m = Toy { fail_finish: true, ..toy(&g) };
    for c in cases(&g) {
        // Every golden replay lands on a finish transition.
        assert_eq!(run(&m, &c, &c.opened, &c.siblings), Ok(LxRuling::Challenger));
    }
}

#[test]
fn output_claims_rule_like_python() {
    let g = golden();
    let m = toy(&g);
    for o in g["outputs"].as_array().unwrap() {
        let slots: Vec<u32> = o["output_slots"].as_array().unwrap().iter().map(|v| v.as_u64().unwrap() as u32).collect();
        let opened: Vec<(u32, Option<Vec<u8>>)> =
            o["opened"].as_array().unwrap().iter().map(|e| (e[0].as_u64().unwrap() as u32, e[1].as_str().map(hex))).collect();
        let view: Vec<(u32, Option<&[u8]>)> = opened.iter().map(|(s, v)| (*s, v.as_deref())).collect();
        let claimed: Vec<Option<Vec<u8>>> = o["claimed"].as_array().unwrap().iter().map(|v| v.as_str().map(hex)).collect();
        let claimed: Vec<Option<&[u8]>> = claimed.iter().map(|v| v.as_deref()).collect();
        let sib: Vec<Hash> = o["siblings"].as_array().unwrap().iter().map(h32).collect();
        let want = if o["ruling"] == "E" { LxRuling::Executor } else { LxRuling::Challenger };
        let mut nodes = [(0u64, [0u8; 32]); 8];
        assert_eq!(output_claim(&Soft, m.height(), &slots, &view, &sib, &h32(&o["root_t"]), &claimed, &mut nodes), Ok(want));
        let wrong_root = [0u8; 32];
        assert_eq!(output_claim(&Soft, m.height(), &slots, &view, &sib, &wrong_root, &claimed, &mut nodes), Err(LxRefusal::Proof));
    }
}

/// A machine whose only transition touches no slot (LX1 program review M1).
struct Empty;
impl LxMachine for Empty {
    fn positions(&self) -> u64 { 1 }
    fn height(&self) -> u16 { 2 }
    fn transitions_in(&self, _p: u64) -> u64 { 1 }
    fn position_start(&self, p: u64) -> u64 { p }
    fn slots(&self, _p: u64, _i: u64, _r: &mut [u32], _w: &mut [u32]) -> Option<(usize, usize)> { Some((0, 0)) }
    fn apply(&self, _p: u64, _i: u64, _r: &[Option<&[u8]>], _c: &[&[u8]], _o: &mut Outputs) -> Result<(), KernelFailure> { Ok(()) }
}

#[test]
fn a_transition_that_touches_no_slot_is_the_identity() {
    let (mut reads, mut writes) = ([0u32; 4], [0u32; 4]);
    let mut nodes = [(0u64, [0u8; 32]); 4];
    let mut rv: [Option<&[u8]>; 4] = [None; 4];
    let mut fx = [Write::Keep; 4];
    let mut out = [0u8; 8];
    let (mut cr, mut cv) = ([(0u32, 0u64); 1], [&[][..]; 1]);
    let mut s = Scratch {
        reads: &mut reads,
        writes: &mut writes,
        nodes: &mut nodes,
        read_values: &mut rv,
        write_effects: &mut fx,
        out: &mut out,
        const_reads: &mut cr,
        const_values: &mut cv,
    };
    let (a, b, z) = ([1u8; 32], [2u8; 32], [0u8; 32]);
    assert_eq!(replay(&Soft, &Empty, 0, &[], &[], &[], &z, &a, &a, &mut s), Ok(LxRuling::Executor));
    assert_eq!(replay(&Soft, &Empty, 0, &[], &[], &[], &z, &a, &b, &mut s), Ok(LxRuling::Challenger));
    assert_eq!(replay(&Soft, &Empty, 0, &[], &[[0; 32]], &[], &z, &a, &a, &mut s), Err(LxRefusal::Proof));
    // An undeclared constant entry is refused.
    let e = ConstOpening { chunk: &[], chunk_path: &[], digest: z, const_path: &[] };
    assert_eq!(replay(&Soft, &Empty, 0, &[], &[], &[e], &z, &a, &a, &mut s), Err(LxRefusal::Constant));
}

// --- constants in openings (design §13) ---------------------------------------------------

struct Weighted {
    case: Case,
    reads: Vec<(u32, u64)>,
    chunks: Vec<Vec<u8>>,
    chunk_paths: Vec<Vec<u8>>,
    digests: Vec<Hash>,
    const_paths: Vec<Vec<u8>>,
}

impl Weighted {
    fn openings(&self) -> Vec<ConstOpening<'_>> {
        (0..self.chunks.len())
            .map(|k| ConstOpening {
                chunk: &self.chunks[k],
                chunk_path: &self.chunk_paths[k],
                digest: self.digests[k],
                const_path: &self.const_paths[k],
            })
            .collect()
    }
}

fn weighted(g: &serde_json::Value) -> (Toy, Hash, Vec<Weighted>) {
    let w = &g["weighted"];
    let hashes = |v: &serde_json::Value| -> Vec<Hash> { v.as_array().unwrap().iter().map(h32).collect() };
    let cases = w["replays"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            let cs = r["constants"].as_array().unwrap();
            Weighted {
                case: Case {
                    coordinate: r["coordinate"].as_u64().unwrap(),
                    opened: r["opened"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|e| (e[0].as_u64().unwrap() as u32, e[1].as_str().map(hex)))
                        .collect(),
                    siblings: hashes(&r["siblings"]),
                    lo: h32(&r["root_lo"]),
                    hi: h32(&r["root_hi"]),
                    ruling: if r["ruling"] == "E" { LxRuling::Executor } else { LxRuling::Challenger },
                },
                reads: r["const_reads"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|x| (x[0].as_u64().unwrap() as u32, x[1].as_u64().unwrap()))
                    .collect(),
                chunks: cs.iter().map(|e| hex(e["chunk"].as_str().unwrap())).collect(),
                chunk_paths: cs.iter().map(|e| hashes(&e["chunk_path"]).concat()).collect(),
                digests: cs.iter().map(|e| h32(&e["digest"])).collect(),
                const_paths: cs.iter().map(|e| hashes(&e["const_path"]).concat()).collect(),
            }
        })
        .collect();
    (Toy { weights: true, ..toy(g) }, h32(&w["constants_root"]), cases)
}

#[test]
fn weighted_replays_rule_like_python() {
    let g = golden();
    let (m, root, cases) = weighted(&g);
    assert!(cases.iter().any(|c| c.case.ruling == LxRuling::Executor) && cases.iter().any(|c| c.case.ruling == LxRuling::Challenger));
    for w in &cases {
        let (p, i) = locate(&m, w.case.coordinate).unwrap();
        let mut reads = [(0u32, 0u64); 4];
        let n = m.constants(p, i, &[], &mut reads).unwrap();
        assert_eq!(&reads[..n], &w.reads[..], "declared reads match Python");
        for (k, (cid, _)) in w.reads.iter().enumerate() {
            let digest = g["weighted"]["digests"][cid.to_string()].as_str().unwrap();
            assert_eq!(w.digests[k], h32(&serde_json::Value::from(digest)));
            let path: Vec<Hash> = w.const_paths[k].chunks(32).map(|c| c.try_into().unwrap()).collect();
            assert_eq!(dcg_disputes::root_from_path(&Soft, dcg_disputes::Tree::LxConst, &const_leaf(&Soft, *cid, &w.digests[k]), *cid as u64, &path), root);
        }
        let c = &w.case;
        assert_eq!(run_c(&m, c, &c.opened, &c.siblings, &w.openings(), &root), Ok(c.ruling), "coordinate {}", c.coordinate);
    }
}

#[test]
fn wrong_missing_or_reordered_constants_are_refused() {
    let g = golden();
    let (m, root, cases) = weighted(&g);
    for w in &cases {
        let c = &w.case;
        let good = w.openings();
        let refuse = |consts: &[ConstOpening]| assert_eq!(run_c(&m, c, &c.opened, &c.siblings, consts, &root), Err(LxRefusal::Constant));
        // A changed chunk byte.
        let mut chunk = w.chunks[0].clone();
        chunk[0] ^= 1;
        refuse(&[ConstOpening { chunk: &chunk, ..good[0] }, good[1]]);
        // A wrong chunk path, a wrong digest, a wrong or overlong constant path.
        let mut cp = w.chunk_paths[0].clone();
        cp[0] ^= 1;
        refuse(&[ConstOpening { chunk_path: &cp, ..good[0] }, good[1]]);
        refuse(&[ConstOpening { digest: [7; 32], ..good[0] }, good[1]]);
        let mut kp = w.const_paths[1].clone();
        kp[0] ^= 1;
        refuse(&[good[0], ConstOpening { const_path: &kp, ..good[1] }]);
        let mut long = w.const_paths[1].clone();
        long.extend_from_slice(&[0; 32]);
        refuse(&[good[0], ConstOpening { const_path: &long, ..good[1] }]);
        // A path that is not whole hashes.
        let ragged = &w.const_paths[1][..w.const_paths[1].len() - 1];
        refuse(&[good[0], ConstOpening { const_path: ragged, ..good[1] }]);
        // Too short to hold the chunk index or the constant id.
        if w.reads[0].1 > 0 {
            refuse(&[ConstOpening { chunk_path: &[], ..good[0] }, good[1]]);
        }
        refuse(&[good[0], ConstOpening { const_path: &[], ..good[1] }]);
        // Missing, extra and swapped.
        refuse(&good[..1]);
        refuse(&[good[0], good[1], good[1]]);
        refuse(&[good[1], good[0]]);
        refuse(&[]);
        // Against another constants root.
        assert_eq!(run_c(&m, c, &c.opened, &c.siblings, &good, &[0; 32]), Err(LxRefusal::Constant));
        // Still accepted afterwards (refusals change nothing).
        assert_eq!(run_c(&m, c, &c.opened, &c.siblings, &good, &root), Ok(c.ruling));
    }
}

#[test]
fn unweighted_transitions_refuse_constant_entries() {
    let g = golden();
    let m = toy(&g);
    let (_, root, wc) = weighted(&g);
    let e = wc[0].openings();
    for c in cases(&g) {
        assert_eq!(run_c(&m, &c, &c.opened, &c.siblings, &e[..1], &root), Err(LxRefusal::Constant));
    }
}
