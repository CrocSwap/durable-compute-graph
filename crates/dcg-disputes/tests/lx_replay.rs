//! The LX1 terminal replay and OUTPUT claim, driven through the machine trait
//! by a Rust port of the Python toy machine (`python/dcg/disputes_v21/lx_toy.py`),
//! reproduce the rulings of played Python disputes.

use dcg_disputes::lx::{locate, output_claim, replay, KernelFailure, LxMachine, LxRefusal, LxRuling, Outputs, Scratch, Write};
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
    fn apply(&self, p: u64, i: u64, r: &[Option<&[u8]>], out: &mut Outputs) -> Result<(), KernelFailure> {
        let nw = self.windows(p);
        if i == 0 {
            let v = (3 * dec(r[0]).ok_or(KernelFailure)? + p as i64 + 1).rem_euclid(MOD);
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
    Toy { p: t["positions"].as_u64().unwrap(), w: t["window"].as_u64().unwrap(), fail_finish: false }
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
    let view: Vec<(u32, Option<&[u8]>)> = opened.iter().map(|(s, v)| (*s, v.as_deref())).collect();
    let (mut reads, mut writes) = ([0u32; 16], [0u32; 8]);
    let mut nodes = [(0u64, [0u8; 32]); 32];
    let mut read_values: [Option<&[u8]>; 16] = [None; 16];
    let mut effects = [Write::Keep; 8];
    let mut out = [0u8; 256];
    let mut s = Scratch {
        reads: &mut reads,
        writes: &mut writes,
        nodes: &mut nodes,
        read_values: &mut read_values,
        write_effects: &mut effects,
        out: &mut out,
    };
    replay(&Soft, m, c.coordinate, &view, siblings, &c.lo, &c.hi, &mut s)
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
    fn apply(&self, _p: u64, _i: u64, _r: &[Option<&[u8]>], _o: &mut Outputs) -> Result<(), KernelFailure> { Ok(()) }
}

#[test]
fn a_transition_that_touches_no_slot_is_the_identity() {
    let (mut reads, mut writes) = ([0u32; 4], [0u32; 4]);
    let mut nodes = [(0u64, [0u8; 32]); 4];
    let mut rv: [Option<&[u8]>; 4] = [None; 4];
    let mut fx = [Write::Keep; 4];
    let mut out = [0u8; 8];
    let mut s = Scratch { reads: &mut reads, writes: &mut writes, nodes: &mut nodes, read_values: &mut rv, write_effects: &mut fx, out: &mut out };
    let (a, b) = ([1u8; 32], [2u8; 32]);
    assert_eq!(replay(&Soft, &Empty, 0, &[], &[], &a, &a, &mut s), Ok(LxRuling::Executor));
    assert_eq!(replay(&Soft, &Empty, 0, &[], &[], &a, &b, &mut s), Ok(LxRuling::Challenger));
    assert_eq!(replay(&Soft, &Empty, 0, &[], &[[0; 32]], &a, &a, &mut s), Err(LxRefusal::Proof));
}
