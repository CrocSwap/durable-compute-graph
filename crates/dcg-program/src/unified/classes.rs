//! Class admission (ESL2, spec §3): instance shapes over a PT2P plan, the
//! canonical class list, closed-form representatives and class shapes.
//!
//! Everything here is a pure function of the PT2P view (base triple, `PWR1`,
//! the PT1S payload index) and the sealed position count `P`; it never looks
//! at an executor claim. The class walk (DEA2, tag 160) and the per-instance
//! backstop at a fix-point (§3.5) share these functions, so the backstop is
//! evaluated with exactly the shape rule the walk admitted.
//!
//! Class order (§3.3): base entries `0..B`; then per layer, form 40..46
//! ascending, form 44 non-final then final, `h0` ascending over the form's
//! head starts; then one summary class per DFS2 family (not in DEA2).

use super::registry::{Shape, EXP_LUT_BYTES, FORM_RS1_SUMMARY};
use super::PLAN_BINDING;
use crate::pt2p::{self, Item, Levels, Pt2p};

pub fn no_plan(_: u32) -> u32 {
    PLAN_BINDING
}

fn form48_class_read_bytes(routes: &[u8], read_count: u16) -> Result<u64, u32> {
    let (_, _, pxr) =
        crate::position_template::route_header_v4_shallow(routes).map_err(|_| PLAN_BINDING)?;
    let pxr = pxr.ok_or(PLAN_BINDING)?;
    let mut largest_row = 0u32;
    for i in 0..pxr.row_count {
        largest_row = largest_row.max(pxr.row(i).map_err(|_| PLAN_BINDING)?.byte_length);
    }
    form48_read_bytes(read_count, largest_row)
}

fn form48_read_bytes(read_count: u16, largest_row: u32) -> Result<u64, u32> {
    (read_count as u64)
        .checked_mul(largest_row as u64)
        .ok_or(PLAN_BINDING)
}

/// `H = ceil(log2 P)`, 0 for `P = 1` (clause-12 v2 `range_tree_height`).
pub fn rs1_height(position_count: u32) -> u8 {
    if position_count <= 1 {
        0
    } else {
        (32 - (position_count - 1).leading_zeros()) as u8
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ClassKey {
    Base(u32),
    Gen {
        layer: u32,
        form: u16,
        h0: u64,
        fin: bool,
    },
}

/// Generated classes per layer: `G = h/sg + 2h/smg + 5h`.
pub fn generated_per_layer(x: &Pt2p<'_>) -> u64 {
    let g = &x.g;
    g.heads / g.score_heads + 2 * (g.heads / g.softmax_heads) + 5 * g.heads
}

/// `B + L·G`: the classes DEA2 records (summary classes excluded).
pub fn class_count(x: &Pt2p<'_>) -> Result<u32, u32> {
    let total = (x.layer_count() as u64)
        .checked_mul(generated_per_layer(x))
        .and_then(|g| g.checked_add(x.base_entries as u64))
        .ok_or(PLAN_BINDING)?;
    u32::try_from(total).map_err(|_| PLAN_BINDING)
}

/// The class at canonical index `i < B + L·G`.
pub fn key_of(x: &Pt2p<'_>, i: u32) -> Result<ClassKey, u32> {
    if i < x.base_entries {
        return Ok(ClassKey::Base(i));
    }
    let g = &x.g;
    let per = generated_per_layer(x);
    let j = (i - x.base_entries) as u64;
    let layer = j / per;
    if layer >= x.layer_count() as u64 {
        return Err(PLAN_BINDING);
    }
    let mut r = j % per;
    let groups: [(u16, u64, bool); 8] = [
        (pt2p::FORM_27W, g.score_heads, false),
        (pt2p::FORM_28E, g.softmax_heads, false),
        (pt2p::FORM_28N, g.softmax_heads, false),
        (pt2p::FORM_29W, 1, false),
        (pt2p::FORM_29C, 1, false),
        (pt2p::FORM_29C, 1, true),
        (pt2p::FORM_28M, 1, false),
        (pt2p::FORM_28S, 1, false),
    ];
    for (form, step, fin) in groups {
        let n = g.heads / step;
        if r < n {
            return Ok(ClassKey::Gen {
                layer: layer as u32,
                form,
                h0: r * step,
                fin,
            });
        }
        r -= n;
    }
    Err(PLAN_BINDING)
}

/// Final-node child count `F(n)` of the combine tree over `n` leaves.
fn fin_reads(n: u64, fanin: u64) -> Result<u64, u32> {
    let comb = Levels::of(n, fanin, true)?;
    Ok(if comb.len == 1 {
        n
    } else {
        comb.get(comb.len - 2)
    })
}

/// `(p_r, t_r)` of a class, or `None` for an empty class (§3.3 table).
pub fn representative(x: &Pt2p<'_>, key: ClassKey) -> Result<Option<(u32, u32)>, u32> {
    let p_count = x.position_count;
    let ws = x.g.window_start;
    let last = p_count.checked_sub(1).ok_or(PLAN_BINDING)?;
    match key {
        ClassKey::Base(o) => {
            if x.is_replaced(o) {
                let m = p_count.min(ws);
                return Ok(if m == 0 { None } else { Some((m - 1, o)) });
            }
            let t = x.old_to_new(o, last)?.ok_or(PLAN_BINDING)?;
            Ok(Some((last, t)))
        }
        ClassKey::Gen {
            layer,
            form,
            h0,
            fin,
        } => {
            if last < ws {
                return Ok(None);
            }
            // Spec §12's deliberately weakened rule (test images only): the
            // representative at the first generated position, which L1's
            // domination check must catch at a later fix-point.
            let last = if cfg!(feature = "test-weakened-class-rule") {
                ws
            } else {
                last
            };
            let shape = x.shape(last)?.ok_or(PLAN_BINDING)?;
            let t = match form {
                pt2p::FORM_27W | pt2p::FORM_28E | pt2p::FORM_28N | pt2p::FORM_29W => {
                    x.form_index(&shape, layer, form, h0, 0, 0, 0)?
                }
                pt2p::FORM_28M | pt2p::FORM_28S => {
                    if shape.red.len == 0 {
                        return Ok(None);
                    }
                    x.form_index(&shape, layer, form, h0, 0, 0, 0)?
                }
                pt2p::FORM_29C if !fin => {
                    if shape.comb.len < 2 {
                        return Ok(None);
                    }
                    x.form_index(&shape, layer, form, h0, 0, 0, 0)?
                }
                pt2p::FORM_29C => {
                    let (lo, hi) = (x.n_of(ws), x.n_of(last));
                    let (mut best, mut best_reads) = (lo, fin_reads(lo, x.g.fanin)?);
                    for n in lo + 1..=hi {
                        let reads = fin_reads(n, x.g.fanin)?;
                        if reads > best_reads {
                            best = n;
                            best_reads = reads;
                        }
                    }
                    let p =
                        (ws as u64).max((best - 1).checked_mul(x.g.window).ok_or(PLAN_BINDING)?);
                    let p = u32::try_from(p).map_err(|_| PLAN_BINDING)?;
                    let s = x.shape(p)?.ok_or(PLAN_BINDING)?;
                    let t = x.form_index(&s, layer, form, h0, 0, (s.comb.len - 1) as u64, 0)?;
                    return Ok(Some((p, u32::try_from(t).map_err(|_| PLAN_BINDING)?)));
                }
                _ => return Err(PLAN_BINDING),
            };
            Ok(Some((last, u32::try_from(t).map_err(|_| PLAN_BINDING)?)))
        }
    }
}

/// Instance shape of surviving base entry `o` at `p` (§3.1): clause-5 route
/// records with T-scaled and class-3 range lengths instantiated at `p`.
pub fn base_shape(x: &Pt2p<'_>, o: u32, p: u32, h: u8) -> Result<Shape, u32> {
    let e = x.base_entry_record(o)?;
    let c = &x.c;
    let span = p as u64 + 1;
    let (mut read_bytes, mut write_bytes, mut slots) = (0u64, 0u64, 0u64);
    let (mut asserted, mut ranged) = (false, false);
    let mut c3 = 0u32;
    let add = |a: u64, b: u64| a.checked_add(b).ok_or(PLAN_BINDING);
    let mul = |a: u64, b: u64| a.checked_mul(b).ok_or(PLAN_BINDING);
    for k in 0..e.read_count {
        let r = x.base_route_record(e, k)?;
        // Form 47's option-table read is supplied by immutable DCM2 and
        // authenticated by its binding hash. It is not an executor assertion
        // and has no prompt route. PXR1 seal validation fixes this route to
        // region 0xffff, class 2, and NO_PRODUCER; all other class-2 reads
        // retain the prompt-only admission rule.
        let document_option_table = cfg!(feature = "revision-8")
            && e.kernel_index == crate::kernels::decision::FORM_ID
            && r.region_id == u16::MAX
            && r.read_class == 2
            && r.producer_entry == crate::position_template::NO_PRODUCER;
        asserted |= r.read_class == 1
            || (r.read_class == 2 && !document_option_table && c.prompt_for(o, k)?.is_none());
        if r.read_class == 3 {
            let decl = c.range_for(o, c3)?.ok_or(PLAN_BINDING)?;
            c3 += 1;
            let first = if decl.first_rule == 0 {
                0
            } else {
                p.saturating_sub(decl.window)
            } as u64;
            let n = span - first;
            let stride = c.region_position(r.region_id)?.map_or(0, |x| x.stride);
            slots = add(slots, n)?;
            read_bytes = add(read_bytes, mul(n, stride)?)?;
            ranged = true;
        } else if r.flags & 2 != 0 {
            let row = c.t_scaled_for(o, 0, k)?.ok_or(PLAN_BINDING)?;
            read_bytes = add(read_bytes, mul(span, row.length_per_t as u64)?)?;
        } else {
            read_bytes = add(read_bytes, r.byte_length as u64)?;
        }
    }
    // Form 48's sealed routes are fixed 8-byte placeholders. Admission must
    // bound the document-selected full producer witnesses instead: the live
    // slot count times the largest PXR1 write. The form-47 row uses the
    // ordinary maximum-length table and gather-output routes above.
    if e.kernel_index == crate::kernels::decision::GATHER_FORM_ID {
        read_bytes = form48_class_read_bytes(x.routes, e.read_count)?;
    }
    for k in 0..e.write_count {
        let r = x.base_route_record(e, e.read_count + k)?;
        write_bytes = add(
            write_bytes,
            if r.flags & 2 != 0 {
                mul(
                    span,
                    c.t_scaled_for(o, 1, k)?.ok_or(PLAN_BINDING)?.length_per_t as u64,
                )?
            } else {
                r.byte_length as u64
            },
        )?;
    }
    Ok(Shape {
        form: e.kernel_index,
        reads: e.read_count as u64,
        writes: e.write_count as u64,
        read_bytes,
        write_bytes,
        payload: x.base_payload_len(o)? as u64,
        asserted,
        range_slots: slots,
        rs1_height: if ranged { h } else { 0 },
        position: p,
    })
}

/// Instance shape of generated entry `(p, t)` (§3.1): closed-form routes;
/// the only admissible supplied read is the whole exp LUT of a 28E/28N entry.
pub fn generated_shape(x: &Pt2p<'_>, p: u32, t: u32, h: u8) -> Result<Shape, u32> {
    let e = x.entry(p, t)?;
    let g = &x.g;
    let (mut read_bytes, mut write_bytes, mut slots) = (0u64, 0u64, 0u64);
    let (mut asserted, mut ranged) = (false, false);
    for k in 0..e.read_count {
        let (r, bind) = x.raw_route(&e, k)?;
        read_bytes = read_bytes
            .checked_add(r.byte_length as u64)
            .ok_or(PLAN_BINDING)?;
        if r.read_class == 1 {
            asserted = true;
        } else if r.read_class == 2 {
            asserted |= !(matches!(e.kernel_index, pt2p::FORM_28E | pt2p::FORM_28N)
                && r.region_id == g.lut_region
                && r.region_offset == 0
                && r.byte_length as u64 == EXP_LUT_BYTES);
        }
        if let Some(b) = bind {
            slots = slots
                .checked_add((b.end - b.first) as u64)
                .ok_or(PLAN_BINDING)?;
            ranged = true;
        }
    }
    for k in 0..e.write_count {
        let (r, _) = x.raw_route(&e, e.read_count + k)?;
        write_bytes = write_bytes
            .checked_add(r.byte_length as u64)
            .ok_or(PLAN_BINDING)?;
    }
    Ok(Shape {
        form: e.kernel_index,
        reads: e.read_count as u64,
        writes: e.write_count as u64,
        read_bytes,
        write_bytes,
        payload: pt2p::GENERATED_PAYLOAD as u64,
        asserted,
        range_slots: slots,
        rs1_height: if ranged { h } else { 0 },
        position: p,
    })
}

/// `S(p, t)` of an instance (the fix-point backstop evaluates this).
pub fn instance_shape(x: &Pt2p<'_>, p: u32, t: u32) -> Result<Shape, u32> {
    let h = rs1_height(x.position_count);
    match x.locate(p, t)? {
        Item::Base(o) => base_shape(x, o, p, h),
        Item::Form(_) => generated_shape(x, p, t, h),
    }
}

/// The class shape `check` evaluates: the representative's shape with
/// `position` raised to the class maximum `p̂`; `None` for an empty class.
pub fn class_shape(x: &Pt2p<'_>, key: ClassKey) -> Result<Option<Shape>, u32> {
    let Some((p, t)) = representative(x, key)? else {
        return Ok(None);
    };
    let h = rs1_height(x.position_count);
    let (s, p_hat) = match key {
        ClassKey::Base(o) => (
            base_shape(x, o, p, h)?,
            if x.is_replaced(o) {
                p
            } else {
                x.position_count - 1
            },
        ),
        ClassKey::Gen { .. } => (generated_shape(x, p, t, h)?, x.position_count - 1),
    };
    Ok(Some(Shape {
        position: p_hat,
        ..s
    }))
}

/// A summary class's pseudo-shape (§3.3): the family's slots as reads, the
/// sum of their raw clause-5 write lengths, height `H`, position `P − 1`.
pub fn summary_shape(x: &Pt2p<'_>, slots: &[u8]) -> Result<Shape, u32> {
    let mut read_bytes = 0u64;
    for slot in slots.chunks_exact(5) {
        let o = u32::from_le_bytes(slot[..4].try_into().unwrap());
        let e = x.base_entry_record(o)?;
        if slot[4] as u16 >= e.write_count {
            return Err(PLAN_BINDING);
        }
        let w = x.base_route_record(e, e.read_count + slot[4] as u16)?;
        read_bytes = read_bytes
            .checked_add(w.byte_length as u64)
            .ok_or(PLAN_BINDING)?;
    }
    Ok(Shape {
        form: FORM_RS1_SUMMARY,
        reads: (slots.len() / 5) as u64,
        writes: 0,
        read_bytes,
        write_bytes: 0,
        payload: 0,
        asserted: false,
        range_slots: 0,
        rs1_height: rs1_height(x.position_count),
        position: x.position_count - 1,
    })
}

/// `Σ_{p<P} entry_count(p)` in closed form (at most `ceil(P/W) + 1` terms).
pub fn total_entries(x: &Pt2p<'_>) -> Result<u64, u32> {
    let p_count = x.position_count as u64;
    let ws = (x.g.window_start as u64).min(p_count);
    let mut total = ws.checked_mul(x.base_entries as u64).ok_or(PLAN_BINDING)?;
    let mut p = ws;
    while p < p_count {
        let n = x.n_of(p as u32);
        let end = p_count.min(n.checked_mul(x.g.window).ok_or(PLAN_BINDING)?);
        let count = x.entry_count(p as u32)? as u64;
        total = total
            .checked_add((end - p).checked_mul(count).ok_or(PLAN_BINDING)?)
            .ok_or(PLAN_BINDING)?;
        p = end;
    }
    Ok(total)
}
