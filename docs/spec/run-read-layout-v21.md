# v2.1 run read layout (run-read v1) — 2026-10-05

**Status: designed (documents the layout the program writes at DCG 953763c;
no program change).** This is the stable read surface for applications that
consume the outcome of a v2.1 run (tag 227), for example a request program
that pays on a final run. Everything not listed here (dispute records,
staging buffers, caches, the run's internal dispute counters) is internal and
may change between program versions.

All integers are little-endian. Offsets are bytes from the start of account
data.

## Address and owner

A run lives at the PDA `["dcg21run", run_id, payer]` of the DCG program that
created it, and the account is owned by that program. When the run is closed
(tag 227 sub 19) the same address is shrunk in place into a **receipt**; the
receipt is never closed. A reader therefore sees one of:

| Magic (0..4) | Form | Length |
|---|---|---|
| `D21R` | live run | `192 + 176 + 52·n_ext + 4` |
| `D21P` | receipt of a settled run | `312` |
| (no data, system-owned) | an uncommitted run cancelled after its commit deadline | 0 |

## Live run (`D21R`)

| Offset | Size | Field | Notes |
|---:|---:|---|---|
| 0 | 4 | magic `D21R` | |
| 4 | 1 | status | see below |
| 5 | 3 | zero | |
| 8 | 32 | template | the template account's address |
| 40 | 32 | payer | paid rent and the fee; receives the remainder |
| 72 | 32 | executor | the only key that may commit |
| 104 | 32 | run_id | see "Run id" |
| 136 | 8 | commit slot | |
| 144 | 8 | deadline (slot) | before commit: the commit deadline; after: the challenge deadline |
| 152 | 4 | open disputes | |
| 156 | 4 | n_ext | external refs count |
| 160..192 | 32 | internal | dispute sequence counters, pot flag; not part of this layout |
| 192 | 176 | run root | committed by the executor; zero before commit |
| 368 | 52·n_ext | external refs | sorted by strictly increasing external id |
| end − 4 | 4 | internal | executor-wait trailer |

## Receipt (`D21P`)

Bytes 0..136 are the run's bytes 0..136 with the magic replaced (so status,
template, payer, executor and run_id read at the same offsets). Bytes
136..312 are the run root. A receipt exists only for a settled run: status
`FINAL`, or `REFUTED` with the pot paid.

## Status

| Value | Name | Meaning for a consumer |
|---:|---|---|
| 0 | OPEN | initialized, not committed |
| 1 | COMMITTED | committed; disputes may still open until the deadline |
| 2 | FINAL | the challenge window passed with no successful challenge; the executor's bond is returned. **The only status whose outputs a consumer should accept.** |
| 3 | REFUTED | a challenger won a dispute: the executor is convicted. Never accept its outputs. |

`FINAL` is terminal (a final run cannot be disputed again). A consumer that
reads `COMMITTED` must wait; the deadline at offset 144 tells it when
finalize becomes possible. Note: the Basanos BST6/DCR2 programs use
`RUN_FINAL = 1`; do not reuse those constants for v2.1 runs.

## Run root (176 bytes)

The template decides the root's form: a template with kind byte (template
offset 5) equal to 1 is an **LX1** template; otherwise the root is the
generic v2.1 root.

Generic v2.1 root (`RunRootV21`, dcg-disputes `RunRoot`):

| Offset | Size | Field |
|---:|---:|---|
| 0 | 32 | plan_id |
| 32 | 32 | run_id |
| 64 | 32 | spec_root |
| 96 | 8 | total_steps |
| 104 | 32 | step_root |
| 136 | 8 | total_outputs |
| 144 | 32 | out_root |

LX1 root (`disputes_v21_lx.rs`):

| Offset | Size | Field |
|---:|---:|---|
| 0 | 32 | run_id |
| 32 | 32 | checkpoint_root |
| 64 | 32 | outputs_digest |
| 96 | 32 | params_digest (domain `dcg.lx.params.v1\0`) |
| 128 | 8 | positions |
| 136 | 4 | k (checkpoint interval) |
| 140 | 36 | zero |

### LX1 outputs digest

Over the run's output slots in slot order, from a 32-byte zero start:

```
acc = SHA-256("dcg.lx.outputs.v1\0" || acc || 0x00)                        # empty slot
acc = SHA-256("dcg.lx.outputs.v1\0" || acc || 0x01 || len:u32 || bytes)    # present slot
```

A consumer that is handed the output values re-hashes them this way and
compares with `outputs_digest` (dcg-disputes `lx::outputs_digest`).

## Run id

```
run_id = SHA-256("dcg.run.id.v2.1\0" || template_id || nonce[32] || n_ext:u32 || refs[52·n_ext] || executor[32])
```

`template_id` is the 32 bytes at template offset 96; `nonce`, `executor` and
`refs` are the init arguments (tag 227 sub 2). A consumer that knows the
template, nonce, refs and executor can compute the run id, and so the run's
address, before the run exists.

## Consumer checklist

To accept a run's outputs, a consumer checks, in order:

1. The account is owned by the expected DCG program and is the PDA
   `["dcg21run", run_id, payer]` for the run id it expects.
2. Magic `D21R` with the exact length above, or `D21P` with length 312.
3. Template (offset 8) is the expected template; executor (offset 72) is the
   expected executor; run_id (offset 104) equals the expected run id.
4. Status is `FINAL` (2).
5. For LX1: `params_digest` (root offset 96) equals the expected parameters,
   and the output values re-hash to `outputs_digest`.

## Versioning

This layout is run-read v1. A change to any listed offset, size or meaning
gets a new magic (for the run and the receipt) and a new version of this
document; the old magic keeps its layout for as long as such accounts exist.
Adding fields after the listed ones in a new account form does not change v1
readers of the old form.
