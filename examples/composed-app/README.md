# Composed app: optimistic results as consensus inputs

An example of mode composition with mode results v1
(`docs/design/mode-results-v1.md`). The program embeds DCG's stateful
runtime with one kernel, `dcg-importsum-v1`, which sums 4-byte inputs. It
refuses the raw `WRITE_INPUT`; inputs enter only through its `IMPORT`
instruction, which:

1. reads a v2.1 run's result (`dcg_program::result::read_run_result`, no CPI)
   from the run account (live or receipt) and its template;
2. requires a `FINAL` run of the template it trusts, with a challenge window of
   at least 750 slots;
3. opens the named output against the run's out tree (`open_output`) and checks
   the value bytes (`plain_value_matches`);
4. writes those bytes into the session's input stream through the runtime's own
   `WRITE_INPUT` checks.

So every input the consensus session consumes is a verified output of a final
optimistic run of the trusted template. What that does and does not give:

- **FINAL means unchallenged, not checked.** A run is FINAL when its challenge
  window passed with no successful challenge. The input is as good as that
  template's dispute game: an honest, live challenger, the window and the
  bonds.
- **Anyone can make such a run.** Anyone, the session authority included, can
  initialize a run of the trusted template with external inputs they choose
  and execute it. If the inputs or the executor matter, also pin them: require
  the run id (which binds the executor, nonce and external inputs), or check
  them in the kernel.
- **The authority picks what enters.** It chooses which outputs to import, in
  what order, and can leave any out. The example does not count each output
  once (one can be imported twice); a kernel that must, records the run id and
  index it has seen.
- **The host program is trusted.** Results are only as trustworthy as the
  program at `RUN_HOST` (a placeholder here): its image and upgrade authority.
  An image with test or raw-write routes could write records no honest run
  wrote. Check the host with `dcg verify`.
- The kernel never halts, so this session never produces a result of its own.

```sh
CARGO_TARGET_DIR=/private/tmp/dcg-extract-target cargo test            # native
cargo build-sbf --tools-version v1.51 --sbf-out-dir OUT
V3_SBF=1 SBF_OUT_DIR=OUT cargo test                                      # the SBF image
```

The test uses the Hello Graph run's real account bytes (live record, receipt,
template), captured by DCG's flow test into `tests/golden/dcg/result/run.json`,
and checks refusals for a raw write, wrong value bytes, a wrong path, a
committed or refuted run, an untrusted template and a foreign owner.
