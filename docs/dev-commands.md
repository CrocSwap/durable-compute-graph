# Developer commands: `dcg dev`, `dcg build`, `dcg verify`

These commands replace the runbook steps that used to need project
knowledge: the pinned toolchain path, environment variables, and the deploy
scripts. Alpha plan item E6.

Run them from the repository with `PYTHONPATH=python python -m dcg ...`, or
install the Python package and use `dcg ...`. They need `cargo build-sbf`
(platform tools v1.51) and `solana-test-validator` on PATH.

## `dcg dev`: a local chain with DCG on it

```sh
dcg dev                        # the alpha image (built on first use, cached by commit)
dcg dev --crate examples/session-app      # your application program instead
dcg dev --image path/to/program.so
```

It starts `solana-test-validator`:
- the program is loaded at a fresh address;
- slots are about 50 ms (8 ticks per slot), close to Fogo testnet's 40 ms;
- ports are free and away from the defaults;
- the ledger path is short, since macOS limits socket paths.

It funds a payer and writes an env file with `DCG_RPC_URL`,
`DCG_PROGRAM_ID` and `DCG_PAYER_KEYPAIR`, then runs until Ctrl-C. An
automatically created run directory is deleted on exit unless you pass
`--keep`.

Every example reads that env file:

```sh
source /private/tmp/dcg-dev-…/dcg-dev.env
python examples/hello-graph/traced_dispute.py --settle
```

**Measured (2026-10-05):**
- the first `dcg dev` built the alpha image and started in 36 s; later
  starts take about 1 s;
- `traced_dispute.py --settle` and `app_kernel_dispute.py` ran unchanged
  against it. The rulings matched the oracle, and all runs and the template
  closed (67 s).

## `dcg build`: a reproducible image with a receipt

```sh
dcg build --alpha out/alpha               # the alpha shared-program image
dcg build --crate examples/session-app out/app
```

It runs `cargo build-sbf -- --locked` twice, in separate target directories,
and refuses unless the two images are byte-identical. It writes
`receipt.json` with:
- the commit and whether the tree was clean;
- the features and platform tools;
- the size and sha256;
- the DCG runtime version read from the image.

It refuses to build from a crate with uncommitted changes unless you pass
`--allow-dirty`.

**Measured (2026-10-05):**
- `dcg build --alpha` reproduced the image deployed on the alpha testnet
  program, `8d39d440…`, 344,400 bytes;
- the template app also built reproducibly: `11a7b0ba…`, 375,744 bytes.

## `dcg verify`: is the deployed program the receipt's image?

```sh
dcg verify --rpc https://… --program PROGRAM_ID --receipt out/alpha/receipt.json
```

It reads the program's ProgramData at finalized commitment and checks:
- the payload starts with the receipt's image (sha256 over its length);
- every byte after the image is zero;
- the runtime version matches.

Older receipts carry no runtime version; for them the image hash alone pins
it.

**Measured (2026-10-05):** the alpha testnet program
`J9Eje75v3AgEUZZPJJTJNqKmVxiAjhRhQ7iKYBRo1Hi9` verifies against the R4
receipt. The image matches, 16,080 bytes of zero headroom follow it, and the
runtime is `dcg-runtime 0.1.0`.

## Not covered yet

- Deploying to a network. Use the Solana CLI or your own deploy tooling,
  then run `dcg verify`.
- `dcg dev` loads one program; an application that also needs the alpha
  program would start two.
