# DCG TPU send helper

This standalone Rust executable accepts fully signed Solana wire transactions
on stdin and submits them through leader TPU/QUIC connections. Python owns the
signer, durable transaction journal, confirmation polling, and retry decisions.
The helper receives no key or unsigned message, and its local pipe handoff is
not evidence that a validator received or landed a transaction.

Build with the checked-in lockfile:

```sh
cargo build --locked --release --manifest-path rust/tpu-sender/Cargo.toml
```

Pass the resulting `target/release/tpu-sender` path as
`TpuQuicConfig.helper_binary`. The provider starts one persistent helper for
its configured RPC cluster and bind address. Configure a separate provider for
each source address or route required by the application.

The stdin frame is a four-byte little-endian packet length followed by the
signed packet bytes. The helper accepts packets up to Solana's 1,232-byte wire
limit. It writes asynchronous `ERR <signature|-> <reason>` records to stdout;
the Python provider retains these in a bounded failure queue. Successful
submission has no per-transaction network acknowledgment, so signature status
and account-state observation stay on the RPC side.

The crate is intentionally standalone from `crates/dcg-program`; its pinned
Solana client dependencies and lockfile define the executable build. It has no
live endpoint test in this package.
