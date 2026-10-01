// SPDX-License-Identifier: GPL-3.0-only
//! tpu-sender — a stdin -> TPU QUIC pump.
//!
//! Reads length-prefixed, fully signed Solana wire transactions from stdin and
//! forwards them straight to the current/upcoming leaders' TPU QUIC ports (the
//! same path `solana program deploy` uses) instead of going through the RPC
//! `sendTransaction` endpoint.
//!
//! Confirmation is deliberately *not* this tool's job: the producer polls
//! `getSignatureStatuses` itself and owns expiry/resubmission.
//!
//! # Why this file talks to the connection cache directly
//!
//! `TpuClient::try_send_wire_transaction_batch` (solana-tpu-client 2.3.13,
//! `src/nonblocking/tpu_client.rs`) fans a batch out to every leader in the
//! fanout window with `join_all` and then returns `Ok(())` **if any single
//! leader accepted it**, discarding every other leader's `TransportError`.
//! A run can therefore report `sent=N err=0` while three of four leaders
//! refused the traffic outright. It also has no timeout: `open_uni().await`
//! inside `solana-quic-client` blocks until the peer grants stream credit, so
//! one throttled leader wedges the whole pump indefinitely.
//!
//! So `TpuClient` is not used at all here. The pump drives the two pieces it
//! wraps directly: `LeaderTpuService` (re-exported by solana-client) for the
//! leader sockets, and our own `ConnectionCache`, whose
//! `get_nonblocking_connection` / `send_data_batch` are called per leader,
//! sequentially, under a deadline. Sequential per-leader sends are what make
//! the connection-cache counters (which the library resets on every metrics
//! submission) attributable to a single peer, and owning the cache outright is
//! what guarantees it is built once and never churned.

use {
    clap::Parser,
    log::{debug, info, warn},
    solana_client::{
        connection_cache::ConnectionCache,
        nonblocking::tpu_client::{LeaderTpuService, TpuSenderError},
    },
    solana_commitment_config::CommitmentConfig,
    solana_connection_cache::{
        connection_cache::{ConnectionCache as BackendConnectionCache, Protocol},
        connection_cache_stats::ConnectionCacheStats,
        nonblocking::client_connection::ClientConnection,
    },
    solana_quic_client::{QuicConfig, QuicConnectionManager, QuicPool},
    solana_rpc_client::nonblocking::rpc_client::RpcClient,
    std::{
        collections::{BTreeMap, HashMap},
        fs::{File, OpenOptions},
        io::{Read, Write},
        net::{IpAddr, SocketAddr, UdpSocket},
        path::PathBuf,
        process::ExitCode,
        sync::{
            atomic::{AtomicBool, AtomicU64, Ordering},
            Arc, Mutex,
        },
        time::Duration,
        time::{SystemTime, UNIX_EPOCH},
    },
    tokio::{
        io::AsyncWriteExt,
        sync::{mpsc, RwLock, Semaphore},
        time::{timeout, timeout_at, Instant, MissedTickBehavior},
    },
};

/// Concrete QUIC-flavoured alias for the generic connection cache.
type QuicCache = Arc<BackendConnectionCache<QuicPool, QuicConnectionManager, QuicConfig>>;

/// Largest legal Solana transaction on the wire.
const MAX_FRAME: usize = 1232;
/// Bounded frame channel: when it fills, the stdin reader thread parks and the
/// producer blocks on its pipe write. That *is* the backpressure signal.
const CHANNEL_CAP: usize = 4096;
/// Give up on leader-schedule/cluster-node/websocket setup after this long.
const STARTUP_TIMEOUT: Duration = Duration::from_secs(45);
/// How often we ask the RPC where the cluster is (slot + leader, for `STAT`
/// and for the websocket-fallback freshness check).
const SLOT_POLL_INTERVAL: Duration = Duration::from_secs(2);
/// How often we re-read `getClusterNodes` to label TPU sockets with the
/// validator pubkey that owns them.
const NODE_MAP_REFRESH: Duration = Duration::from_secs(60);
/// In websocket-fallback mode the embedded leader service has no slot feed, so
/// its leader view goes stale. Rebuild it once the polled slot has drifted this
/// far past the slot the current client was anchored at.
const FALLBACK_REBUILD_DRIFT_SLOTS: u64 = 64;
/// ...but never more often than this, whatever the slot time is. The rebuild
/// reuses the existing `ConnectionCache`, so it costs RPC calls, not QUIC
/// connections; this bound keeps it from hammering the endpoint on a chain
/// with short slots.
const FALLBACK_REBUILD_MIN_INTERVAL: Duration = Duration::from_secs(10);
/// After tearing the connection pool down, give the peer a moment to reap the
/// sockets we just closed before we dial again.
const POOL_REAP_GRACE: Duration = Duration::from_millis(1000);
/// On the way out, let quinn flush its CONNECTION_CLOSE frames so the peer frees
/// our slot immediately instead of waiting out its 60s idle timeout.
const SHUTDOWN_LINGER: Duration = Duration::from_millis(500);
/// How much traffic the `--rate` token bucket may hold in reserve. QUIC servers
/// meter unstaked streams over a short window (Agave's is 100ms), so a deeper
/// bucket only lets us hand them a burst they will throttle.
const BURST_WINDOW: Duration = Duration::from_millis(100);

#[derive(Parser, Debug)]
#[command(
    name = "tpu-sender",
    about = "Pump length-prefixed signed Solana wire transactions from stdin to leader TPU QUIC ports"
)]
struct Args {
    /// JSON-RPC endpoint (used for leader schedule + cluster nodes only).
    #[arg(long)]
    rpc: String,
    /// Websocket endpoint. Defaults to --rpc with http->ws / https->wss.
    #[arg(long)]
    ws: Option<String>,
    /// Local IP address the QUIC endpoint's UDP socket is bound to. Unset
    /// leaves the library's own choice in force (`0.0.0.0`, a port out of
    /// `VALIDATOR_PORT_RANGE`).
    ///
    /// This process uses one source address. Applications that need multiple
    /// source addresses may run separate helpers and route signed packets
    /// between them; coordination and traffic policy stay with the caller.
    ///
    /// The socket is bound eagerly at startup, so an address this host does
    /// not hold is a `FATAL` before any transaction is accepted rather than a
    /// silent fallback to the default source address. The bound `ip:port` is
    /// echoed once as a `BIND` line on stdout and repeated in every `STAT` as
    /// `bind=`, which is the only in-process evidence of which address the
    /// traffic actually left from: nothing the leader returns carries it.
    #[arg(long)]
    bind: Option<IpAddr>,
    /// Number of upcoming slots whose leaders also receive each batch.
    #[arg(long, default_value_t = 8)]
    fanout_slots: u64,
    /// QUIC connection pool size per leader. A peer refusal may cause the pool
    /// to collapse to one connection once for the life of this helper. The
    /// default is one; connection policy is configurable for the target
    /// cluster and environment.
    #[arg(long, default_value_t = 1)]
    connections: usize,
    /// Maximum frames coalesced into a single TPU batch.
    #[arg(long, default_value_t = 64)]
    batch_max: usize,
    /// How long to keep coalescing after the first frame of a batch arrives.
    #[arg(long, default_value_t = 2)]
    batch_wait_ms: u64,
    /// Seconds between STAT lines; 0 disables them.
    #[arg(long, default_value_t = 5)]
    stats_interval_secs: u64,
    /// Token-bucket ceiling on transactions handed to the network, per second.
    /// 0 = unlimited.
    #[arg(long, default_value_t = 0.0)]
    rate: f64,
    /// Token-bucket reserve, in frames. 0 = derive it from `--rate` over a
    /// 100ms window (the old behaviour: rate 100 gives bursts of 10).
    ///
    /// `--burst 1` paces strictly: one frame per `1/rate` seconds, no reserve
    /// to spend at once. That is the knob for testing whether the one-slot
    /// late arrivals are quinn interleaving a burst's streams across packets,
    /// because a burst of one cannot be interleaved with anything.
    #[arg(long, default_value_t = 0)]
    burst: usize,
    /// Append one line per frame handed to the wire:
    /// `<unix_micros> <base58 signature> <bytes> <leader>`.
    ///
    #[arg(long)]
    frame_log: Option<PathBuf>,
    /// Batches allowed to be in flight at once. 1 = strictly serial.
    #[arg(long, default_value_t = 1)]
    max_inflight_batches: usize,
    /// Deadline for one leader's `send_data_batch`. The library has none: a
    /// peer that stops granting stream credit blocks `open_uni()` forever.
    ///
    /// This bounds a send wait. A send that reaches the deadline marks the
    /// peer unavailable until the reconnect interval allows another attempt.
    /// Configure it for the target cluster and environment.
    #[arg(long, default_value_t = 5000)]
    send_timeout_ms: u64,
    /// Never dial the same peer more often than this. A peer whose last send
    /// failed is skipped (not redialled) until the interval has elapsed.
    #[arg(long, default_value_t = 10)]
    reconnect_min_interval_secs: u64,
}

/// A unit of work handed from the stdin reader thread to the sender task.
enum Item {
    /// A frame that passed framing checks and should go to the network.
    Tx(Vec<u8>),
    /// A frame rejected before it ever reached the network. `head` holds
    /// whatever prefix we managed to read, so we can still recover a signature.
    Reject { head: Vec<u8>, reason: &'static str },
}

// ---------------------------------------------------------------- statistics

#[derive(Default)]
struct Stats {
    sent: AtomicU64,
    err: AtomicU64,
    batches: AtomicU64,
    /// 0 means "not observed yet".
    slot: AtomicU64,
    leader: Mutex<Option<String>>,
    /// Per-leader send outcomes, summed over every leader of every batch.
    leader_ok: AtomicU64,
    leader_err: AtomicU64,
    leader_stall: AtomicU64,
    leader_skip: AtomicU64,
    /// Batches where at least one leader's send raised STREAMS_BLOCKED — the
    /// peer withheld stream credit, i.e. it throttled us.
    credit_stalls: AtomicU64,
    /// Application-level connection closes observed from peers.
    peer_closes: AtomicU64,
    /// Milliseconds spent parked in the rate limiter.
    paced_ms: AtomicU64,
}

/// Counters harvested out of `ConnectionCacheStats`.
///
/// The library drains every one of those atomics to zero inside
/// `ConnectionCacheStats::report`, which `ConnectionCache::get_connection` runs
/// every ~2s. They are therefore useless as running totals unless somebody
/// reads and accumulates them faster than that — which is what `harvest` does,
/// once immediately before and once immediately after every per-leader send.
#[derive(Default)]
struct LibCounters {
    connections: AtomicU64,
    reuse: AtomicU64,
    conn_errors: AtomicU64,
    zrtt_ok: AtomicU64,
    zrtt_rej: AtomicU64,
    packets_ok: AtomicU64,
    streams_blocked: AtomicU64,
    data_blocked: AtomicU64,
    congestion: AtomicU64,
}

/// What one `harvest` pulled out of the shared cache stats.
#[derive(Default, Clone, Copy)]
struct LibDelta {
    connections: u64,
    reuse: u64,
    conn_errors: u64,
    zrtt_ok: u64,
    zrtt_rej: u64,
    packets_ok: u64,
    streams_blocked: u64,
    data_blocked: u64,
    congestion: u64,
}

impl LibDelta {
    fn is_quiet(&self) -> bool {
        self.connections == 0
            && self.conn_errors == 0
            && self.zrtt_rej == 0
            && self.streams_blocked == 0
            && self.data_blocked == 0
            && self.congestion == 0
    }
}

impl LibCounters {
    fn harvest(&self, stats: &ConnectionCacheStats) -> LibDelta {
        let client = &stats.total_client_stats;
        let delta = LibDelta {
            connections: client.total_connections.swap(0, Ordering::Relaxed),
            reuse: client.connection_reuse.swap(0, Ordering::Relaxed),
            conn_errors: client.connection_errors.swap(0, Ordering::Relaxed),
            zrtt_ok: client.zero_rtt_accepts.swap(0, Ordering::Relaxed),
            zrtt_rej: client.zero_rtt_rejects.swap(0, Ordering::Relaxed),
            packets_ok: client.successful_packets.swap(0, Ordering::Relaxed),
            streams_blocked: client.streams_blocked_uni.load_and_reset(),
            data_blocked: client.data_blocked.load_and_reset(),
            congestion: client.congestion_events.load_and_reset(),
        };
        self.connections
            .fetch_add(delta.connections, Ordering::Relaxed);
        self.reuse.fetch_add(delta.reuse, Ordering::Relaxed);
        self.conn_errors
            .fetch_add(delta.conn_errors, Ordering::Relaxed);
        self.zrtt_ok.fetch_add(delta.zrtt_ok, Ordering::Relaxed);
        self.zrtt_rej.fetch_add(delta.zrtt_rej, Ordering::Relaxed);
        self.packets_ok
            .fetch_add(delta.packets_ok, Ordering::Relaxed);
        self.streams_blocked
            .fetch_add(delta.streams_blocked, Ordering::Relaxed);
        self.data_blocked
            .fetch_add(delta.data_blocked, Ordering::Relaxed);
        self.congestion
            .fetch_add(delta.congestion, Ordering::Relaxed);
        delta
    }
}

/// Everything we know about one leader's TPU QUIC socket.
#[derive(Default)]
struct Peer {
    batches: u64,
    ok: u64,
    err: u64,
    stall: u64,
    skip: u64,
    txs_ok: u64,
    connections: u64,
    reuse: u64,
    conn_errors: u64,
    zrtt_ok: u64,
    zrtt_rej: u64,
    streams_blocked: u64,
    data_blocked: u64,
    congestion: u64,
    /// `error_code/reason` (or an error class) -> how many times seen.
    closes: BTreeMap<String, u64>,
    last_err: Option<String>,
    /// Our belief that a usable connection to this peer exists.
    connected: bool,
    /// A send that will dial this peer is in flight right now.
    dialing: bool,
    /// When we last let the library dial this peer.
    last_dial: Option<Instant>,
}

impl Peer {
    /// The reconnect decision for this peer, made against `now`.
    ///
    /// `dialing` is what keeps concurrent batches (`--max-inflight-batches`)
    /// from turning one peer's first contact into N-1 skipped sends: while a
    /// dial is in flight the others are told to reuse, and `QuicClient` holds a
    /// mutex over its connection slot, so they queue behind the same handshake
    /// and then share its result.
    fn gate(&mut self, now: Instant, min_interval: Duration) -> Gate {
        if self.connected || self.dialing {
            return Gate::Reuse;
        }
        match self.last_dial {
            None => {
                self.last_dial = Some(now);
                self.dialing = true;
                Gate::Dial("first-contact")
            }
            Some(last) if now.saturating_duration_since(last) >= min_interval => {
                self.last_dial = Some(now);
                self.dialing = true;
                Gate::Dial("previous-attempt-failed")
            }
            Some(_) => Gate::Skip,
        }
    }
}

/// What the reconnect policy says about contacting a peer right now.
enum Gate {
    /// A connection is believed to be up; the library will reuse it.
    Reuse,
    /// No connection: let the library dial, for this reason.
    Dial(&'static str),
    /// The last dial to this peer was too recent. Skip it this round.
    Skip,
}

// -------------------------------------------------------------- rate limiter

struct PacerState {
    tokens: f64,
    last: Instant,
}

/// A token bucket over transactions. `rate <= 0` disables it entirely.
struct Pacer {
    rate: f64,
    burst: f64,
    state: Mutex<PacerState>,
}

impl Pacer {
    fn new(rate: f64, burst: f64) -> Self {
        Self {
            rate,
            burst: burst.max(1.0),
            state: Mutex::new(PacerState {
                tokens: burst.max(1.0),
                last: Instant::now(),
            }),
        }
    }

    /// Refill, then either spend `want` tokens or report how long to wait.
    fn try_take(&self, want: f64, now: Instant) -> Result<(), Duration> {
        let mut state = match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let elapsed = now.saturating_duration_since(state.last).as_secs_f64();
        state.last = now;
        state.tokens = (state.tokens + elapsed * self.rate).min(self.burst);
        // A batch bigger than the bucket would never be affordable; cap the ask.
        let want = want.min(self.burst);
        if state.tokens >= want {
            state.tokens -= want;
            return Ok(());
        }
        let deficit = want - state.tokens;
        Err(Duration::from_secs_f64((deficit / self.rate).max(0.001)))
    }

    /// Spend a token if one is there right now, without parking.
    fn try_now(&self, want: f64) -> bool {
        self.rate <= 0.0 || self.try_take(want, Instant::now()).is_ok()
    }

    /// Hand a token back, for one that was taken but not used.
    fn refund(&self, want: f64) {
        if self.rate <= 0.0 {
            return;
        }
        let mut state = match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        state.tokens = (state.tokens + want).min(self.burst);
    }

    /// Park until `count` transactions may be sent. Returns the time waited.
    async fn acquire(&self, count: usize) -> Duration {
        if self.rate <= 0.0 {
            return Duration::ZERO;
        }
        let started = Instant::now();
        let want = count as f64;
        loop {
            match self.try_take(want, Instant::now()) {
                Ok(()) => return started.elapsed(),
                Err(wait) => tokio::time::sleep(wait).await,
            }
        }
    }
}

// ---------------------------------------------------------------------- pump

/// The parts of the pump that a rebuild replaces wholesale.
struct Inner {
    leaders: LeaderTpuService,
    /// The exit flag the leader service's background task watches.
    exit: Arc<AtomicBool>,
    cache: QuicCache,
    pool_size: usize,
    /// True when the leader service is running without a websocket slot feed.
    ws_fallback: bool,
    /// Slot the current leader view was anchored at (fallback only).
    anchor_slot: u64,
    /// When the leader view was last rebuilt (fallback only).
    last_refresh: Option<Instant>,
}

/// Everything the sender loop needs to keep a live TPU client pointed at the
/// right leaders over connections the peers are actually willing to accept.
struct Pump {
    rpc: Arc<RpcClient>,
    ws_url: String,
    fanout_slots: u64,
    send_timeout: Duration,
    reconnect_min: Duration,
    inner: RwLock<Inner>,
    peers: Mutex<HashMap<SocketAddr, Peer>>,
    /// TPU QUIC socket -> validator pubkey, refreshed from `getClusterNodes`.
    names: Mutex<HashMap<SocketAddr, String>>,
    lib: LibCounters,
    /// The cache-wide stats object, captured from the first connection we take.
    lib_stats: Mutex<Option<Arc<ConnectionCacheStats>>>,
    /// The connection cache is rebuilt at most once in the life of a process.
    rebuilt: AtomicBool,
    cache_rebuilds: AtomicU64,
    leader_refreshes: AtomicU64,
    pacer: Pacer,
    /// Optional per-frame send log; see `Args::frame_log`.
    frame_log: Option<Mutex<File>>,
    /// Local IP every connection cache in this process binds to (`--bind`).
    /// Kept because a rebuild has to bind a *fresh* socket to the same
    /// address: the old endpoint owns the old one until it is dropped.
    bind: Option<IpAddr>,
    /// The `ip:port` the live cache's endpoint actually got. A rebuild changes
    /// the port, so this is read rather than assumed when a `STAT` is built.
    bind_local: Mutex<Option<SocketAddr>>,
}

impl Pump {
    /// Record when each frame of a batch was handed to the wire.
    ///
    /// One line per frame: `<unix_micros> <base58 signature> <bytes> <leader>`.
    /// The signature is the transaction's own, so this joins directly against
    /// the driver's event log -- which is what separates "the frame left late"
    /// from "the frame was delayed in transit or at the leader".
    fn log_frames(&self, wires: &[Vec<u8>], addr: &SocketAddr) {
        let Some(log) = self.frame_log.as_ref() else {
            return;
        };
        let micros = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|since| since.as_micros())
            .unwrap_or(0);
        let mut out = String::new();
        for wire in wires {
            // Wire format: shortvec signature count, then the signatures.  One
            // signer is the only shape this driver sends, so the signature is
            // bytes 1..65; anything shorter is not a transaction we can name.
            if wire.len() < 65 {
                continue;
            }
            let signature = bs58::encode(&wire[1..65]).into_string();
            out.push_str(&format!("{micros} {signature} {} {addr}\n", wire.len()));
        }
        if out.is_empty() {
            return;
        }
        if let Ok(mut file) = log.lock() {
            let _ = file.write_all(out.as_bytes());
        }
    }

    /// Snapshot the leader sockets and the cache without holding the lock
    /// across the sends.
    async fn targets(&self) -> (Vec<SocketAddr>, QuicCache) {
        let inner = self.inner.read().await;
        let leaders = inner.leaders.unique_leader_tpu_sockets(self.fanout_slots);
        (leaders, inner.cache.clone())
    }

    fn bind_lib_stats(&self, stats: &Arc<ConnectionCacheStats>) {
        let mut guard = match self.lib_stats.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if guard.is_none() {
            *guard = Some(stats.clone());
        }
    }

    /// Pull the shared cache counters into our own running totals.
    fn harvest(&self) -> LibDelta {
        let stats = {
            let guard = match self.lib_stats.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            guard.clone()
        };
        match stats {
            Some(stats) => self.lib.harvest(&stats),
            None => LibDelta::default(),
        }
    }

    /// The reconnect policy: at most one dial per peer per
    /// `--reconnect-min-interval-secs`.
    fn gate(&self, addr: &SocketAddr) -> Gate {
        let now = Instant::now();
        let mut peers = match self.peers.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        peers
            .entry(*addr)
            .or_default()
            .gate(now, self.reconnect_min)
    }

    fn with_peer<R>(&self, addr: &SocketAddr, f: impl FnOnce(&mut Peer) -> R) -> R {
        let mut peers = match self.peers.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        f(peers.entry(*addr).or_default())
    }

    fn name_of(&self, addr: &SocketAddr) -> String {
        let names = match self.names.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        names.get(addr).cloned().unwrap_or_else(|| "-".to_string())
    }

    /// Collapse the QUIC connection pool to a single connection, at most once
    /// in the life of the process.
    ///
    /// Agave refuses more than `max_connections_per_peer` concurrent QUIC
    /// connections from one unstaked peer and closes the extras with
    /// `too_many`; that limit defaults to 1, so once a peer says "too many"
    /// the only value guaranteed to work is 1 (QUIC multiplexes every
    /// transaction onto its own stream anyway, so one connection is plenty).
    ///
    /// Rebuilding the cache throws away every live connection to every leader,
    /// and each redial counts against the peer's per-IP-per-minute new
    /// connection budget — so doing it repeatedly is precisely how a sender
    /// talks itself into a ban. Hence: once, ever.
    async fn rebuild_pool_once(&self) -> bool {
        if self.rebuilt.swap(true, Ordering::SeqCst) {
            debug!("pool already rebuilt once in this process; not rebuilding again");
            return false;
        }

        let next = 1usize;
        {
            let inner = self.inner.read().await;
            if inner.pool_size <= next {
                return false;
            }
            warn!(
                "reconnect: rebuilding connection cache, reason=peer-refused-{}-connections (too_many); collapsing pool to {next}",
                inner.pool_size
            );
        }

        // A fresh socket on the same `--bind` address: the endpoint we are
        // about to drop still owns the old one, so this one lands on a
        // different ephemeral port. The peer meters by address, not by port.
        let (cache, fresh_local) = match build_cache("tpu-sender", next, self.bind) {
            Ok(built) => built,
            Err(reason) => {
                warn!("replacement connection cache could not be built ({reason}); keeping the old pool");
                return false;
            }
        };

        let mut inner = self.inner.write().await;
        // Keep whatever slot feed we already had: an empty URL only if we were
        // already polling, otherwise the real websocket.
        let ws_url = if inner.ws_fallback {
            ""
        } else {
            self.ws_url.as_str()
        };
        let (fresh, fresh_exit, fell_back) = match build_leader_service(&self.rpc, ws_url).await {
            Ok(built) => built,
            Err(e) => {
                warn!("could not rebuild the leader service on a smaller pool: {e}");
                return false;
            }
        };

        // Everything the old cache held is about to go; harvest its counters
        // before they vanish and forget every peer's connection state.
        self.harvest();
        {
            let mut guard = match self.lib_stats.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            *guard = None;
        }
        {
            let mut peers = match self.peers.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            for peer in peers.values_mut() {
                peer.connected = false;
                peer.dialing = false;
                peer.last_dial = None;
            }
        }

        inner.exit.store(true, Ordering::Relaxed);
        let stale_leaders = std::mem::replace(&mut inner.leaders, fresh);
        drop(stale_leaders);
        inner.exit = fresh_exit;
        let stale_cache = std::mem::replace(&mut inner.cache, cache);
        drop(stale_cache);
        inner.pool_size = next;
        inner.ws_fallback |= fell_back;
        inner.anchor_slot = 0;
        drop(inner);

        if fresh_local.is_some() {
            let mut guard = match self.bind_local.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            *guard = fresh_local;
        }
        self.cache_rebuilds.fetch_add(1, Ordering::Relaxed);
        tokio::time::sleep(POOL_REAP_GRACE).await;
        true
    }

    /// In websocket-fallback mode the embedded leader service never learns
    /// about new slots (`run_slot_watcher` returns immediately with no pubsub
    /// client), so its leader view is frozen at the slot it was built at. Once
    /// our polled slot has drifted far enough we rebuild the client — reusing
    /// the QUIC cache, so no connection is dropped by this path.
    async fn refresh_leaders(&self, stats: &Stats) {
        {
            let inner = self.inner.read().await;
            if !inner.ws_fallback {
                return;
            }
        }
        let current = stats.slot.load(Ordering::Relaxed);
        if current == 0 {
            return;
        }

        let mut inner = self.inner.write().await;
        if !inner.ws_fallback {
            return;
        }
        if inner.anchor_slot == 0 {
            inner.anchor_slot = current;
            return;
        }
        if current.saturating_sub(inner.anchor_slot) < FALLBACK_REBUILD_DRIFT_SLOTS {
            return;
        }
        if let Some(last) = inner.last_refresh {
            if Instant::now().saturating_duration_since(last) < FALLBACK_REBUILD_MIN_INTERVAL {
                return;
            }
        }

        // Re-anchor regardless of outcome so a broken RPC cannot spin this.
        inner.anchor_slot = current;
        inner.last_refresh = Some(Instant::now());

        match build_leader_service(&self.rpc, "").await {
            Ok((fresh, fresh_exit, _)) => {
                inner.exit.store(true, Ordering::Relaxed);
                let stale = std::mem::replace(&mut inner.leaders, fresh);
                drop(stale);
                inner.exit = fresh_exit;
                self.leader_refreshes.fetch_add(1, Ordering::Relaxed);
                info!(
                    "refreshed leader view at slot {current} (websocket fallback; connection cache reused, no QUIC reconnect)"
                );
            }
            Err(e) => warn!("could not refresh leader view at slot {current}: {e}"),
        }
    }

    /// One `PEER` line per leader we have ever tried to talk to.
    fn peer_lines(&self) -> Vec<String> {
        let peers = match self.peers.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let mut addrs: Vec<SocketAddr> = peers.keys().copied().collect();
        addrs.sort();
        addrs
            .iter()
            .map(|addr| {
                let peer = &peers[addr];
                let closes = if peer.closes.is_empty() {
                    "-".to_string()
                } else {
                    peer.closes
                        .iter()
                        .map(|(what, n)| format!("{what}x{n}"))
                        .collect::<Vec<_>>()
                        .join(",")
                };
                format!(
                    "PEER {addr} id={} batches={} ok={} err={} stall={} skip={} tx={} conns={} reuse={} cerr={} zrtt={}/{} sblk={} dblk={} cong={} closes={} last={}",
                    self.name_of(addr),
                    peer.batches,
                    peer.ok,
                    peer.err,
                    peer.stall,
                    peer.skip,
                    peer.txs_ok,
                    peer.connections,
                    peer.reuse,
                    peer.conn_errors,
                    peer.zrtt_ok,
                    peer.zrtt_rej,
                    peer.streams_blocked,
                    peer.data_blocked,
                    peer.congestion,
                    closes,
                    peer.last_err.as_deref().unwrap_or("-"),
                )
            })
            .collect()
    }

    fn stat_line(&self, stats: &Stats) -> String {
        let slot = stats.slot.load(Ordering::Relaxed);
        let slot = if slot == 0 {
            "-".to_string()
        } else {
            slot.to_string()
        };
        let leader = match stats.leader.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
        .unwrap_or_else(|| "-".to_string());
        let peers = match self.peers.lock() {
            Ok(guard) => guard.len(),
            Err(poisoned) => poisoned.into_inner().len(),
        };
        // Appended, never inserted, and only under `--bind`: a reader that
        // predates striping keeps seeing the line it already parses, and a
        // reader that stripes gets every helper's counters labelled with the
        // source address they belong to.
        let bind = match self.bind_local.lock() {
            Ok(guard) => *guard,
            Err(poisoned) => *poisoned.into_inner(),
        }
        .map(|addr| format!(" bind={addr}"))
        .unwrap_or_default();
        format!(
            "STAT sent={} err={} batches={} slot={slot} leader={leader} \
             lok={} lerr={} lstall={} lskip={} conns={} reuse={} cerr={} zrtt={}/{} \
             sblk={} dblk={} cong={} closes={} creditstall={} paced_ms={} peers={peers} \
             rebuilds={} leaderrefresh={}{bind}",
            stats.sent.load(Ordering::Relaxed),
            stats.err.load(Ordering::Relaxed),
            stats.batches.load(Ordering::Relaxed),
            stats.leader_ok.load(Ordering::Relaxed),
            stats.leader_err.load(Ordering::Relaxed),
            stats.leader_stall.load(Ordering::Relaxed),
            stats.leader_skip.load(Ordering::Relaxed),
            self.lib.connections.load(Ordering::Relaxed),
            self.lib.reuse.load(Ordering::Relaxed),
            self.lib.conn_errors.load(Ordering::Relaxed),
            self.lib.zrtt_ok.load(Ordering::Relaxed),
            self.lib.zrtt_rej.load(Ordering::Relaxed),
            self.lib.streams_blocked.load(Ordering::Relaxed),
            self.lib.data_blocked.load(Ordering::Relaxed),
            self.lib.congestion.load(Ordering::Relaxed),
            stats.peer_closes.load(Ordering::Relaxed),
            stats.credit_stalls.load(Ordering::Relaxed),
            stats.paced_ms.load(Ordering::Relaxed),
            self.cache_rebuilds.load(Ordering::Relaxed),
            self.leader_refreshes.load(Ordering::Relaxed),
        )
    }
}

// ------------------------------------------------------------ error taxonomy

/// Classify a `TransportError` string from `send_data_batch`.
///
/// The QUIC client wraps every failure as
/// `ClientErrorKind::Custom(format!("{quic_error:?}"))`, so what arrives here is
/// the `Debug` rendering of `solana_quic_client::nonblocking::quic_client::QuicError`
/// — which is a thin wrapper over quinn's `WriteError` / `ConnectionError` /
/// `ConnectError`. Returns a short, groupable label.
fn classify_transport_error(err: &str) -> String {
    if let Some(close) = parse_application_close(err) {
        return format!("close:{close}");
    }
    if let Some(code) = digits_after(err, "Stopped(") {
        return format!("stream-stopped:{code}");
    }
    if err.contains("TimedOut") || err.contains("TimeoutError") {
        return "timeout".to_string();
    }
    if err.contains("ConnectionClosed") {
        return "transport-close".to_string();
    }
    if err.contains("LocallyClosed") {
        return "locally-closed".to_string();
    }
    if err.contains("Reset(") {
        return "reset".to_string();
    }
    if err.contains("ConnectError") || err.contains("CidsExhausted") {
        return "connect-failed".to_string();
    }
    if err.contains("ClosedStream") {
        return "closed-stream".to_string();
    }
    "other".to_string()
}

/// Pull `error_code` / `reason` out of quinn's `ApplicationClose` Debug output.
///
/// The text has usually been through one or two rounds of `{:?}`, so the
/// reason arrives as `b"too_many"`, `b\"too_many\"`, or worse. Only the word
/// itself is wanted.
fn parse_application_close(err: &str) -> Option<String> {
    if !err.contains("ApplicationClose") {
        return None;
    }
    let code = digits_after(err, "error_code: ").unwrap_or_else(|| "?".to_string());
    let reason = word_after(err, "reason: ").unwrap_or_else(|| "-".to_string());
    Some(format!("{code}/{reason}"))
}

/// The run of ASCII digits immediately following `needle`.
fn digits_after(haystack: &str, needle: &str) -> Option<String> {
    let start = haystack.find(needle)? + needle.len();
    let digits: String = haystack[start..]
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    (!digits.is_empty()).then_some(digits)
}

/// The first bare word after `needle`, ignoring the byte-string and escaped
/// quote noise that `{:?}` layers on.
fn word_after(haystack: &str, needle: &str) -> Option<String> {
    let start = haystack.find(needle)? + needle.len();
    let rest = haystack[start..].trim_start();
    let rest = rest.trim_start_matches(['b', '\\', '"']);
    let word: String = rest
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .collect();
    (!word.is_empty()).then_some(word)
}

/// Does this transport error mean "you already hold as many connections as I
/// allow"? Agave closes the extras with application code 4 / `too_many`.
fn is_peer_connection_limit(err: &str) -> bool {
    err.contains("too_many")
}

// ------------------------------------------------------------- source address

/// Build the QUIC connection cache, optionally pinning its UDP socket to one
/// local address.
///
/// `solana-quic-client` 2.3.13 has exactly one hook for this and it is not
/// obvious: `QuicConfig::client_endpoint` is private, but
/// `QuicConfig::update_client_endpoint(UdpSocket)` wraps a socket we bind
/// ourselves into a `quinn::Endpoint` and stores it, and
/// `QuicLazyInitializedEndpoint::create_endpoint` then *clones that endpoint*
/// instead of calling `solana_net_utils::bind_in_range_with_config` on
/// `0.0.0.0`. `ConnectionCache::new_with_client_options` is the public path
/// that reaches it -- `ConnectionCache::new_quic(name, size)` is literally
/// `new_with_client_options(name, size, None, None, None)`, so passing `None`
/// here reproduces the old behaviour exactly, byte for byte on the wire.
///
/// Because `QuicConfig::clone` clones the `Endpoint` (a handle, not a socket),
/// every pool in the cache shares that one socket. `--connections 4` therefore
/// still means four QUIC connections out of a single `ip:port`, which is what
/// we want: the peer's per-IP budget does not care about ports.
///
/// Two consequences worth knowing. The bind happens *now*, not on the first
/// send, so a bad address fails startup. And `update_client_endpoint` builds
/// the endpoint inside `solana_quic_client::quic_client::get_runtime()`, the
/// library's own static runtime, so with `--bind` the quinn endpoint driver
/// lives on that runtime rather than on ours; the connection futures we await
/// are unaffected, they just talk to it over quinn's channels.
fn build_cache(
    name: &'static str,
    pool_size: usize,
    bind: Option<IpAddr>,
) -> Result<(QuicCache, Option<SocketAddr>), String> {
    let (socket, local) = match bind {
        None => (None, None),
        Some(ip) => {
            // Port 0: the peer meters us by address, and a fixed client port
            // would only collide with the next helper on the same host.
            let socket = UdpSocket::bind(SocketAddr::new(ip, 0)).map_err(|e| {
                format!("--bind {ip}: cannot bind a UDP socket to that local address: {e}")
            })?;
            let local = socket
                .local_addr()
                .map_err(|e| format!("--bind {ip}: bound socket has no local address: {e}"))?;
            (Some(socket), Some(local))
        }
    };
    match ConnectionCache::new_with_client_options(name, pool_size, socket, None, None) {
        ConnectionCache::Quic(cache) => Ok((cache, local)),
        _ => Err("connection cache did not come up as QUIC".to_string()),
    }
}

// ---------------------------------------------------------------------- main

fn main() -> ExitCode {
    let args = Args::parse();
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("FATAL failed to start tokio runtime: {e}");
            return ExitCode::from(2);
        }
    };

    match runtime.block_on(run(args)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(reason) => {
            eprintln!("FATAL {reason}");
            ExitCode::from(2)
        }
    }
}

async fn run(args: Args) -> Result<(), String> {
    if args.batch_max == 0 {
        return Err("--batch-max must be >= 1".to_string());
    }
    if args.fanout_slots == 0 {
        return Err("--fanout-slots must be >= 1".to_string());
    }
    if args.max_inflight_batches == 0 {
        return Err("--max-inflight-batches must be >= 1".to_string());
    }
    if args.send_timeout_ms == 0 {
        return Err("--send-timeout-ms must be >= 1".to_string());
    }
    if args.rate.is_nan() || args.rate < 0.0 {
        return Err("--rate must be a number >= 0".to_string());
    }
    let pool_size = args.connections.max(1);

    let ws_url = args.ws.clone().unwrap_or_else(|| derive_ws_url(&args.rpc));

    let rpc = Arc::new(RpcClient::new_with_commitment(
        args.rpc.clone(),
        CommitmentConfig::processed(),
    ));

    let (cache, bind_local) = build_cache("tpu-sender", pool_size, args.bind)?;
    if let Some(local) = bind_local {
        // Printed before the writer task exists, and before the leader service
        // is built, on purpose: this is the one line that says which source
        // address this process holds, and an RPC that never answers must not
        // be able to swallow it. Only emitted under `--bind`, so a helper
        // without the flag produces exactly the stdout it always did.
        println!("BIND {local}");
        let _ = std::io::stdout().flush();
    }

    let (leaders, exit, ws_fallback) = build_leader_service(&rpc, &ws_url).await?;
    info!(
        "tpu-sender ready: rpc={} ws={ws_url} bind={} fanout_slots={} connections={pool_size} \
         batch_max={} batch_wait_ms={} rate={} max_inflight_batches={} send_timeout_ms={} \
         reconnect_min_interval_secs={} ws_fallback={ws_fallback}",
        args.rpc,
        bind_local
            .map(|addr| addr.to_string())
            .unwrap_or_else(|| "-".to_string()),
        args.fanout_slots,
        args.batch_max,
        args.batch_wait_ms,
        args.rate,
        args.max_inflight_batches,
        args.send_timeout_ms,
        args.reconnect_min_interval_secs,
    );

    // The bucket holds at most one `--batch-max` burst, and at most a tenth of
    // a second's worth of traffic -- QUIC servers budget unstaked streams per
    // short interval, so a bucket deeper than that just re-creates the burst
    // the rate limit was meant to remove.
    let burst = if args.burst > 0 {
        // Explicit reserve, in frames.  `--burst 1` removes the reserve
        // entirely: frames go out strictly one per 1/rate seconds.
        args.burst as f64
    } else if args.rate > 0.0 {
        (args.rate * BURST_WINDOW.as_secs_f64()).clamp(1.0, args.batch_max as f64)
    } else {
        args.batch_max as f64
    };
    let pump = Arc::new(Pump {
        rpc: rpc.clone(),
        ws_url,
        fanout_slots: args.fanout_slots,
        send_timeout: Duration::from_millis(args.send_timeout_ms),
        reconnect_min: Duration::from_secs(args.reconnect_min_interval_secs),
        inner: RwLock::new(Inner {
            leaders,
            exit,
            cache,
            pool_size,
            ws_fallback,
            anchor_slot: 0,
            last_refresh: None,
        }),
        peers: Mutex::new(HashMap::new()),
        names: Mutex::new(HashMap::new()),
        lib: LibCounters::default(),
        lib_stats: Mutex::new(None),
        rebuilt: AtomicBool::new(false),
        cache_rebuilds: AtomicU64::new(0),
        leader_refreshes: AtomicU64::new(0),
        pacer: Pacer::new(args.rate, burst),
        frame_log: match args.frame_log.as_ref() {
            None => None,
            Some(path) => match OpenOptions::new().create(true).append(true).open(path) {
                Ok(file) => Some(Mutex::new(file)),
                Err(err) => {
                    warn!("frame log {} could not be opened: {err}", path.display());
                    None
                }
            },
        },
        bind: args.bind,
        bind_local: Mutex::new(bind_local),
    });

    let stats = Arc::new(Stats::default());

    // Single writer task owns stdout so every line is emitted whole and flushed.
    let (out_tx, out_rx) = mpsc::unbounded_channel::<String>();
    let writer = tokio::spawn(writer_task(out_rx));

    // Bounded frame channel + a real OS thread doing the blocking stdin reads.
    let (frame_tx, mut frame_rx) = mpsc::channel::<Item>(CHANNEL_CAP);
    let reader = std::thread::Builder::new()
        .name("stdin-reader".to_string())
        .spawn(move || read_frames(frame_tx))
        .map_err(|e| format!("could not spawn stdin reader thread: {e}"))?;

    let poller = tokio::spawn(poll_cluster(rpc, stats.clone(), pump.clone()));
    let statter = if args.stats_interval_secs > 0 {
        Some(tokio::spawn(stats_task(
            Duration::from_secs(args.stats_interval_secs),
            stats.clone(),
            pump.clone(),
            out_tx.clone(),
        )))
    } else {
        None
    };

    // The Python parent waits for this handshake before writing any packet.
    // Leader/RPC startup can take up to 45 seconds per attempt, including the
    // fallback path, so accepting stdin before this point could lose frames to
    // a fatal startup exit.
    out_tx
        .send("READY".to_string())
        .map_err(|_| "stdout writer stopped before startup completed".to_string())?;

    let batch_wait = Duration::from_millis(args.batch_wait_ms);
    let inflight = Arc::new(Semaphore::new(args.max_inflight_batches));

    loop {
        // Pace at admission, one token per frame, *before* the frame leaves the
        // channel. Pacing the assembled batch instead would let a backlog build
        // up in the channel during the wait and then leave as one 64-stream
        // burst -- which is the shape a peer's per-interval stream budget
        // punishes, and it is measurably worse than the same average rate
        // delivered smoothly.
        let waited = pump.pacer.acquire(1).await;
        if !waited.is_zero() {
            stats
                .paced_ms
                .fetch_add(waited.as_millis() as u64, Ordering::Relaxed);
        }
        let Some(first) = frame_rx.recv().await else {
            pump.pacer.refund(1.0);
            break;
        };

        let mut items = Vec::with_capacity(args.batch_max);
        items.push(first);
        let mut eof = false;

        if args.batch_max > 1 {
            let deadline = Instant::now() + batch_wait;
            while items.len() < args.batch_max {
                // Coalesce only as far as the bucket already allows: a frame
                // that would have to wait for a token stays in the channel and
                // starts the next batch instead of fattening this one.
                if !pump.pacer.try_now(1.0) {
                    break;
                }
                match timeout_at(deadline, frame_rx.recv()).await {
                    Ok(Some(item)) => items.push(item),
                    Ok(None) => {
                        pump.pacer.refund(1.0);
                        eof = true;
                        break;
                    }
                    Err(_) => {
                        pump.pacer.refund(1.0);
                        break; // coalescing window closed
                    }
                }
            }
        }

        pump.refresh_leaders(&stats).await;

        let Ok(permit) = inflight.clone().acquire_owned().await else {
            break;
        };
        let task_pump = pump.clone();
        let task_stats = stats.clone();
        let task_out = out_tx.clone();
        tokio::spawn(async move {
            process_batch(&task_pump, items, &task_stats, &task_out).await;
            drop(permit);
        });

        if eof {
            break;
        }
    }

    // Let every in-flight batch finish before the shutdown sequence.
    let permits = u32::try_from(args.max_inflight_batches).unwrap_or(u32::MAX);
    let _drained = inflight.acquire_many(permits).await;

    // Wind everything down before the final line so DONE is genuinely last.
    if let Some(statter) = statter {
        statter.abort();
        let _ = statter.await;
    }
    poller.abort();
    let _ = poller.await;
    pump.harvest();
    for line in pump.peer_lines() {
        let _ = out_tx.send(line);
    }
    {
        // Stop the leader service's background task. `LeaderTpuService::join`
        // is deliberately not called: it unwraps the task's result, so a
        // websocket that died on the way out would turn shutdown into a panic.
        let mut inner = pump.inner.write().await;
        inner.exit.store(true, Ordering::Relaxed);

        // Hand the peers back their connection slots *now*, while there is
        // still time to flush. An Agave peer keeps an unstaked connection in
        // its per-IP table until the client closes it or it idles out after
        // 60s, and `max_connections_per_peer` defaults to 1 -- so a helper
        // that exits without closing gets the *next* helper from this host
        // refused with `too_many` for a minute. Swapping in an empty cache
        // drops the last reference to every live connection, which is what
        // makes quinn emit CONNECTION_CLOSE.
        //
        // Deliberately not `build_cache(.., self.bind)`: this cache exists to
        // be empty and is never sent through, and under `--bind` building one
        // would eagerly open a second UDP socket on the address we are in the
        // middle of giving up.
        if let ConnectionCache::Quic(fresh) = ConnectionCache::new_quic("tpu-sender-drained", 1) {
            let stale = std::mem::replace(&mut inner.cache, fresh);
            drop(stale);
        }
    }
    // Let quinn put those CONNECTION_CLOSE frames on the wire before the
    // runtime goes away.
    tokio::time::sleep(SHUTDOWN_LINGER).await;
    let _ = reader.join();

    let _ = out_tx.send(format!(
        "DONE sent={} err={} batches={} conns={} lok={} lerr={} lstall={} lskip={}",
        stats.sent.load(Ordering::Relaxed),
        stats.err.load(Ordering::Relaxed),
        stats.batches.load(Ordering::Relaxed),
        pump.lib.connections.load(Ordering::Relaxed),
        stats.leader_ok.load(Ordering::Relaxed),
        stats.leader_err.load(Ordering::Relaxed),
        stats.leader_stall.load(Ordering::Relaxed),
        stats.leader_skip.load(Ordering::Relaxed),
    ));
    drop(out_tx);
    let _ = writer.await;
    Ok(())
}

/// Build the leader tracker, degrading to RPC-polled tracking if the websocket
/// subscription cannot be established. Returns the service, the exit flag its
/// background task watches, and whether we fell back.
async fn build_leader_service(
    rpc: &Arc<RpcClient>,
    ws_url: &str,
) -> Result<(LeaderTpuService, Arc<AtomicBool>, bool), String> {
    let exit = Arc::new(AtomicBool::new(false));
    let attempt = tokio::time::timeout(
        STARTUP_TIMEOUT,
        LeaderTpuService::new(rpc.clone(), ws_url, Protocol::QUIC, exit.clone()),
    )
    .await;

    match attempt {
        Ok(Ok(service)) => return Ok((service, exit, false)),
        Ok(Err(TpuSenderError::PubsubError(e))) => {
            warn!("websocket {ws_url} unavailable ({e}); falling back to RPC getSlot polling for leader tracking");
        }
        Ok(Err(e)) => return Err(format!("{e}")),
        Err(_) => {
            warn!("leader-service setup via {ws_url} timed out after {STARTUP_TIMEOUT:?}; falling back to RPC getSlot polling for leader tracking");
        }
    }
    exit.store(true, Ordering::Relaxed);

    // An empty websocket URL makes the leader service skip pubsub entirely --
    // and with no slot feed its view is frozen at the slot it was built at,
    // which is why `refresh_leaders` exists.
    let exit = Arc::new(AtomicBool::new(false));
    match tokio::time::timeout(
        STARTUP_TIMEOUT,
        LeaderTpuService::new(rpc.clone(), "", Protocol::QUIC, exit.clone()),
    )
    .await
    {
        Ok(Ok(service)) => Ok((service, exit, true)),
        Ok(Err(e)) => Err(format!("{e}")),
        Err(_) => Err(format!(
            "timed out after {STARTUP_TIMEOUT:?} fetching leader schedule / cluster nodes from RPC"
        )),
    }
}

/// Validate, pace, send, and report on one coalesced batch.
async fn process_batch(
    pump: &Pump,
    items: Vec<Item>,
    stats: &Stats,
    out: &mpsc::UnboundedSender<String>,
) {
    let mut wires: Vec<Vec<u8>> = Vec::with_capacity(items.len());
    let mut sigs: Vec<String> = Vec::with_capacity(items.len());

    for item in items {
        match item {
            Item::Reject { head, reason } => {
                report_err(out, stats, &signature_of(&head), reason);
            }
            Item::Tx(bytes) => match first_signature(&bytes) {
                Some(sig) => {
                    wires.push(bytes);
                    sigs.push(sig);
                }
                None => report_err(out, stats, "-", "bad-sig-header"),
            },
        }
    }

    if wires.is_empty() {
        return;
    }

    let count = wires.len() as u64;
    let mut outcome = send_to_leaders(pump, &wires, stats).await;

    // The one place a batch is retried: a peer told us we hold too many
    // concurrent connections, so collapse the pool (once per process) and try
    // the batch again over the single connection that is guaranteed to fit.
    if !outcome.any_ok && outcome.saw_too_many && pump.rebuild_pool_once().await {
        outcome = send_to_leaders(pump, &wires, stats).await;
    }

    stats.batches.fetch_add(1, Ordering::Relaxed);
    if outcome.any_ok {
        stats.sent.fetch_add(count, Ordering::Relaxed);
    } else {
        warn!(
            "batch of {count} reached no leader ({} tried, {} skipped for reconnect cooldown): {}",
            outcome.attempted,
            outcome.skipped,
            outcome.last_err.as_deref().unwrap_or("no leader sockets"),
        );
        for sig in &sigs {
            report_err(out, stats, sig, "send-failed");
        }
    }
}

#[derive(Default)]
struct BatchOutcome {
    any_ok: bool,
    saw_too_many: bool,
    attempted: usize,
    skipped: usize,
    last_err: Option<String>,
}

/// Send one batch to every leader in the fanout window, sequentially, under a
/// deadline, accounting for each leader separately.
async fn send_to_leaders(pump: &Pump, wires: &[Vec<u8>], stats: &Stats) -> BatchOutcome {
    let mut outcome = BatchOutcome::default();
    let (leaders, cache) = pump.targets().await;
    if leaders.is_empty() {
        outcome.last_err = Some("leader tracker knows no TPU sockets".to_string());
        return outcome;
    }

    for addr in leaders {
        match pump.gate(&addr) {
            Gate::Reuse => {}
            Gate::Dial(reason) => {
                info!(
                    "reconnect: dialling {addr} ({}) reason={reason}",
                    pump.name_of(&addr)
                );
            }
            Gate::Skip => {
                outcome.skipped += 1;
                stats.leader_skip.fetch_add(1, Ordering::Relaxed);
                pump.with_peer(&addr, |peer| peer.skip += 1);
                debug!(
                    "skipping {addr}: last dial was under {:?} ago and the connection is down",
                    pump.reconnect_min
                );
                continue;
            }
        }

        outcome.attempted += 1;
        let conn = cache.get_nonblocking_connection(&addr);
        pump.bind_lib_stats(&conn.connection_stats);
        // Flush anything the previous leader (or the library's own metrics
        // submission inside get_nonblocking_connection) left behind, so the
        // post-send harvest belongs to this peer alone.
        pump.harvest();

        pump.log_frames(wires, &addr);
        let started = Instant::now();
        let result = timeout(pump.send_timeout, conn.send_data_batch(wires)).await;
        let elapsed = started.elapsed();
        let delta = pump.harvest();

        let n = wires.len() as u64;
        match result {
            Ok(Ok(())) => {
                outcome.any_ok = true;
                stats.leader_ok.fetch_add(1, Ordering::Relaxed);
                if delta.streams_blocked > 0 {
                    stats.credit_stalls.fetch_add(1, Ordering::Relaxed);
                }
                pump.with_peer(&addr, |peer| {
                    peer.batches += 1;
                    peer.ok += 1;
                    peer.txs_ok += n;
                    peer.connected = true;
                    peer.dialing = false;
                    absorb(peer, delta);
                });
                // What "success" means here, precisely: solana-quic-client's
                // `_send_buffer_using_conn` does `open_uni().await` then
                // `write_all(..).await` and returns. It never calls `finish()`,
                // never awaits `stopped()`, and never waits for an ack — so the
                // bytes are in quinn's send buffer, nothing more. If the peer
                // then resets the stream (a throttling STOP_SENDING, say), the
                // implicit `finish()` in `SendStream::drop` swallows it and the
                // transaction is gone with no error anywhere. STREAMS_BLOCKED /
                // DATA_BLOCKED below is the only in-band signal that the peer
                // was withholding credit while we "succeeded".
                let message = format!(
                    "leader {addr} ({}) accepted {n} tx in {elapsed:?} \
                     [unverified: the client API never awaits finish()/ack] \
                     conns={} reuse={} zrtt={}/{} sblk={} dblk={} cong={}",
                    pump.name_of(&addr),
                    delta.connections,
                    delta.reuse,
                    delta.zrtt_ok,
                    delta.zrtt_rej,
                    delta.streams_blocked,
                    delta.data_blocked,
                    delta.congestion,
                );
                if delta.is_quiet() {
                    debug!("{message}");
                } else {
                    info!("{message}");
                }
            }
            Ok(Err(e)) => {
                let text = e.to_string();
                let class = classify_transport_error(&text);
                if is_peer_connection_limit(&text) {
                    outcome.saw_too_many = true;
                }
                if class.starts_with("close:") {
                    stats.peer_closes.fetch_add(1, Ordering::Relaxed);
                }
                stats.leader_err.fetch_add(1, Ordering::Relaxed);
                outcome.last_err = Some(format!("{addr}: {text}"));
                info!(
                    "leader {addr} ({}) refused {n} tx after {elapsed:?}: {class} — {text}",
                    pump.name_of(&addr)
                );
                pump.with_peer(&addr, |peer| {
                    peer.batches += 1;
                    peer.err += 1;
                    peer.connected = false;
                    peer.dialing = false;
                    *peer.closes.entry(class).or_insert(0) += 1;
                    peer.last_err = Some(text);
                    absorb(peer, delta);
                });
            }
            Err(_) => {
                stats.leader_stall.fetch_add(1, Ordering::Relaxed);
                outcome.last_err = Some(format!("{addr}: send timed out"));
                warn!(
                    "leader {addr} ({}) stalled: send_data_batch of {n} tx did not return within {:?} \
                     (the library has no deadline here; open_uni() blocks until the peer grants \
                     stream credit) sblk={} dblk={}",
                    pump.name_of(&addr),
                    pump.send_timeout,
                    delta.streams_blocked,
                    delta.data_blocked,
                );
                pump.with_peer(&addr, |peer| {
                    peer.batches += 1;
                    peer.stall += 1;
                    peer.connected = false;
                    peer.dialing = false;
                    *peer.closes.entry("stall".to_string()).or_insert(0) += 1;
                    peer.last_err = Some("send-timeout".to_string());
                    absorb(peer, delta);
                });
            }
        }
    }

    outcome
}

fn absorb(peer: &mut Peer, delta: LibDelta) {
    peer.connections += delta.connections;
    peer.reuse += delta.reuse;
    peer.conn_errors += delta.conn_errors;
    peer.zrtt_ok += delta.zrtt_ok;
    peer.zrtt_rej += delta.zrtt_rej;
    peer.streams_blocked += delta.streams_blocked;
    peer.data_blocked += delta.data_blocked;
    peer.congestion += delta.congestion;
}

fn report_err(out: &mpsc::UnboundedSender<String>, stats: &Stats, sig: &str, reason: &str) {
    stats.err.fetch_add(1, Ordering::Relaxed);
    let _ = out.send(format!("ERR {sig} {reason}"));
}

fn signature_of(bytes: &[u8]) -> String {
    first_signature(bytes).unwrap_or_else(|| "-".to_string())
}

/// Blocking stdin framing loop, run on its own OS thread.
///
/// Frame = u32 little-endian length, then exactly that many bytes. A frame that
/// is empty or larger than `MAX_FRAME` is rejected but still fully consumed, so
/// the stream stays in sync.
fn read_frames(tx: mpsc::Sender<Item>) {
    let stdin = std::io::stdin();
    let mut stdin = stdin.lock();
    let mut header = [0u8; 4];
    let mut scratch = [0u8; 8192];

    loop {
        match read_exact_or_eof(&mut stdin, &mut header) {
            Ok(true) => {}
            Ok(false) => break, // clean EOF on a frame boundary
            Err(e) => {
                warn!("stdin read error while reading frame header: {e}");
                break;
            }
        }

        let len = u32::from_le_bytes(header) as usize;
        if len == 0 {
            if tx
                .blocking_send(Item::Reject {
                    head: Vec::new(),
                    reason: "empty-frame",
                })
                .is_err()
            {
                break;
            }
            continue;
        }

        let head_len = len.min(MAX_FRAME);
        let mut head = vec![0u8; head_len];
        match read_exact_or_eof(&mut stdin, &mut head) {
            Ok(true) => {}
            Ok(false) => {
                warn!("stdin ended mid-frame: wanted {head_len} bytes of a {len}-byte frame");
                break;
            }
            Err(e) => {
                warn!("stdin read error inside frame body: {e}");
                break;
            }
        }

        // Drain the tail of an oversize frame so framing stays aligned.
        let mut remaining = len - head_len;
        let mut truncated = false;
        while remaining > 0 {
            let want = remaining.min(scratch.len());
            match read_exact_or_eof(&mut stdin, &mut scratch[..want]) {
                Ok(true) => remaining -= want,
                Ok(false) => {
                    warn!("stdin ended while discarding an oversize {len}-byte frame");
                    truncated = true;
                    break;
                }
                Err(e) => {
                    warn!("stdin read error while discarding an oversize frame: {e}");
                    truncated = true;
                    break;
                }
            }
        }

        let item = if len > MAX_FRAME {
            Item::Reject {
                head,
                reason: "oversize",
            }
        } else {
            Item::Tx(head)
        };
        if tx.blocking_send(item).is_err() {
            break;
        }
        if truncated {
            break;
        }
    }
}

/// `Ok(true)` = buffer filled, `Ok(false)` = EOF before enough bytes arrived.
fn read_exact_or_eof<R: Read>(reader: &mut R, buf: &mut [u8]) -> std::io::Result<bool> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => return Ok(false),
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(true)
}

/// Base58 of the first signature in a wire transaction, if one is there.
fn first_signature(wire: &[u8]) -> Option<String> {
    let (count, offset) = decode_compact_u16(wire)?;
    if count == 0 {
        return None;
    }
    let sig = wire.get(offset..offset.checked_add(64)?)?;
    Some(bs58::encode(sig).into_string())
}

/// Decode a Solana `compact-u16` (ShortU16) prefix. Returns the value and the
/// number of bytes consumed. Handles the 1-, 2-, and 3-byte encodings.
fn decode_compact_u16(bytes: &[u8]) -> Option<(u16, usize)> {
    let mut value: u32 = 0;
    for index in 0..3usize {
        let byte = *bytes.get(index)?;
        let payload = u32::from(byte & 0x7f);
        if index == 2 && payload > 0x03 {
            return None; // would overflow u16
        }
        value |= payload << (index * 7);
        if byte & 0x80 == 0 {
            // Reject non-canonical encodings (a continuation that added nothing).
            if index > 0 && payload == 0 {
                return None;
            }
            return u16::try_from(value).ok().map(|v| (v, index + 1));
        }
    }
    None
}

async fn poll_cluster(rpc: Arc<RpcClient>, stats: Arc<Stats>, pump: Arc<Pump>) {
    let mut ticker = tokio::time::interval(SLOT_POLL_INTERVAL);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut last_nodes: Option<Instant> = None;
    loop {
        ticker.tick().await;

        let due = last_nodes
            .map(|at| Instant::now().saturating_duration_since(at) >= NODE_MAP_REFRESH)
            .unwrap_or(true);
        if due {
            last_nodes = Some(Instant::now());
            match rpc.get_cluster_nodes().await {
                Ok(nodes) => {
                    let mut names = match pump.names.lock() {
                        Ok(guard) => guard,
                        Err(poisoned) => poisoned.into_inner(),
                    };
                    for node in nodes {
                        if let Some(addr) = node.tpu_quic {
                            names.insert(addr, node.pubkey.clone());
                        }
                    }
                }
                Err(e) => debug!("getClusterNodes failed: {e}"),
            }
        }

        match rpc.get_slot().await {
            Ok(slot) => {
                stats.slot.store(slot, Ordering::Relaxed);
                match rpc.get_slot_leaders(slot, 1).await {
                    Ok(leaders) => {
                        if let Some(leader) = leaders.first() {
                            if let Ok(mut guard) = stats.leader.lock() {
                                *guard = Some(leader.to_string());
                            }
                        }
                    }
                    Err(e) => debug!("getSlotLeaders({slot}) failed: {e}"),
                }
            }
            Err(e) => debug!("getSlot failed: {e}"),
        }
    }
}

async fn stats_task(
    interval: Duration,
    stats: Arc<Stats>,
    pump: Arc<Pump>,
    out: mpsc::UnboundedSender<String>,
) {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    ticker.tick().await; // the first tick is immediate; skip it
    loop {
        ticker.tick().await;
        let line = pump.stat_line(&stats);
        info!("{line}");
        if out.send(line).is_err() {
            break;
        }
        for peer in pump.peer_lines() {
            info!("{peer}");
            if out.send(peer).is_err() {
                return;
            }
        }
    }
}

async fn writer_task(mut rx: mpsc::UnboundedReceiver<String>) {
    let mut stdout = tokio::io::stdout();
    while let Some(line) = rx.recv().await {
        if stdout.write_all(line.as_bytes()).await.is_err()
            || stdout.write_all(b"\n").await.is_err()
            || stdout.flush().await.is_err()
        {
            break;
        }
    }
    let _ = stdout.flush().await;
}

fn derive_ws_url(rpc: &str) -> String {
    if let Some(rest) = rpc.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = rpc.strip_prefix("http://") {
        format!("ws://{rest}")
    } else {
        rpc.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_u16_single_byte() {
        assert_eq!(decode_compact_u16(&[0x01]), Some((1, 1)));
        assert_eq!(decode_compact_u16(&[0x7f]), Some((127, 1)));
        assert_eq!(decode_compact_u16(&[0x00]), Some((0, 1)));
    }

    #[test]
    fn compact_u16_multi_byte() {
        // 128 -> 0x80 0x01
        assert_eq!(decode_compact_u16(&[0x80, 0x01]), Some((128, 2)));
        // 16384 -> 0x80 0x80 0x01
        assert_eq!(decode_compact_u16(&[0x80, 0x80, 0x01]), Some((16384, 3)));
        // Non-canonical trailing zero continuation byte.
        assert_eq!(decode_compact_u16(&[0x80, 0x00]), None);
        // Truncated.
        assert_eq!(decode_compact_u16(&[0x80]), None);
    }

    #[test]
    fn signature_extraction() {
        let mut wire = vec![0x01];
        wire.extend_from_slice(&[7u8; 64]);
        wire.extend_from_slice(&[0u8; 32]);
        assert_eq!(
            first_signature(&wire),
            Some(bs58::encode([7u8; 64]).into_string())
        );

        // Two signatures: still the first one.
        let mut wire2 = vec![0x02];
        wire2.extend_from_slice(&[9u8; 64]);
        wire2.extend_from_slice(&[3u8; 64]);
        assert_eq!(
            first_signature(&wire2),
            Some(bs58::encode([9u8; 64]).into_string())
        );

        // Compact-u16 count >= 128 (synthetic, exercises the general path).
        let mut wire3 = vec![0x80, 0x01];
        wire3.extend_from_slice(&[5u8; 64]);
        assert_eq!(
            first_signature(&wire3),
            Some(bs58::encode([5u8; 64]).into_string())
        );

        assert_eq!(first_signature(&[]), None);
        assert_eq!(first_signature(&[0x00]), None);
        assert_eq!(first_signature(&[0x01, 0x02, 0x03]), None);
    }

    #[test]
    fn ws_url_derivation() {
        assert_eq!(
            derive_ws_url("http://127.0.0.1:8899"),
            "ws://127.0.0.1:8899"
        );
        assert_eq!(
            derive_ws_url("https://api.mainnet-beta.solana.com"),
            "wss://api.mainnet-beta.solana.com"
        );
    }

    #[test]
    fn detects_peer_connection_limit() {
        assert!(is_peer_connection_limit(
            "transport custom error: \"WriteError(ConnectionLost(ApplicationClosed(ApplicationClose { error_code: 4, reason: b\\\"too_many\\\" })))\""
        ));
        assert!(!is_peer_connection_limit("transport custom error: timeout"));
    }

    #[test]
    fn classifies_peer_application_close() {
        let too_many = "transport custom error: \"WriteError(ConnectionLost(ApplicationClosed(ApplicationClose { error_code: 4, reason: b\\\"too_many\\\" })))\"";
        assert_eq!(classify_transport_error(too_many), "close:4/too_many");

        let disallowed = "Custom(\"ConnectionError(ApplicationClosed(ApplicationClose { error_code: 2, reason: b\\\"disallowed\\\" }))\")";
        assert_eq!(classify_transport_error(disallowed), "close:2/disallowed");

        let exceed = "ConnectionError(ApplicationClosed(ApplicationClose { error_code: 3, reason: b\"exceed_max_stream_count\" }))";
        assert_eq!(
            classify_transport_error(exceed),
            "close:3/exceed_max_stream_count"
        );
    }

    #[test]
    fn classifies_other_transport_failures() {
        assert_eq!(
            classify_transport_error("Custom(\"ConnectionError(TimedOut)\")"),
            "timeout"
        );
        assert_eq!(
            classify_transport_error("Custom(\"WriteError(Stopped(15))\")"),
            "stream-stopped:15"
        );
        assert_eq!(
            classify_transport_error("Custom(\"ConnectError(EndpointStopping)\")"),
            "connect-failed"
        );
        assert_eq!(
            classify_transport_error("Custom(\"ConnectionError(ConnectionClosed(ConnectionClose { error_code: NO_ERROR }))\")"),
            "transport-close"
        );
        assert_eq!(classify_transport_error("something else entirely"), "other");
    }

    #[test]
    fn gate_dials_once_then_reuses() {
        let min = Duration::from_secs(10);
        let t0 = Instant::now();
        let mut peer = Peer::default();

        assert!(matches!(peer.gate(t0, min), Gate::Dial("first-contact")));
        // A second batch racing that first contact must not be skipped: it
        // queues behind the handshake and reuses the connection.
        assert!(matches!(peer.gate(t0, min), Gate::Reuse));

        peer.dialing = false;
        peer.connected = true;
        assert!(matches!(peer.gate(t0, min), Gate::Reuse));
    }

    #[test]
    fn gate_holds_a_failed_peer_down_for_the_interval() {
        let min = Duration::from_secs(10);
        let t0 = Instant::now();
        let mut peer = Peer::default();
        assert!(matches!(peer.gate(t0, min), Gate::Dial(_)));

        // The send failed.
        peer.dialing = false;
        peer.connected = false;

        // Inside the interval the peer is skipped, not redialled, however many
        // batches ask.
        for offset in [0, 1, 5, 9] {
            let later = t0 + Duration::from_secs(offset);
            assert!(matches!(peer.gate(later, min), Gate::Skip), "at +{offset}s");
        }
        // Once it has elapsed, exactly one dial goes through.
        let later = t0 + Duration::from_secs(10);
        assert!(matches!(
            peer.gate(later, min),
            Gate::Dial("previous-attempt-failed")
        ));
        assert!(matches!(peer.gate(later, min), Gate::Reuse));
    }

    #[test]
    fn pacer_is_a_token_bucket() {
        let pacer = Pacer::new(100.0, 64.0);
        let t0 = Instant::now();
        // The bucket starts full: one burst is affordable immediately.
        assert!(pacer.try_take(64.0, t0).is_ok());
        // ...and the next one is not.
        let wait = pacer
            .try_take(64.0, t0)
            .expect_err("bucket should be empty");
        assert!(wait > Duration::from_millis(500), "{wait:?}");
        // After enough time at 100/s, 64 tokens are back.
        assert!(pacer
            .try_take(64.0, t0 + Duration::from_millis(700))
            .is_ok());
    }

    #[test]
    fn pacer_never_asks_for_more_than_the_bucket_holds() {
        let pacer = Pacer::new(50.0, 8.0);
        let t0 = Instant::now();
        // A 1000-tx ask must not deadlock: it is capped at the burst size.
        assert!(pacer.try_take(1000.0, t0).is_ok());
    }

    #[test]
    fn pacer_disabled_at_zero_rate() {
        let pacer = Pacer::new(0.0, 64.0);
        // Rate 0 means unlimited: nothing is ever refused and nothing is spent.
        for _ in 0..1000 {
            assert!(pacer.try_now(1.0));
        }
        pacer.refund(1.0);
    }

    #[test]
    fn pacer_refund_returns_an_unused_token() {
        let pacer = Pacer::new(10.0, 4.0);
        for _ in 0..4 {
            assert!(pacer.try_now(1.0));
        }
        // Bucket is empty: coalescing would stop here.
        assert!(!pacer.try_now(1.0));
        // The frame never arrived, so the token goes back and the next frame
        // is admitted immediately rather than waiting out a refill.
        pacer.refund(1.0);
        assert!(pacer.try_now(1.0));
    }

    #[test]
    fn pacer_refund_cannot_overfill_the_bucket() {
        let pacer = Pacer::new(10.0, 4.0);
        for _ in 0..100 {
            pacer.refund(1.0);
        }
        for _ in 0..4 {
            assert!(pacer.try_now(1.0));
        }
        assert!(
            !pacer.try_now(1.0),
            "refunds must not raise the burst ceiling"
        );
    }
}
