//! `tabminer`: a tabernacle node with a wallet prompt. It follows the
//! network's heaviest chain, relays blocks and transactions, and by default
//! mines and proves blocks on it.
//!
//! ```text
//! tabminer [mine] [--data DIR] [--blocks N] [--delay-blocks N] [--jobs N] [--no-mine] [options]
//! tabminer node [--data DIR] [options]
//! tabminer show [--data DIR]
//! tabminer restore [--data DIR]
//!
//! options: [--listen ADDR] [--peer ADDR]... [--seed HOST:PORT]... [--verbose] [--no-prompt]
//! ```
//!
//! With no command, `tabminer` mines. The data directory defaults to
//! `~/.tabernacle/tabminer` (`./tabminer-data` when `HOME` is unset) and
//! holds the chain, the wallet, the peer list and `tabminer.log`.
//!
//! Every command starts from the fixed mainnet genesis. `mine` and `node`
//! listen for peers on UDP (port 3737 by default), contact the seeds and
//! any `--peer`, sync to the chain with the most work, relay new blocks and
//! transactions, and save the peers they found for next time. Logs go to
//! the log file; the terminal shows a prompt for wallet and status commands
//! (type `help`), unless `--no-prompt` sends the log to the terminal
//! instead.
//!
//! `mine` additionally builds blocks on the tip (unless `--no-mine` is
//! given, which makes it the same as `node`): the pooled transactions by
//! fee rate, within the block limits, and a reward paying the subsidy plus
//! their fees to the node's wallet. Each block is proven (segments, then
//! the aggregation tree), mined, applied through full validation, and
//! announced. If the network delivers a better tip while a block is being
//! proven or mined, the miner drops it and starts over on the new tip.
//! `--blocks 0` (the default) runs until `quit`. `--jobs` bounds how many
//! segments are proven at once; the `TABMINER_THREADS` environment variable
//! bounds the threads hashing and proving use (all cores by default), for
//! a machine that also serves peers.
//!
//! The wallet is created on first run with a 12-word BIP39 phrase, shown
//! once (and by `phrase`). `restore` rebuilds a wallet from a phrase in an
//! empty data directory; once the node has synced, `scan` finds its
//! outputs on chain from their memos.
//!
//! Payments use slate files: `send` writes one for the recipient, who
//! answers it with `receive`; `finalize` on the sender's side signs it and
//! pools the transaction. `cancel` replaces an unconfirmed payment with
//! one paying the inputs back, at a higher fee. Given a `tab1…` address
//! or `@name` instead of a file, `send` goes over the message layer
//! (`docs/ONION.md`): the recipient's wallet answers at once and this one
//! finalizes, if both are online.

use std::io::{BufRead, Write};
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::SyncSender;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tabminer::aggregate::{AggregateVerifier, Progress, Statement};
use tabminer::block::{BLOCK_OUTPUT_SIZE, Block, BlockOutput, Body, HEADER_SIZE, POSITION_SIZE};
use tabminer::block_air::{SegmentWitness, pack};
use tabminer::chain::{BlockStatement, Chain, ChainParams, DEFAULT_MAX_UNDO};
use tabminer::log;
use tabminer::mempool::{DEFAULT_CAPACITY, Mempool};
use tabminer::name_air::NameWitness;
use tabminer::names::NameOp;
use tabminer::node::{Config, DEFAULT_PORT, DEFAULT_SYNC_POINT, Event, Mode, Node, Note, Outbound, SEEDS, Stats};
use tabminer::onion;
use tabminer::poseidon2::{P, digest_from_bytes, digest_to_bytes};
use tabminer::pow::{Dataset, Digest, Nonce, PowOutput, SeedText, Target, hashimoto, nonce_from_u64};
use tabminer::transaction::{Output, Sig, Transaction, UnsignedTransaction};
use tabminer::utxo;
use tabminer::wallet::{Ask, Fee, Incoming, Signed, Slate, State, Wallet};

type AnyResult<T> = Result<T, Box<dyn std::error::Error>>;

const USAGE: &str = "usage:
  tabminer [mine] [--data DIR] [--blocks N] [--delay-blocks N] [--jobs N] [--no-mine] [options]
  tabminer node [--data DIR] [options]
  tabminer show [--data DIR]
  tabminer restore [--data DIR]     rebuild a wallet from its 12-word phrase

  --data DIR        chain, wallet and log directory (default ~/.tabernacle/tabminer,
                    or tabminer-dev / tabminer-dev-recursive beside it)
  --network NAME    mainnet (default); dev: a test chain of its own with a block a
                    second, proofs checked segment by segment (no chain proof),
                    the proof-of-work dataset built in;
                    dev-recursive: the same with the mainnet proof path at the
                    smallest parameters (about six seconds a block, every ten
                    seconds). Dev coins are worth nothing. Both need
                    a build with `--features dev`
  --blocks N        blocks to mine, 0 for no limit (default 0)
  --delay-blocks N  wait N seconds after each block mined before starting the
                    next (default 0): slower blocks, for a test network whose
                    nodes are far apart (the difficulty follows)
  --jobs N          segments proven at once (default 2)
  TABMINER_THREADS=N  (environment) threads for hashing and proving, all
                    cores by default; fewer leaves the node responsive to
                    peers while it mines
  --no-mine         follow the chain without mining (same as the node command)

options:
  --listen ADDR     UDP address to listen on (default 0.0.0.0:3737)
  --peer ADDR       a peer to contact, host:port; may repeat
  --seed HOST:PORT  an extra seed node to resolve; may repeat
  --no-seeds        do not contact the built-in seed nodes (for a local network)
  --test-relays FILE  (dev builds, dev networks) the relays of FILE, an
                    onion-mode consensus.txt, stand as if it were in force: for
                    tests of onion mode that cannot wait for a boundary
  --relay           relay for others on the message layer (docs/ONION.md); prints
                    this node's `relay` line for consensus.txt at startup. The
                    relay's key is derived from the wallet's phrase, apart from
                    the wallet's own address
  --max-sessions N  a relay's caps, sized to its memory (docs/SCALING.md):
  --max-hops N      sessions it holds (10000), circuit hops through it (16384)
  --max-channels N  and channels open at once (4096)
  --no-wallet       run without a wallet (implies --no-mine): no payments, no
                    names, no part in the message layer but as a relay. With
                    --relay the relay key's seed is written once from the
                    wallet's phrase to DIR/relay.key, and the wallet is not
                    read again: keep the phrase elsewhere and remove DIR/wallet
  --sync-point N    when starting from genesis, fast-sync from the state N blocks
                    below the best header, checked by that block's chain proof
                    (default 144); 0 replays every block instead
  --max-undo-blocks N  keep undo records and bodies for the last N blocks
                    (default 1008, a week); older blocks keep only their
                    headers. Deeper reorganizations are refused, and snapshots
                    are served only within them; 0 keeps everything (archive)
  --min-fee N       pool and relay only transactions paying at least N base
                    units a byte (default 10, 10^-9 coins; docs/FEES.md); the
                    dust limit follows. Announced to peers
  --fee-half-life H the pool's raised minimum falls halfway back to the floor
                    in H hours (default 12)
  --mempool-expiry D  drop a transaction waiting D days unconfirmed, and refuse
                    it for as long again (default 14)
  --reserve P       give P% of each mined block's space for transactions to
                    the longest-waiting ones, oldest first, whatever they pay
                    (default 10; 0 takes all by fee rate)
  --verbose         log every network message handled
  --no-prompt       no wallet prompt; log to the terminal instead of the file
  --password-file FILE  the wallet's password, the file's first line: for a
                    locked wallet started with --no-prompt (a new wallet
                    started so is locked under it, or left unlocked without it)

debugging (a node so started can be fed any block; never use with real funds):
  --debug-no-validate-proofs  accept block proofs without checking them, and
                    mine without proving (a 205 KB stand-in instead); only on a
                    data directory of its own, which is marked unchecked for good
  --debug-fill N[,S]  with the above, fill each mined block with N random
                    outputs and spend S of the earlier ones at random (default
                    S = 0), up to the block size limit: for simulating large
                    blocks and a large state
  --debug-fill-names N  with the above, start with N synthetic names in the
                    registry behind genesis (the same N on every node of the
                    network, on the first start only): for testing names at
                    scale
  --debug-fill-outputs N[,K]  with the above, start with N synthetic outputs in
                    the set behind genesis, one every K positions (default 5;
                    the rest as if spent), the same on every node of the
                    network, on the first start only: for testing a large
                    state without mining it
  --debug-genesis-outputs N[,K]  with the above, start with the genesis of a
                    chain so filled but without the outputs: a fresh node to
                    fast-sync such a chain";

const HELP: &str = "commands:
  status                    chain tip, peers, mempool, wallet totals
  peers                     known peers
  mempool                   pooled transactions
  balance                   confirmed, pending, reserved and locked funds
  outputs                   the wallet's outputs
  send AMOUNT [FEE] TO [named]
                            pay TO, a tab1… address, @NAME or @LABEL.NAME: the slate
                            goes over the message layer, where the recipient's wallet
                            answers it and this one finalizes it, if both are online
                            (FEE: coins, N/byte, or block, hour (the default), day:
                            the rate this node's pool suggests for that wait, or
                            economy: its minimum, waiting for the aged reserve); the
                            recipient learns nothing of the sender unless it adds
                            `named`, which puts this wallet's address in the slate
                            and so in the receipt
  send-file AMOUNT [FEE] FILE [named]
                            start a payment by file: write the slate to FILE for the
                            recipient to `receive`, then `finalize` its answer
  receive FILE [OUT]        answer a slate: add your output (writes OUT, default FILE.received)
  finalize FILE             sign an answered slate and pool the transaction
                            (a slate is text, `-----BEGIN TAB SLATE-----` and base64,
                            to copy and paste or keep in a file; FILE `-` is the
                            terminal: printed, or pasted up to its END line)
  cancel ID [FEE]           abandon a pending slate (freeing its inputs), or replace
                            an unconfirmed payment with one paying its inputs back
                            (FEE as for send, at least the smallest replacement)
  slates                    pending slates
  sent                      unconfirmed payments that can be cancelled
  bump TXID [FEE]           pay an unconfirmed payment's recipient the same with a
                            higher fee, from its change (FEE defaults to block)
  fees                      the fee rates this node's pool suggests, from what it
                            has seen confirm
  resend TXID               send an unconfirmed payment again, as signed (after a
                            restart dropped it, or a reorganization moved its inputs)
  payments                  payments and burns made, where they landed, and whether
                            their proofs are ready
  payment-proof TXID [FILE] a payment's proof (docs/PROOFS.md): the block that made the
                            recipient's output, its path there, and the recipient's
                            receipt; printed as text to paste, or written to FILE
  burn AMOUNT PURPOSE [FOR] [FEE]
                            burn AMOUNT: an output nobody can spend, whose memo names
                            FOR (a tab1… address or @NAME, default this wallet) and
                            PURPOSE (one word, up to 255 bytes)
  burn-proof TXID [FILE]    a burn's proof, as payment-proof
  verify-proof [FILE]       check a payment proof or proof of burn, from FILE or pasted
                            at the prompt, against this node's chain: what it shows,
                            and its block's confirmations
  scan                      find this wallet's outputs and names on chain (after a restore)
  prune                     forget unspent outputs the chain does not hold, and name
                            commits that never reached it
  name-commit NAME [VALUE] [FEE]
                            start registering NAME: pool a transaction committing to it
                            (VALUE: a tab1… address or 64 hex digits, the id payments
                            to @NAME go to; default this wallet's address)
  name-reveal NAME [WAIT] [FEE]
                            reveal a committed name once its commit is WAIT blocks old
                            (at least 12; more makes the registration harder to undo)
  name-update NAME VALUE [FEE]
                            change a name's value, rotating its owner key
  name-offer NAME FILE [VALUE]
                            write a record for NAME under a key of yours, for its owner
                            to sign over with name-transfer: an offer, as text
                            (-----BEGIN TAB NAME OFFER-----); FILE `-` prints it
  name-transfer FILE [FEE]  sign a name over to the offer in FILE (`-`: pasted)
  names                     this wallet's names and pending commits
  name NAME                 look a name up on chain
  subname issuer ADDRESS…   let up to 3 issuers (tab1… addresses or @NAMEs) sign
                            certificates for the sub-names of every name pointing at
                            this wallet's address (docs/SUBNAME_CERT.md), so this
                            wallet can stay offline; the delegation is signed for a
                            week and renewed daily while this wallet runs
  subname issuer none       sign this wallet's sub-names itself only
  subname set LABEL.NAME TO give LABEL.NAME to TO (a tab1… address or @NAME): sign a
                            certificate (for a week, renewed daily while this wallet
                            runs) and send it to TO, whose node publishes it; for this
                            wallet's own names, or any whose delegation names it
  subname del LABEL.NAME    withdraw a sub-name, at once
  subnames                  the issuers, the sub-names this wallet issued, and those
                            it holds
  set-leaf INDEX FILE       set aux leaf INDEX (0 to 15) to the SHA-256 of FILE:
                            their Merkle root goes in the headers this node mines
  set-leaf-value INDEX HEX  set aux leaf INDEX to a 32-byte value given in hex
  leaves                    the aux leaves and their root
  consensus                 the consensus file in force (docs/ONION.md), decided at the
                            last 144-block boundary, any switch under way, and the
                            running count for the next boundary
  policies                  this wallet's policy outputs: multisigs, channels
  channel-key [HEIGHT]      a fresh channel key for a policy: its nonce and key
                            hash (HEIGHT levels, 16 by default, 20 at most)
  address                   this wallet's tab1… address (the hash of its Dilithium key)
                            and, on a relay, the relay's id: a different one
  address next              move to a new address (docs/PRIVACY.md): sessions open at
                            its rendezvous points, then the old address's close, and
                            it answers nothing again; a restore starts on a new one
  address off               close the address's sessions: the wallet can pay but
                            nobody can reach it, until address next
  phrase                    show the wallet's 12-word recovery phrase (asks the
                            password of a locked wallet)
  password                  lock the wallet's phrase under a password, change it,
                            or remove it (an empty new one); the password is
                            asked at every start
  storage                   disk use of the chain database, part by part
  quit                      stop the node
amounts are coins with up to ten decimals, e.g. 1.5";

/// LMDB map size: 1 TiB. It is only an upper bound, reserved as address
/// space: the file grows as data is written (a Bitcoin-sized output set
/// takes about 36 GB) and is never allocated ahead.
const MAP_SIZE: usize = 1 << 40;

/// Size of the stand-in proof a debugging miner attaches: about a real one.
const DEBUG_PROOF_SIZE: usize = 205_000;
/// Room a block template leaves for its proof (about 205 KB).
const PROOF_SIZE_ALLOWANCE: usize = 256 << 10;

/// How long the miner waits for its node's verdict on a block it mined
/// (the tip, a side block, or refused) before moving on: only a guard, as
/// a slow machine serving a fast sync can take minutes to apply a full
/// block, which is no reason to give the block up.
const ACCEPT_TIMEOUT: Duration = Duration::from_secs(600);

/// Which chain a node is on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Network {
    Mainnet,
    /// Rapid blocks for testing: direct proofs, a block a second.
    Dev,
    /// The mainnet proof path at the smallest parameters.
    DevRecursive,
}

impl Network {
    fn params(self) -> ChainParams {
        match self {
            Network::Mainnet => ChainParams::MAINNET,
            Network::Dev => ChainParams::DEV,
            Network::DevRecursive => ChainParams::DEV_RECURSIVE,
        }
    }

    /// The default data directory's name, under ~/.tabernacle.
    fn dir_name(self) -> &'static str {
        match self {
            Network::Mainnet => "tabminer",
            Network::Dev => "tabminer-dev",
            Network::DevRecursive => "tabminer-dev-recursive",
        }
    }
}

struct Args {
    command: String,
    network: Network,
    data: PathBuf,
    blocks: u64,
    /// Seconds the miner waits after each block it mines.
    delay_blocks: u64,
    jobs: usize,
    no_mine: bool,
    no_prompt: bool,
    listen: SocketAddr,
    peers: Vec<SocketAddr>,
    seeds: Vec<String>,
    verbose: bool,
    sync_point: u32,
    max_undo: u32,
    /// The pool's policy (`docs/FEES.md`): the relay floor, the rolling
    /// minimum's half-life and the expiry.
    min_fee: u64,
    fee_half_life_hours: u64,
    mempool_expiry_days: u64,
    reserve_percent: usize,
    no_seeds: bool,
    /// Relay for others on the message layer (`docs/ONION.md`).
    relay: bool,
    /// A relay's caps (`docs/SCALING.md`).
    max_sessions: usize,
    max_hops: usize,
    max_channels: usize,
    /// Run without a wallet; implies `no_mine`.
    no_wallet: bool,
    /// Dev builds: a consensus file whose relays stand as if it were in
    /// force (`--test-relays`), for tests of onion mode on a dev network.
    #[cfg_attr(not(feature = "dev"), allow(dead_code))]
    test_relays: Option<String>,
    /// Where the wallet's password is read from with `no_prompt`.
    password_file: Option<PathBuf>,
    debug_unchecked: bool,
    /// Random outputs to add, and earlier ones to spend, per mined block.
    debug_fill: Option<(usize, usize)>,
    /// Synthetic names to start the registry with.
    debug_fill_names: usize,
    debug_fill_outputs: u64,
    debug_genesis_outputs: u64,
    /// One filled output every this many positions.
    debug_fill_spacing: u64,
}

fn parse_args() -> Result<Args, String> {
    let mut it = std::env::args().skip(1).peekable();
    // No command, or only options, means `mine`.
    let command = match it.peek() {
        Some(c) if !c.starts_with('-') => it.next().unwrap(),
        _ => "mine".to_string(),
    };
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let data = home.map(|h| h.join(".tabernacle").join("tabminer")).unwrap_or_else(|| PathBuf::from("tabminer-data"));
    let mut data_given = false;
    let mut a = Args {
        command,
        network: Network::Mainnet,
        data,
        blocks: 0,
        delay_blocks: 0,
        jobs: 2,
        no_mine: false,
        no_prompt: false,
        listen: SocketAddr::from(([0, 0, 0, 0], DEFAULT_PORT)),
        peers: Vec::new(),
        seeds: Vec::new(),
        verbose: false,
        sync_point: DEFAULT_SYNC_POINT,
        max_undo: DEFAULT_MAX_UNDO,
        min_fee: tabminer::mempool::MIN_FEE_PER_BYTE,
        fee_half_life_hours: tabminer::mempool::HALF_LIFE_SECS / 3600,
        mempool_expiry_days: tabminer::mempool::EXPIRY_SECS / 86400,
        reserve_percent: tabminer::mempool::RESERVE_PERCENT,
        no_seeds: false,
        relay: false,
        max_sessions: tabminer::node::MAX_SESSIONS,
        max_hops: tabminer::node::MAX_HOPS,
        max_channels: tabminer::node::MAX_CHANNELS,
        no_wallet: false,
        test_relays: None,
        password_file: None,
        debug_unchecked: false,
        debug_fill: None,
        debug_fill_names: 0,
        debug_fill_outputs: 0,
        debug_genesis_outputs: 0,
        debug_fill_spacing: 5,
    };
    while let Some(flag) = it.next() {
        let mut value = || it.next().ok_or(format!("{flag} needs a value"));
        let number = |v: String| v.parse::<u64>().map_err(|_| format!("{flag}: not a number: {v}"));
        match flag.as_str() {
            "--data" => {
                a.data = PathBuf::from(value()?);
                data_given = true;
            }
            "--network" => {
                a.network = match value()?.as_str() {
                    "mainnet" => Network::Mainnet,
                    "dev" => Network::Dev,
                    "dev-recursive" => Network::DevRecursive,
                    other => return Err(format!("--network: unknown network {other} (mainnet, dev or dev-recursive)")),
                };
                if a.network != Network::Mainnet && !cfg!(feature = "dev") {
                    return Err("the dev networks need a build with them: cargo build --release --features dev".into());
                }
            }
            "--blocks" => a.blocks = number(value()?)?,
            "--delay-blocks" => a.delay_blocks = number(value()?)?,
            "--jobs" => a.jobs = number(value()?)?.max(1) as usize,
            "--no-mine" => a.no_mine = true,
            "--no-prompt" => a.no_prompt = true,
            "--password-file" => a.password_file = Some(PathBuf::from(value()?)),
            "--listen" => {
                let v = value()?;
                a.listen = v.parse().map_err(|_| format!("--listen: not an address: {v}"))?;
                if !a.listen.is_ipv4() {
                    return Err(format!("--listen {v}: IPv6 is not supported; give an IPv4 address"));
                }
            }
            "--peer" => {
                let v = value()?;
                // Every IPv4 address it resolves to (IPv6 is not spoken).
                let before = a.peers.len();
                a.peers.extend(v.to_socket_addrs().map_err(|e| format!("--peer {v}: {e}"))?.filter(|a| a.is_ipv4()));
                if a.peers.len() == before {
                    return Err(format!("--peer {v}: no IPv4 address (IPv6 is not supported)"));
                }
            }
            "--seed" => a.seeds.push(value()?),
            "--no-seeds" => a.no_seeds = true,
            "--relay" => a.relay = true,
            #[cfg(feature = "dev")]
            "--test-relays" => a.test_relays = Some(value()?),
            "--max-sessions" => a.max_sessions = number(value()?)?.max(1) as usize,
            "--max-hops" => a.max_hops = number(value()?)?.max(1) as usize,
            "--max-channels" => a.max_channels = number(value()?)?.max(1) as usize,
            // No wallet, so no reward to pay: never mining.
            "--no-wallet" => {
                a.no_wallet = true;
                a.no_mine = true;
            }
            "--debug-no-validate-proofs" => a.debug_unchecked = true,
            "--debug-fill" => {
                let v = value()?;
                let (n, s) = v.split_once(',').unwrap_or((&v, "0"));
                a.debug_fill = Some((number(n.to_string())? as usize, number(s.to_string())? as usize));
            }
            "--debug-fill-names" => a.debug_fill_names = number(value()?)? as usize,
            "--debug-fill-outputs" | "--debug-genesis-outputs" => {
                let v = value()?;
                let (n, k) = v.split_once(',').unwrap_or((&v, "5"));
                let n = number(n.to_string())?;
                a.debug_fill_spacing = number(k.to_string())?.max(1);
                if flag == "--debug-fill-outputs" {
                    a.debug_fill_outputs = n;
                } else {
                    a.debug_genesis_outputs = n;
                }
            }
            "--verbose" => a.verbose = true,
            "--sync-point" => a.sync_point = number(value()?)? as u32,
            "--min-fee" => a.min_fee = number(value()?)?,
            "--fee-half-life" => a.fee_half_life_hours = number(value()?)?.max(1),
            "--mempool-expiry" => a.mempool_expiry_days = number(value()?)?.max(1),
            "--reserve" => a.reserve_percent = (number(value()?)? as usize).min(100),
            "--max-undo-blocks" => a.max_undo = number(value()?)? as u32,
            "-h" | "--help" => return Err(String::new()),
            _ => return Err(format!("unknown option {flag}")),
        }
    }
    // A dev network differs from mainnet in its chain only: its own data
    // directory, so the two never share a chain or a wallet, and otherwise
    // the same port and seeds (a node of the other chain is refused at the
    // handshake, by its genesis).
    if a.network != Network::Mainnet && !data_given {
        a.data = a.data.with_file_name(a.network.dir_name());
    }
    let fills = a.debug_fill_names > 0 || a.debug_fill_outputs > 0 || a.debug_genesis_outputs > 0;
    if (a.debug_fill.is_some() || fills) && !a.debug_unchecked {
        return Err("the --debug-fill flags need --debug-no-validate-proofs: such a chain cannot be proven".into());
    }
    if a.debug_fill_outputs > 0 && a.debug_genesis_outputs > 0 {
        return Err("--debug-fill-outputs and --debug-genesis-outputs: one or the other".into());
    }
    Ok(a)
}

fn main() {
    tabminer::parallel::limit_arenas();
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            if !e.is_empty() {
                eprintln!("error: {e}\n");
            }
            eprintln!("{USAGE}");
            std::process::exit(2);
        }
    };
    let result = match args.command.as_str() {
        "mine" => run(&args, !args.no_mine),
        "node" => run(&args, false),
        "show" => show(&args),
        "restore" => restore(&args),
        other => {
            eprintln!("error: unknown command {other}\n\n{USAGE}");
            std::process::exit(2);
        }
    };
    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn hex(d: &Digest) -> String {
    digest_to_bytes(d).iter().map(|b| format!("{b:02x}")).collect()
}

fn short(d: &Digest) -> String {
    hex(d)[..16].to_string()
}

fn secs(d: Duration) -> String {
    format!("{:.2}s", d.as_secs_f64())
}

/// Coins as whole units with all their decimals.
fn fmt_coins(amount: u128) -> String {
    let coin = tabminer::chain::COIN as u128;
    format!("{}.{:0width$}", amount / coin, amount % coin, width = tabminer::chain::DECIMALS)
}

/// Parses coins with up to [`tabminer::chain::DECIMALS`] decimals into
/// base units.
fn parse_coins(s: &str) -> Option<u64> {
    let places = tabminer::chain::DECIMALS;
    let (whole, frac) = s.split_once('.').unwrap_or((s, ""));
    if whole.is_empty() && frac.is_empty() || frac.len() > places || !frac.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let whole: u64 = if whole.is_empty() { 0 } else { whole.parse().ok()? };
    let frac: u64 = if frac.is_empty() { 0 } else { format!("{frac:0<places$}").parse().ok()? };
    whole.checked_mul(tabminer::chain::COIN)?.checked_add(frac)
}

/// Expected hashes to meet `target`: `2^248 / (target + 1)`, as log2.
fn work_bits(target: &Target) -> f64 {
    let t = target.0.iter().rev().fold(0f64, |acc, b| acc * 256.0 + *b as f64);
    248.0 - (t + 1.0).log2()
}

fn open_chain(args: &Args, params: ChainParams, seed: SeedText) -> AnyResult<Arc<Chain<AggregateVerifier>>> {
    std::fs::create_dir_all(args.data.join("chain"))?;
    let genesis = tabminer::aggregate::Genesis::of(&params.genesis().header, &seed);
    let mut verifier = AggregateVerifier::new(params.aggregator, params.emission, genesis);
    if args.debug_unchecked {
        verifier = verifier.unchecked();
    }
    let chain = Chain::open(&args.data.join("chain"), MAP_SIZE, params, seed, verifier)?
        .with_max_undo((args.max_undo > 0).then_some(args.max_undo));
    chain.init_or_check_genesis()?;
    // A data directory is checked or unchecked for good: unchecked blocks
    // must never pass for verified ones, nor a verified chain take
    // unchecked blocks.
    let marker = args.data.join("unchecked");
    let past_genesis = chain.tip()?.is_some_and(|t| t.height > 0);
    match (args.debug_unchecked, marker.exists()) {
        (true, false) if past_genesis => {
            return Err(format!(
                "{} holds a verified chain: --debug-no-validate-proofs needs a data directory of its own",
                args.data.display()
            )
            .into());
        }
        (true, false) => std::fs::write(&marker, "blocks here were taken without checking their proofs\n")?,
        (false, true) => {
            return Err(format!(
                "{} was run with --debug-no-validate-proofs: its blocks were never checked; \
                 use another data directory, or the flag again",
                args.data.display()
            )
            .into());
        }
        _ => {}
    }
    // Outputs before names: the names fill keeps the outputs' root.
    for (n, header_only) in [(args.debug_fill_outputs, false), (args.debug_genesis_outputs, true)] {
        if n == 0 {
            continue;
        }
        let (t, logged) = (Instant::now(), std::cell::Cell::new(0));
        chain.debug_fill_outputs(n, args.debug_fill_spacing, header_only, &|done| {
            // About every ten million.
            if done / 10_000_000 > logged.get() {
                logged.set(done / 10_000_000);
                log::line(&format!("debug: {done} outputs filled in {}", secs(t.elapsed())));
            }
        })?;
        let what = if header_only { "the genesis of" } else { "a set filled with" };
        log::line(&format!("debug: {what} {n} outputs ready in {}", secs(t.elapsed())));
    }
    if args.debug_fill_names > 0 {
        let t = Instant::now();
        chain.debug_fill_names(args.debug_fill_names, &|done| {
            if done.is_multiple_of(1_000_000) {
                log::line(&format!("debug: {done} names filled in {}", secs(t.elapsed())));
            }
        })?;
        log::line(&format!("debug: the registry holds {} names", args.debug_fill_names));
    }
    Ok(Arc::new(chain))
}

fn net_config(args: &Args) -> Config {
    Config {
        listen: args.listen,
        peers: args.peers.clone(),
        seeds: if args.no_seeds { Vec::new() } else { SEEDS.iter().map(|s| s.to_string()).collect() }
            .into_iter()
            .chain(args.seeds.iter().cloned())
            .collect(),
        peers_file: Some(args.data.join("peers")),
        verbose: args.verbose,
        relay: args.relay,
        identity: None,
        wallet: false,
        relay_key: None,
        max_sessions: args.max_sessions,
        max_hops: args.max_hops,
        max_channels: args.max_channels,
        sync_point: (args.sync_point > 0).then_some(args.sync_point),
    }
}

fn show(args: &Args) -> AnyResult<()> {
    let params = args.network.params();
    let chain = open_chain(args, params, SeedText::new(params.pow))?;
    let Some(tip) = chain.tip()? else {
        println!("no chain in {}", args.data.display());
        return Ok(());
    };
    println!("{:>6}  {:16}  {:>19}  {:>6} {:>7}  {:>9}", "height", "id", "time", "inputs", "outputs", "proof");
    for h in 0..=tip.height {
        let header = chain.header_at(h)?.ok_or("missing header")?;
        match chain.body_by_hash(&header.hash())? {
            Some(body) => println!(
                "{:>6}  {}  {:>19}  {:>6} {:>7}  {:>6} KB",
                h,
                short(&header.hash()),
                header.timestamp,
                body.inputs.len(),
                body.outputs.len(),
                body.proof.len() / 1000
            ),
            // Below a fast-sync snapshot or the undo window only headers
            // are kept.
            None => println!("{:>6}  {}  {:>19}  (header only)", h, short(&header.hash()), header.timestamp),
        }
    }
    if let Some(floor) = chain.floor()? {
        println!("fast-synced from the state after block {floor}, verified by its chain proof");
    }
    println!(
        "tip {} at height {}, state root {}, work 2^{:.1}",
        hex(&tip.hash()),
        tip.height,
        short(&tip.state_root),
        log2_u256(chain.tip_work()?)
    );
    Ok(())
}

fn log2_u256(w: tabminer::difficulty::U256) -> f64 {
    // Genesis alone has no work; show 2^0 rather than 2^-inf.
    w.0.iter().rev().fold(0f64, |acc, l| acc * 2f64.powi(64) + *l as f64).max(1.0).log2()
}

/// Everything the prompt and the miner share.
struct Ctx {
    params: ChainParams,
    chain: Arc<Chain<AggregateVerifier>>,
    mempool: Arc<Mutex<Mempool>>,
    /// `None` with `--no-wallet`.
    wallet: Option<Arc<Wallet>>,
    events: SyncSender<Event>,
    stats: Arc<Mutex<Stats>>,
    tip_changes: Arc<AtomicU64>,
    /// The last block of ours the node refused, and why.
    refused: Arc<Mutex<Option<(tabminer::pow::Digest, String)>>>,
    syncing: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    mining: bool,
    /// Started with `--relay`.
    relay: bool,
    /// The relay's `tab1…` id, with `--relay`.
    relay_address: Option<String>,
    /// Debugging: random outputs to add and earlier ones to spend per block.
    debug_fill: Option<(usize, usize)>,
    /// Bytes of each block mined for the aged reserve (`--reserve`).
    reserve_bytes: usize,
    /// The reward output of the block being mined, forgotten on quit.
    in_flight: Mutex<Option<tabminer::transaction::Commitment>>,
    /// Slates sent over the message layer and not yet answered: the
    /// recipient's id by the slate's.
    outgoing: Mutex<std::collections::HashMap<[u8; 32], Digest>>,
    /// Whether a prompt is on the terminal (else the log is).
    prompt: bool,
    /// Stage-1 slates answered lately, to refuse a flood.
    slates: Mutex<onion::SlateLimit>,
    /// The wallet's sub-names, and the file they are kept in.
    subnames: Mutex<Subnames>,
    subnames_file: std::path::PathBuf,
    /// Sub-name lookups waiting on the message layer.
    waiting: Mutex<std::collections::HashMap<Wait, std::sync::mpsc::Sender<Note>>>,
    /// Answers and delegations resolved lately, until they expire.
    resolved: Mutex<Resolved>,
    /// The certificates this wallet issued lately, by name and label.
    issued: Mutex<std::collections::HashMap<(Vec<u8>, Vec<u8>), Issued>>,
    /// This wallet's delegation as last signed: when, for which issuers,
    /// and its bytes.
    delegation: Mutex<Option<(u64, Vec<Digest>, Vec<u8>)>>,
    /// One pass of `publish_subnames` at a time.
    issuing: Mutex<()>,
}

/// A certificate this wallet issued: when, under which send tag, and
/// whether it reached its holder.
struct Issued {
    bundle: tabminer::subnames::Bundle,
    at: u64,
    tag: u64,
    delivered: bool,
}

impl Ctx {
    /// The wallet, or why there is none.
    fn wallet(&self) -> AnyResult<&Wallet> {
        self.wallet.as_deref().ok_or_else(|| "this node runs with --no-wallet".into())
    }
}

/// Runs the node, the miner if `mining`, and the prompt (or waits) until
/// `quit`.
fn run(args: &Args, mining: bool) -> AnyResult<()> {
    let params = args.network.params();
    std::fs::create_dir_all(&args.data)?;
    let log_path = args.data.join("tabminer.log");
    log::init(Some(&log_path), args.no_prompt)?;
    if !args.no_prompt {
        println!("logging to {}", log_path.display());
    }
    log::line(&format!("tabminer starting in {}", args.data.display()));
    if args.network != Network::Mainnet {
        let msg = format!(
            "network {:?}: a test chain of its own, a block every {} s; its coins are worth nothing",
            args.network, params.schedule.block_time
        );
        log::line(&msg);
        if !args.no_prompt {
            println!("{msg}");
        }
    }

    let seed = SeedText::new(params.pow);
    let dataset = if mining {
        let t = Instant::now();
        let path = args.data.join("dataset");
        if !path.exists() {
            let msg = format!(
                "generating the {} MB proof-of-work dataset (once per data directory)...",
                params.pow.dataset_bytes() >> 20
            );
            if !args.no_prompt {
                println!("{msg}");
            }
            log::line(&msg);
        }
        let dataset = Dataset::load_or_generate(&seed, &path)?;
        log::line(&format!("dataset: {} MB ready in {}", params.pow.dataset_bytes() >> 20, secs(t.elapsed())));
        Some(Arc::new(dataset))
    } else {
        None
    };
    let chain = open_chain(args, params, seed.clone())?;
    // Header checks use the full dataset: a miner has it already; a node
    // loads it, or builds it once in the background (checking headers
    // from the seed text meanwhile, at tens of milliseconds each).
    match &dataset {
        Some(d) => chain.set_dataset(Arc::clone(d)),
        None => {
            let chain = Arc::clone(&chain);
            let path = args.data.join("dataset");
            std::thread::Builder::new().name("dataset".into()).spawn(move || {
                let t = Instant::now();
                match Dataset::load_or_generate(&seed, &path) {
                    Ok(d) => {
                        chain.set_dataset(Arc::new(d));
                        log::line(&format!("proof-of-work dataset ready in {}", secs(t.elapsed())));
                    }
                    Err(e) => log::line(&format!("proof-of-work dataset: {e}; checking headers from the seed text")),
                }
            })?;
        }
    }
    let pruned = chain.prune_undo()?;
    if pruned > 0 {
        log::line(&format!("pruned {pruned} undo records beyond the last {} blocks", args.max_undo));
    }
    // Peers keep a snapshot manifest for every block in their undo window.
    let served = DEFAULT_MAX_UNDO;
    if args.sync_point > served {
        log::line(&format!(
            "warning: --sync-point {} is deeper than the {served} blocks peers surely keep snapshots for: \
             a fast sync may use the deepest snapshot they keep instead",
            args.sync_point
        ));
    }
    if args.debug_unchecked {
        let msg = "DEBUG: block proofs are not checked and mined blocks are not proven; \
                   this node accepts any block and its blocks are refused by every other node";
        if !args.no_prompt {
            println!("{msg}");
        }
        log::line(msg);
    }
    if mining && chain.verifier().needs_plan() {
        // The miner proves membership of its wrap in the plan of every
        // segment count: built into the binary, else planned (a minute).
        let t = Instant::now();
        if !chain.verifier().plan_is_built_in() {
            let msg = "planning every segment count for the chain proofs...";
            if !args.no_prompt {
                println!("{msg}");
            }
            log::line(msg);
        }
        chain.verifier().plan_tree();
        log::line(&format!("plan ready in {}", secs(t.elapsed())));
    }
    // A relay without a wallet keeps only its relay key's seed, in
    // DIR/relay.key, written once from the wallet's phrase.
    let relay_file = args.data.join("relay.key");
    let relay_seed = if args.no_wallet && args.relay { read_relay_seed(&relay_file)? } else { None };
    // The wallet, unless --no-wallet; a relay derives its key from the
    // phrase the first time.
    let opened = if args.no_wallet && (!args.relay || relay_seed.is_some()) {
        None
    } else {
        let dir = args.data.join("wallet");
        let mut tries = if args.no_prompt || args.password_file.is_some() { 1 } else { 3 };
        let (wallet, created) = loop {
            tries -= 1;
            match Wallet::open_with(&dir, &mut |ask| wallet_password(args, ask)) {
                Err(tabminer::wallet::WalletError::WrongPassword) if tries > 0 => println!("wrong password"),
                r => break r?,
            }
        };
        if let Some(phrase) = created {
            log::line("created a new wallet");
            println!("\nnew wallet; its recovery phrase is:\n\n    {phrase}\n");
            if args.no_wallet {
                println!("write it down: it restores this relay's id; keep no funds in it\n");
            } else {
                println!("write it down and keep it safe: it is the only way to restore the wallet's funds\n");
            }
        }
        Some(wallet)
    };
    let policy = tabminer::mempool::Policy {
        half_life_secs: args.fee_half_life_hours * 3600,
        expiry_secs: args.mempool_expiry_days * 86400,
        ..tabminer::mempool::Policy::with_floor(args.min_fee)
    };
    let mempool = Arc::new(Mutex::new(Mempool::with_policy(DEFAULT_CAPACITY, policy)));
    let mut config = net_config(args);
    config.relay_key = match (relay_seed, opened.as_ref()) {
        _ if !args.relay => None,
        (Some(seed), _) => Some(tabminer::wallet::relay_key_from(&seed)),
        (None, Some(w)) if args.no_wallet => {
            write_relay_seed(&relay_file, &w.relay_seed())?;
            let msg = format!(
                "relay key saved in {}; this relay no longer reads its wallet: keep the phrase, and remove {} from the server",
                relay_file.display(),
                args.data.join("wallet").display()
            );
            log::line(&msg);
            if !args.no_prompt {
                println!("{msg}");
            }
            Some(w.relay_key())
        }
        (None, w) => w.map(|w| w.relay_key()),
    };
    let relay_address = config.relay_id().map(|id| tabminer::address::encode(&id));
    let wallet = if args.no_wallet { None } else { opened.map(Arc::new) };
    config.identity = wallet.as_ref().filter(|w| !w.address_off()).map(|w| w.identity_key());
    config.wallet = wallet.is_some();
    let (mut node, events) = Node::bind(Arc::clone(&chain), Arc::clone(&mempool), config)?;
    // Dev builds on a dev network: the relays of a file as if it were in
    // force, for tests of onion mode that cannot wait for a boundary.
    #[cfg(feature = "dev")]
    if let Some(file) = &args.test_relays {
        if !matches!(args.network, Network::Dev | Network::DevRecursive) {
            return Err("--test-relays is for the dev networks only".into());
        }
        let bytes = std::fs::read(file).map_err(|e| format!("{file}: {e}"))?;
        let parsed = tabminer::consensus::File::parse(&bytes).map_err(|e| format!("{file}: {e}"))?;
        if parsed.relays.is_empty() {
            return Err(format!("{file}: not an onion-mode file").into());
        }
        log::line(&format!("message layer: the relays of {file} stand as if in force (a test)"));
        let _ = events.send(tabminer::node::Event::TestRelays(parsed.relays));
    }
    let notes = node.take_notes();
    let stats = node.stats();
    let syncing = node.syncing();
    let tip_changes = node.tip_changes();
    let refused = node.refused();
    let listening = format!("listening on {}", node.local_addr()?);
    log::line(&listening);
    let node_thread = std::thread::Builder::new().name("node".into()).spawn(move || node.run())?;
    let tip = chain.tip()?.ok_or("no genesis")?;
    let tip_line = format!("tip at height {} ({})", tip.height, short(&tip.hash()));
    log::line(&tip_line);
    if !args.no_prompt {
        println!("{listening}; {tip_line}; type help for commands");
    }
    if let Some(address) = &relay_address {
        for line in relay_lines(address, args.listen) {
            log::line(&line);
            if !args.no_prompt {
                println!("{line}");
            }
        }
    }

    let ctx = Arc::new(Ctx {
        params,
        chain,
        mempool,
        wallet,
        events: events.clone(),
        stats,
        tip_changes,
        refused,
        syncing,
        stop: Arc::new(AtomicBool::new(false)),
        mining,
        relay: args.relay,
        relay_address: relay_address.clone(),
        debug_fill: args.debug_fill,
        reserve_bytes: tabminer::mempool::reserve_bytes(params.max_block_size, args.reserve_percent),
        in_flight: Mutex::new(None),
        outgoing: Mutex::new(std::collections::HashMap::new()),
        prompt: !args.no_prompt,
        slates: Mutex::new(onion::SlateLimit::default()),
        subnames: Mutex::new(Subnames::load(&args.data.join("subnames"))?),
        subnames_file: args.data.join("subnames"),
        waiting: Mutex::new(std::collections::HashMap::new()),
        resolved: Mutex::new(Resolved::default()),
        issued: Mutex::new(std::collections::HashMap::new()),
        delegation: Mutex::new(None),
        issuing: Mutex::new(()),
    });
    // The wallet's sub-names: certificates issued, renewed and sent again
    // until delivered, those held published, and its delegation renewed,
    // all well before they expire.
    if ctx.wallet.is_some() {
        let ctx = Arc::clone(&ctx);
        std::thread::Builder::new().name("subnames".into()).spawn(move || {
            loop {
                publish_subnames(&ctx);
                std::thread::sleep(SUBNAMES_EVERY);
            }
        })?;
    }
    if let Some(notes) = notes {
        let ctx = Arc::clone(&ctx);
        std::thread::Builder::new().name("messages".into()).spawn(move || {
            for note in notes {
                on_note(&ctx, note);
            }
        })?;
    }
    // The chain ends at the schedule's final block: once the tip reaches
    // it, the node has nothing left to do.
    {
        let ctx = Arc::clone(&ctx);
        std::thread::Builder::new().name("final-block".into()).spawn(move || {
            let last = ctx.params.final_height();
            loop {
                if ctx.chain.tip().ok().flatten().is_some_and(|t| t.height >= last) {
                    let msg = format!("the chain has reached its final block, height {last}; exiting");
                    log::line(&msg);
                    println!("\n{msg}");
                    // Let the node announce the block before going.
                    std::thread::sleep(Duration::from_secs(5));
                    std::process::exit(0);
                }
                std::thread::sleep(Duration::from_secs(1));
            }
        })?;
    }
    // A restored wallet finds its outputs once the node has caught up.
    if let Some(wallet) = ctx.wallet.clone()
        && wallet.scan_pending()?
    {
        let ctx = Arc::clone(&ctx);
        std::thread::Builder::new().name("restore-scan".into()).spawn(move || {
            loop {
                std::thread::sleep(Duration::from_secs(1));
                let peers = ctx.stats.lock().unwrap().peers.iter().any(|p| p.live);
                if !peers || ctx.syncing.load(Ordering::Acquire) {
                    continue;
                }
                // The scan finds every output the set holds up to the tip
                // read first, so the wallet is synced to it.
                let tip = ctx.chain.tip().ok().flatten();
                let found = ctx
                    .chain
                    .env()
                    .read_txn()
                    .map_err(|e| e.to_string())
                    .and_then(|rtxn| wallet.scan(ctx.chain.utxo(), &rtxn).map_err(|e| e.to_string()));
                match found {
                    Ok((n, total)) => {
                        log::line(&format!("restored wallet: found {n} outputs worth {}", fmt_coins(total)));
                        if let Some(tip) = tip {
                            wallet.set_synced(tip.height, &digest_to_bytes(&tip.hash())).ok();
                        }
                        wallet.clear_scan_pending().ok();
                    }
                    Err(e) => log::line(&format!("restored wallet: scan failed: {e}")),
                }
                return;
            }
        })?;
    }
    let miner = match dataset {
        Some(dataset) => {
            let ctx = Arc::clone(&ctx);
            let (blocks, jobs, delay) = (args.blocks, args.jobs, Duration::from_secs(args.delay_blocks));
            Some(std::thread::Builder::new().name("miner".into()).spawn(move || {
                // An error ends a round of mining, not mining: a node left
                // running without its miner would never say so again.
                // (With --blocks, a restart counts its blocks afresh.)
                while let Err(e) = mine(&ctx, &dataset, blocks, jobs, delay) {
                    if ctx.stop.load(Ordering::Acquire) {
                        break;
                    }
                    log::line(&format!("miner stopped: {e}; starting again in 5 s"));
                    std::thread::sleep(Duration::from_secs(5));
                }
            })?)
        }
        None => None,
    };

    if args.no_prompt {
        match miner {
            // A bounded mining run ends the process, after letting peers
            // fetch the last block.
            Some(m) if args.blocks > 0 => {
                m.join().ok();
                log::line("done; serving peers for a few seconds");
                std::thread::sleep(Duration::from_secs(5));
            }
            Some(m) => {
                m.join().ok();
            }
            None => loop {
                std::thread::sleep(Duration::from_secs(3600));
            },
        }
    } else {
        prompt(&ctx);
        // Exit without waiting for the miner: an unfinished proof is simply
        // dropped, and every database write is an LMDB transaction, so
        // nothing is left half done. The node gets a moment to save its
        // peer list.
        ctx.stop.store(true, Ordering::Release);
        drop(miner);
        // The block being mined will never land: drop its reward record,
        // unless its block already did.
        // Taken first: a guard in the condition would be held through the
        // block, and `sync_wallet` locks `in_flight` too.
        let in_flight = ctx.in_flight.lock().unwrap().take();
        if let Some(c) = in_flight
            && let Some(wallet) = &ctx.wallet
        {
            sync_wallet(&ctx).ok();
            let held = wallet.owned(&c).ok().flatten().is_some_and(|o| {
                ctx.chain.env().read_txn().ok().is_some_and(|r| wallet.held(&o, ctx.chain.utxo(), &r).unwrap_or(false))
            });
            if !held {
                wallet.forget(&c).ok();
            }
        }
        events.send(Event::Stop).ok();
        let deadline = Instant::now() + Duration::from_secs(2);
        while !node_thread.is_finished() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        log::line("tabminer stopped");
        std::process::exit(0);
    }
    events.send(Event::Stop).ok();
    node_thread.join().ok();
    log::line("tabminer stopped");
    Ok(())
}

/// Reads commands from standard input until `quit` or end of input.
fn prompt(ctx: &Ctx) {
    let stdin = std::io::stdin();
    let mut line = String::new();
    loop {
        print!("> ");
        std::io::stdout().flush().ok();
        line.clear();
        match stdin.lock().read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {}
            Err(_) => break,
        }
        let words: Vec<&str> = line.split_whitespace().collect();
        let Some(&cmd) = words.first() else {
            continue;
        };
        if matches!(cmd, "quit" | "exit") {
            break;
        }
        if let Err(e) = command(ctx, cmd, &words[1..]) {
            println!("error: {e}");
        }
    }
}

/// Brings the wallet's record of where its outputs are up to the tip:
/// from the outputs of each main-chain block since it last looked, back to
/// where a reorganization forked; by their memos when those blocks are no
/// longer kept (after a fast sync, or a long time offline).
fn sync_wallet(ctx: &Ctx) -> AnyResult<()> {
    let chain = &ctx.chain;
    if chain.staging()? {
        return Ok(());
    }
    let Some(tip) = chain.tip()? else {
        return Ok(());
    };
    // The last block looked at that is still on the main chain.
    let mut from = None;
    if let Some((mut height, mut hash)) = ctx.wallet()?.synced()? {
        loop {
            if chain.header_at(height)?.is_some_and(|h| digest_to_bytes(&h.hash()) == hash) {
                from = Some(height);
                break;
            }
            let header = match digest_from_bytes(&hash) {
                Some(d) if height > 0 => chain.header_by_hash(&d)?,
                _ => None,
            };
            let Some(header) = header else {
                break;
            };
            (height, hash) = (height - 1, digest_to_bytes(&header.prev_hash));
        }
    }
    let mut gap = from.is_none();
    for height in from.map_or(1, |h| h + 1)..=tip.height {
        if gap {
            break;
        }
        match chain.main_outputs(height)? {
            Some((_, first, outputs)) => {
                ctx.wallet()?.locate(first, &outputs)?;
                for p in ctx.wallet()?.land_payments(height, first, &outputs)? {
                    if let Err(e) = make_payment_path(ctx, &p) {
                        log::line(&format!("wallet: no proof yet for {}: {e}", short(&p.txid)));
                    }
                }
            }
            None => gap = true,
        }
    }
    if gap && !ctx.wallet()?.outputs()?.is_empty() {
        log::line("wallet: finding its outputs by their memos");
        let rtxn = chain.env().read_txn()?;
        ctx.wallet()?.relocate(chain.utxo(), &rtxn)?;
    }
    if gap {
        // Payments that landed in the gap, while their outputs are unspent;
        // their paths can be made while the blocks are in the undo window.
        let rtxn = chain.env().read_txn()?;
        let found = ctx.wallet()?.find_payments(chain.utxo(), &rtxn)?;
        drop(rtxn);
        for p in found {
            if let Err(e) = make_payment_path(ctx, &p) {
                log::line(&format!("wallet: no proof for {}: {e}", short(&p.txid)));
            }
        }
    }
    ctx.wallet()?.set_synced(tip.height, &digest_to_bytes(&tip.hash()))?;
    // Pooled spends of our outputs: a leaf signed elsewhere (a copy of
    // this wallet, or its state before a backup was restored) is never
    // signed from again.
    let seen: Vec<(tabminer::transaction::Commitment, u64)> = ctx
        .mempool
        .lock()
        .unwrap()
        .entries()
        .flat_map(|e| e.tx.spent_commitments().into_iter().zip(e.tx.inputs.iter().map(|i| i.signature.index)))
        .collect();
    let behind = ctx.wallet()?.observe_signatures(&seen)?;
    if behind > 0 {
        log::line(&format!(
            "wallet: {behind} outputs were signed from leaves this wallet took for unused (a restored backup?); skipped"
        ));
    }
    let rtxn = chain.env().read_txn()?;
    // Outputs a reorganization took off the main chain, unless their
    // transactions wait in the pool to land again: hidden, then forgotten
    // past the undo window (kept till then: the chain may switch back).
    let waiting: std::collections::HashSet<_> =
        ctx.mempool.lock().unwrap().entries().flat_map(|e| e.tx.outputs.iter().map(|o| o.commitment)).collect();
    let settle = chain.max_undo().unwrap_or(DEFAULT_MAX_UNDO);
    let lost = ctx.wallet()?.mark_lost(chain.utxo(), &rtxn, tip.height, &waiting)?;
    if lost > 0 {
        log::line(&format!(
            "wallet: {lost} outputs are no longer on the main chain (a reorganization, or spent by a copy of this wallet)"
        ));
    }
    let forgotten = ctx.wallet()?.prune_lost(tip.height, settle)?;
    if forgotten > 0 {
        log::line(&format!("wallet: forgot {forgotten} outputs lost to a reorganization {settle} blocks ago"));
    }
    ctx.wallet()?.sync_names(chain.names(), &rtxn)?;
    // Rewards of blocks that will not make the main chain: never found
    // (the miner stopped), never accepted, or side blocks past the depth a
    // reorganization reaches. The block being mined is kept.
    let keep = *ctx.in_flight.lock().unwrap();
    let known = |hash: &[u8; 32]| {
        digest_from_bytes(hash).is_some_and(|d| chain.entry(&d).ok().flatten().is_some_and(|e| !e.invalid))
    };
    let n = ctx.wallet()?.prune_rewards(chain.utxo(), &rtxn, tip.height, settle, known, keep)?;
    if n > 0 {
        log::line(&format!("wallet: forgot {n} rewards of blocks that will not make the main chain"));
    }
    Ok(())
}

/// Makes and keeps the path of a payment's (or burn's) output against the
/// block it landed in (`docs/PROOFS.md`): possible while that block is in
/// the undo window.
fn make_payment_path(ctx: &Ctx, p: &tabminer::wallet::Payment) -> AnyResult<()> {
    let (height, position) = p.landed.ok_or("not yet in a block")?;
    let (header, _, path) = ctx
        .chain
        .output_proof_at(position, height)?
        .ok_or("its block has left this node's undo window: an archive node (--max-undo-blocks 0) can still make it")?;
    ctx.wallet()?.set_payment_path(&p.txid, height, position, path, &header.state_root)?;
    Ok(())
}

/// The payment (or burn, with `burn`) whose txid starts with `prefix`, with
/// its proof made now if it was not.
fn payment_by_prefix(ctx: &Ctx, prefix: &str, burn: bool) -> AnyResult<tabminer::proofs::Proof> {
    let what = if burn { "burn" } else { "payment" };
    let matches: Vec<_> = ctx
        .wallet()?
        .payments()?
        .into_iter()
        .filter(|p| p.is_burn() == burn && hex_digest(&p.txid).starts_with(prefix))
        .collect();
    let p = match &matches[..] {
        [p] => p.clone(),
        [] => return Err(format!("no {what} with a txid starting {prefix}").into()),
        _ => return Err(format!("{} {what}s have txids starting {prefix}: give more digits", matches.len()).into()),
    };
    if let Some(proof) = p.proof() {
        return Ok(proof);
    }
    if p.landed.is_none() {
        return Err(format!("the {what} is not in a block yet").into());
    }
    make_payment_path(ctx, &p)?;
    let p = ctx.wallet()?.payments()?.into_iter().find(|q| q.txid == p.txid).ok_or("payment gone")?;
    Ok(p.proof().ok_or("no proof")?)
}

/// What a proof that holds shows, with its block's confirmations; or why
/// it does not hold.
fn check_proof(ctx: &Ctx, proof: &tabminer::proofs::Proof) -> AnyResult<String> {
    use tabminer::proofs::Claim;
    let tip = ctx.chain.tip()?.ok_or("no genesis")?;
    let header = ctx
        .chain
        .header_at(proof.height)?
        .ok_or_else(|| format!("block {} is not on this node's main chain (is it synced?)", proof.height))?;
    proof.check(&header.state_root).map_err(|e| format!("the proof does not hold: {e}"))?;
    let confirmations = tip.height - proof.height + 1;
    let block = format!("in block {} ({}), {confirmations} confirmations", proof.height, short(&header.hash()));
    let amount = fmt_coins(proof.amount as u128);
    Ok(match &proof.claim {
        Claim::Payment { sender, secret, receipt, .. } => format!(
            "payment proof holds: {amount} coins from {} to {}, {block}",
            match secret {
                None => tabminer::address::encode(sender),
                Some(_) => "an unnamed sender (whoever shows this proof holds its secret)".to_string(),
            },
            tabminer::address::encode(&receipt.recipient())
        ),
        Claim::Burn(b) => format!(
            "proof of burn holds: {amount} coins burned for {}, purpose \"{}\", {block}",
            tabminer::address::encode(&b.beneficiary),
            String::from_utf8_lossy(&b.purpose)
        ),
    })
}

/// A 32-byte value from 64 hex digits, or zeros when absent.
fn parse_value(s: Option<&str>) -> AnyResult<tabminer::pow::Digest> {
    match s {
        None => Ok([tabminer::poseidon2::Fp::ZERO; 8]),
        Some(h) if h.len() == tabminer::address::LEN => {
            tabminer::address::decode(h).ok_or_else(|| "not a valid address: check the characters".into())
        }
        Some(h) => {
            let bytes = tabminer::wallet::digest_from_hex(h).ok_or("a value is 64 hex digits or a tab1 address")?;
            digest_from_bytes(&bytes).ok_or_else(|| "a value's 4-byte words must be below the field modulus".into())
        }
    }
}

/// Carries name operations in a transaction of the wallet's and pools it.
fn carry(ctx: &Ctx, ops: Vec<NameOp>, fee: Option<&str>) -> AnyResult<()> {
    let fee = parse_fee(ctx, fee)?;
    let rtxn = ctx.chain.env().read_txn()?;
    let signed = match ctx.wallet()?.carry(ops.clone(), fee, ctx.chain.utxo(), &rtxn) {
        Ok(s) => s,
        Err(e) => {
            // No transaction carries them: what preparing them recorded
            // in the wallet is undone, so they can be tried again.
            for op in &ops {
                ctx.wallet()?.undo_name_op(op)?;
            }
            return Err(e.into());
        }
    };
    drop(rtxn);
    println!("transaction {} pays a fee of {}", short(&signed.tx.txid()), fmt_coins(signed.tx.balance() as u128));
    submit(ctx, signed);
    Ok(())
}

fn command(ctx: &Ctx, cmd: &str, args: &[&str]) -> AnyResult<()> {
    if matches!(
        cmd,
        "status"
            | "balance"
            | "outputs"
            | "send"
            | "send-file"
            | "finalize"
            | "cancel"
            | "sent"
            | "prune"
            | "payments"
            | "resend"
            | "payment-proof"
            | "burn"
            | "burn-proof"
            | "names"
            | "name-commit"
            | "name-reveal"
            | "name-update"
            | "name-offer"
            | "name-transfer"
    ) && (ctx.wallet.is_some() || cmd != "status")
    {
        sync_wallet(ctx)?;
    }
    match cmd {
        "help" => println!("{HELP}"),
        "status" => {
            let tip = ctx.chain.tip()?.ok_or("no genesis")?;
            // One LMDB read transaction per thread at a time: the work is
            // read before the one the balance needs.
            let work = log2_u256(ctx.chain.tip_work()?);
            let (supply, issued) = (ctx.chain.supply()?, ctx.chain.issued(tip.height)?);
            let stats = ctx.stats.lock().unwrap().clone();
            let pool = ctx.mempool.lock().unwrap();
            let rtxn = ctx.chain.env().read_txn()?;
            let b = match &ctx.wallet {
                Some(w) => Some(w.balance(ctx.chain.utxo(), &rtxn)?),
                None => None,
            };
            println!(
                "tip      height {} {} at {}, work 2^{work:.1}",
                tip.height,
                short(&tip.hash()),
                log::timestamp_of(tip.timestamp)
            );
            // Every node checks the supply with each block (docs/AMOUNTS.md).
            println!(
                "supply   {} unspent, {} issued{}",
                fmt_coins(supply),
                fmt_coins(issued),
                if supply == issued { "" } else { " (MISMATCH)" }
            );
            println!(
                "peers    {} live of {} known; {} downloads, {} blocks to fetch, {} waiting for a parent",
                stats.peers.iter().filter(|p| p.live).count(),
                stats.peers.len(),
                stats.downloads,
                stats.wanted,
                stats.waiting
            );
            match (stats.mode, stats.parts) {
                (Some(Mode::Headers), _) => println!("sync     fast sync: downloading headers"),
                (Some(Mode::Snapshot), Some((have, all))) => {
                    println!("sync     fast sync: {have} of {all} state parts")
                }
                (Some(Mode::Snapshot), None) => println!("sync     fast sync: fetching the snapshot block"),
                _ if ctx.syncing.load(Ordering::Acquire) => println!("sync     catching up"),
                _ => println!("sync     up to date"),
            }
            println!("mempool  {} transactions, {} KB", pool.len(), pool.bytes() / 1000);
            match b {
                Some(b) => println!(
                    "wallet   {} confirmed, {} pending, {} unverified, {} reserved, {} locked",
                    fmt_coins(b.confirmed),
                    fmt_coins(b.pending),
                    fmt_coins(b.unverified),
                    fmt_coins(b.reserved),
                    fmt_coins(b.locked)
                ),
                None => println!("wallet   none (--no-wallet)"),
            }
            println!("mining   {}", if ctx.mining { "on" } else { "off" });
            let live = stats.rendezvous.iter().filter(|(_, l)| *l).count();
            print!("messages {live} of {} rendezvous sessions live", stats.rendezvous.len());
            if stats.sessions > 0 || ctx.relay {
                print!("; holding {} sessions as a relay", stats.sessions);
            }
            println!();
        }
        "storage" => {
            let (rows, file) = ctx.chain.storage()?;
            // One read transaction per thread at a time: the tip first.
            let height = ctx.chain.tip()?.map_or(0, |t| t.height);
            let rtxn = ctx.chain.env().read_txn()?;
            let unspent = ctx.chain.utxo().len(&rtxn)?;
            let positions = ctx.chain.utxo().next_position(&rtxn)?;
            drop(rtxn);
            println!("{:<12} {:>12} {:>12} {:>14}", "database", "MB", "entries", "bytes each");
            let mb = |b: u64| format!("{:.1}", b as f64 / 1e6);
            let (mut state, mut blocks) = (0u64, 0u64);
            for (name, bytes, entries) in &rows {
                // The unspent outputs' parts are per output; the rest per block.
                let per_utxo = matches!(*name, "tree" | "outputs");
                let per = if per_utxo { unspent } else { u64::from(height) + 1 };
                let label = if per_utxo { format!("utxo {name}") } else { name.to_string() };
                println!(
                    "{label:<12} {:>12} {entries:>12} {:>9.1} /{}",
                    mb(*bytes),
                    *bytes as f64 / per.max(1) as f64,
                    if per_utxo { "out" } else { "blk" }
                );
                if per_utxo { state += bytes } else { blocks += bytes }
            }
            println!(
                "unspent outputs: {unspent} of {positions} made ({:.1}%), {:.1} bytes each",
                unspent as f64 * 100.0 / positions.max(1) as f64,
                state as f64 / unspent.max(1) as f64
            );
            println!(
                "in use {} MB (state {}, blocks {}); file {} MB, the rest free pages LMDB reuses",
                mb(state + blocks),
                mb(state),
                mb(blocks),
                mb(file)
            );
        }
        "peers" => {
            let stats = ctx.stats.lock().unwrap().clone();
            if stats.peers.is_empty() {
                println!("no peers");
            }
            for p in &stats.peers {
                println!(
                    "{:<24} {:<8} {:<6} {:<10} {}",
                    p.addr,
                    p.height.map_or("?".to_string(), |h| format!("h {h}")),
                    if p.live { "live" } else { "silent" },
                    if p.handshaken { "handshaken" } else { "" },
                    match (p.min_fee, p.pool_fee) {
                        (Some(f), Some(m)) if m > f => format!("floor {f}/byte, pool {m}/byte"),
                        (Some(f), _) => format!("floor {f}/byte"),
                        _ => String::new(),
                    }
                );
            }
        }
        "mempool" => {
            let pool = ctx.mempool.lock().unwrap();
            println!(
                "{} transactions, {} bytes; admitting from {} base units a byte",
                pool.len(),
                pool.bytes(),
                pool.admission_fee(tabminer::mempool::unix_now())
            );
            for e in pool.entries() {
                println!("  {}  {} bytes  fee {}", short(&e.txid), e.size, fmt_coins(e.fee as u128));
            }
        }
        "balance" => {
            let rtxn = ctx.chain.env().read_txn()?;
            let b = ctx.wallet()?.balance(ctx.chain.utxo(), &rtxn)?;
            println!("confirmed {}  spendable", fmt_coins(b.confirmed));
            println!("pending   {}  incoming, not yet on chain", fmt_coins(b.pending));
            println!(
                "unverified {} paid to us in slates, not yet on chain: unverifiable until they land",
                fmt_coins(b.unverified)
            );
            println!("reserved  {}  held for a slate not yet finalized", fmt_coins(b.reserved));
            println!("locked    {}  signed, being sent, not yet confirmed", fmt_coins(b.locked));
        }
        "set-leaf" => {
            let [index, file] = args else { return Err("usage: set-leaf INDEX FILE".into()) };
            let index: usize = index.parse().map_err(|_| format!("not a leaf index: {index}"))?;
            if index >= tabminer::chain::AUX_LEAVES {
                return Err(format!("leaf index must be 0 to {}", tabminer::chain::AUX_LEAVES - 1).into());
            }
            let bytes = std::fs::read(file).map_err(|e| format!("{file}: {e}"))?;
            if index == 0 {
                // A vote for a file nobody can follow is refused here.
                if let Err(e) = tabminer::consensus::File::parse(&bytes) {
                    return Err(format!("{file} is not a valid consensus file: {e}").into());
                }
            }
            let hash = tabminer::bip39::sha256(&bytes);
            let root = ctx.chain.set_aux_leaf(index, hash)?;
            let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
            println!("leaf {index}  {}  ({} bytes)", hex(&hash), bytes.len());
            println!("root     {}  (in the headers mined from now on)", hex(&root));
            if index == 0 {
                // Leaf 0 is a vote for a consensus file: kept, to be served
                // to the nodes that count it.
                ctx.chain.put_consensus_file(&bytes)?;
                let parsed = tabminer::consensus::File::parse(&bytes)?;
                println!(
                    "kept     {file} as a consensus file (mode {}{}), served to peers",
                    parsed.mode,
                    if parsed.mode == tabminer::consensus::Mode::Onion {
                        format!(", {} relays", parsed.relays.len())
                    } else {
                        String::new()
                    }
                );
            }
        }
        "set-leaf-value" => {
            let [index, hex_value] = args else { return Err("usage: set-leaf-value INDEX HEX".into()) };
            let index: usize = index.parse().map_err(|_| format!("not a leaf index: {index}"))?;
            if index >= tabminer::chain::AUX_LEAVES {
                return Err(format!("leaf index must be 0 to {}", tabminer::chain::AUX_LEAVES - 1).into());
            }
            let value = tabminer::wallet::digest_from_hex(hex_value).ok_or("the value must be 64 hex digits")?;
            let root = ctx.chain.set_aux_leaf(index, value)?;
            let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
            println!("leaf {index}  {}", hex(&value));
            println!("root     {}  (in the headers mined from now on)", hex(&root));
        }
        "address" if !args.is_empty() => {
            let w = ctx.wallet.as_ref().ok_or("this node runs with --no-wallet")?;
            let old = w.id();
            match args {
                ["next"] => {
                    let key = w.next_address()?;
                    ctx.events.send(Event::Identity(Some(key))).map_err(|_| "the node has stopped")?;
                    // A delegation, if any, signed again for the new id.
                    publish_subnames(ctx);
                    println!("new address {}", w.address());
                    println!("the old one answers nothing from now on; payments under way are unaffected");
                }
                ["off"] => {
                    if w.address_off() {
                        return Err("the address is already off".into());
                    }
                    w.turn_address_off()?;
                    ctx.events.send(Event::Identity(None)).map_err(|_| "the node has stopped")?;
                    println!("address off: nobody can reach this wallet, though it can still pay;");
                    println!("address next brings it back under a new address");
                }
                _ => return Err("usage: address [next|off]".into()),
            }
            // Names pointing at the old address need to follow.
            for n in w.owned_names()?.into_iter().filter(|n| n.value == old) {
                println!(
                    "{} points at the old address: name-update {} {} to follow",
                    String::from_utf8_lossy(&n.name),
                    String::from_utf8_lossy(&n.name),
                    if w.address_off() { "NEW-ADDRESS".to_string() } else { w.address() }
                );
            }
        }
        "address" => {
            if let Some(w) = &ctx.wallet {
                if w.address_off() {
                    println!("off (address next for a new one; the last was {})", w.address());
                } else {
                    println!("{}", w.address());
                    println!("id {}", hex_digest(&w.id()));
                }
            }
            if let Some(relay) = &ctx.relay_address {
                println!("relay {relay}  (the id this node is listed under in consensus.txt; not for payments)");
            }
            if ctx.wallet.is_none() && ctx.relay_address.is_none() {
                return Err("this node runs with --no-wallet".into());
            }
        }
        "consensus" => {
            use tabminer::consensus::{EPOCH, GRACE, Mode, SWITCH, hex};
            let epoch = ctx.chain.consensus_epoch()?;
            let (votes, running) = ctx.chain.consensus()?;
            let stats = ctx.stats.lock().unwrap().clone();
            let mode_of = |c: &tabminer::consensus::Current| match &c.file {
                Some(f) if f.mode == Mode::Onion => format!("onion: {} relays", f.relays.len()),
                _ => "init".to_string(),
            };
            // In force: decided at the last boundary.
            let current = &epoch.current;
            println!(
                "mode     {} since block {} (decided by heights {} to {})",
                mode_of(current),
                epoch.boundary,
                epoch.votes.range.0,
                epoch.votes.range.1
            );
            match &current.winner {
                Some((hash, n)) => println!("in force {}  ({n} of {} votes)", hex(hash), epoch.votes.blocks),
                None if epoch.votes.counts.is_empty() => println!("in force none: no block of that window voted"),
                None => println!("in force none: no file that window voted for is fetched and valid"),
            }
            if let Some(p) = &epoch.previous {
                println!(
                    "switch   from {} until block {}; the new file is tried first from block {}",
                    mode_of(p),
                    epoch.boundary + GRACE - 1,
                    epoch.boundary + SWITCH
                );
            }
            // The running count, for the next boundary.
            let next = epoch.boundary + EPOCH;
            println!(
                "next     block {next}: heights {} to {} so far, {} voting{}",
                votes.range.0,
                votes.range.1,
                votes.counts.iter().map(|c| c.1).sum::<u32>(),
                if votes.missing.is_empty() {
                    String::new()
                } else {
                    format!(", {} with leaves still to fetch ({} wanted)", votes.missing.len(), stats.aux_wanted)
                }
            );
            for (hash, n, last) in &votes.counts {
                let state = match (&running.winner, running.skipped.iter().find(|s| s.0 == *hash)) {
                    (Some((w, _)), _) if w == hash => "  (leading)".to_string(),
                    (_, Some((_, _, why))) => format!("  ({why})"),
                    _ => String::new(),
                };
                println!("vote     {}  {n:>3} blocks, last at height {last}{state}", hex(hash));
            }
            if let Some((hash, _)) = &current.winner {
                let bytes = ctx.chain.consensus_file(hash)?.unwrap_or_default();
                println!("file     {} bytes:", bytes.len());
                match std::str::from_utf8(&bytes) {
                    Ok(text) => {
                        for line in text.lines().take(64) {
                            println!("  | {line}");
                        }
                        if text.lines().count() > 64 {
                            println!("  | ... ({} lines in all)", text.lines().count());
                        }
                    }
                    Err(_) => println!("  (not text)"),
                }
            }
        }
        "leaves" => {
            let leaves = ctx.chain.aux_leaves()?;
            let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
            for (i, l) in leaves.iter().enumerate() {
                println!("leaf {i:>2}  {}", hex(l));
            }
            println!("root     {}", hex(&ctx.chain.aux_root()?));
        }
        "policies" => {
            let outputs = ctx.wallet()?.policy_outputs()?;
            if outputs.is_empty() {
                println!("no policy outputs");
            }
            for p in outputs {
                let state = match (p.state, p.position) {
                    (State::Unspent, Some(_)) => "confirmed",
                    (State::Unspent, None) => "pending",
                    (State::Reserved, _) => "reserved",
                    (State::Spent, _) => "spent",
                };
                println!(
                    "{}  {:>20}  {:<9}  {} leaves, {} of our keys  {}",
                    short(&p.commitment),
                    fmt_coins(p.amount as u128),
                    state,
                    p.policy.leaves.len(),
                    p.keys.len(),
                    log::timestamp_of(p.created)
                );
            }
        }
        "channel-key" => {
            let height = match args {
                [] => tabminer::wallet::CHANNEL_HEIGHT,
                [h] => h.parse::<usize>().map_err(|_| format!("not a height: {h}"))?,
                _ => return Err("usage: channel-key [HEIGHT]".into()),
            };
            if !(1..=tabminer::xmss::MAX_HEIGHT).contains(&height) {
                return Err(format!("height must be 1 to {}", tabminer::xmss::MAX_HEIGHT).into());
            }
            let nonce = Wallet::fresh_nonce()?;
            let t = Instant::now();
            let hash = ctx.wallet()?.channel_key_hash(&nonce, height);
            let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
            let nonce_bytes: Vec<u8> = nonce.iter().flat_map(|x| x.to_le_bytes()).collect();
            println!("nonce     {}", hex(&nonce_bytes));
            println!("key hash  {}  ({height} levels, made in {})", hex(&digest_to_bytes(&hash)), secs(t.elapsed()));
            println!("keep the nonce: the key is derived from it and the wallet's seed");
        }
        "outputs" => {
            let rtxn = ctx.chain.env().read_txn()?;
            // Lost to a reorganization: as good as gone (`Wallet::mark_lost`).
            let lost = ctx.wallet()?.lost_set()?;
            let outputs: Vec<_> =
                ctx.wallet()?.outputs()?.into_iter().filter(|o| !lost.contains(&o.commitment)).collect();
            if outputs.is_empty() {
                println!("no outputs");
            }
            for o in outputs {
                let held = ctx.wallet()?.held(&o, ctx.chain.utxo(), &rtxn)?;
                let state = match (o.state, held) {
                    (State::Unspent, true) => "confirmed",
                    (State::Unspent, false) => "pending",
                    (State::Reserved, _) => "reserved",
                    (State::Spent, true) => "locked",
                    (State::Spent, false) => "spent",
                };
                println!(
                    "{}  {:>20}  {:<9}{}  {}",
                    short(&o.commitment),
                    fmt_coins(o.amount as u128),
                    state,
                    if o.recovered { "  recovered" } else { "" },
                    log::timestamp_of(o.created)
                );
            }
        }
        "send" | "send-file" => {
            let to_file = cmd == "send-file";
            let usage = if to_file {
                "usage: send-file AMOUNT [FEE] FILE [named]"
            } else {
                "usage: send AMOUNT [FEE] ADDRESS|@NAME|@LABEL.NAME [named]"
            };
            let (args, named) = match args {
                [rest @ .., "named"] => (rest, true),
                _ => (args, false),
            };
            let (amount, fee, target) = match args {
                [amount, target] => (*amount, None, *target),
                [amount, fee, target] => (*amount, Some(*fee), *target),
                _ => return Err(usage.into()),
            };
            let amount = parse_coins(amount).ok_or("bad amount")?;
            // A sub-name's lookups and the slate go over one circuit.
            let group = lookup_tag() | 1;
            let to = if to_file {
                None
            } else {
                Some(recipient_in(ctx, target, group)?.ok_or_else(|| not_a_recipient(ctx, target))?)
            };
            if to.is_some() {
                await_reachable(ctx)?;
            }
            let rtxn = ctx.chain.env().read_txn()?;
            let slate = ctx.wallet()?.send(amount, parse_fee(ctx, fee)?, named, ctx.chain.utxo(), &rtxn)?;
            drop(rtxn);
            if let Some(to) = to {
                ctx.outgoing.lock().unwrap().insert(slate.id, to);
                let out = Outbound {
                    tag: slate_tag(&slate.id),
                    to,
                    kind: onion::KIND_SLATE,
                    inner: slate.to_bytes(),
                    recipient: None,
                    reply: None,
                    group,
                };
                if ctx.events.send(Event::Send(out)).is_err() {
                    ctx.wallet()?.cancel_slate(&slate.id)?;
                    return Err("the node has stopped".into());
                }
                println!(
                    "slate {} sent to {}: {} coins plus {} fee from {} inputs; it is finalized when the recipient answers",
                    &slate.id_hex()[..16],
                    tabminer::address::encode(&to),
                    fmt_coins(amount as u128),
                    fmt_coins(slate.fee as u128),
                    slate.inputs.len()
                );
                return Ok(());
            }
            if let Err(e) = write_slate(target, &slate) {
                // Not written: nothing to answer, so its inputs are freed.
                ctx.wallet()?.cancel_slate(&slate.id)?;
                return Err(format!("{target}: {e}").into());
            }
            println!(
                "slate {} written to {}: {} coins plus {} fee from {} inputs; send it to the recipient",
                &slate.id_hex()[..16],
                if target == "-" { "the terminal, above" } else { target },
                fmt_coins(amount as u128),
                fmt_coins(slate.fee as u128),
                slate.inputs.len()
            );
        }
        "receive" => {
            let (file, out) = match args {
                [file] if *file == "-" => ("-".to_string(), "-".to_string()),
                [file] => (file.to_string(), format!("{file}.received")),
                [file, out] => (file.to_string(), out.to_string()),
                _ => return Err("usage: receive FILE [OUT]".into()),
            };
            if out == file && file != "-" {
                return Err("the answered slate must not overwrite the one received".into());
            }
            let file = file.as_str();
            let out = out.as_str();
            let mut slate = read_slate(file)?;
            ctx.wallet()?.receive_slate(&mut slate)?;
            write_slate(out, &slate)?;
            println!(
                "receiving {} coins (fee {}); answered slate written to {}; return it to the sender",
                fmt_coins(slate.amount as u128),
                fmt_coins(slate.fee as u128),
                if out == "-" { "the terminal, above" } else { out }
            );
        }
        "finalize" => {
            let [file] = args else {
                return Err("usage: finalize FILE".into());
            };
            let slate = read_slate(file)?;
            let signed = ctx.wallet()?.finalize(&slate)?;
            // A file slate's recipient is whoever signed its receipt.
            if let Some(r) = &slate.receipt {
                println!(
                    "paying {} coins to {} (its receipt is kept for payment-proof)",
                    fmt_coins(slate.amount as u128),
                    tabminer::address::encode(&r.recipient())
                );
            }
            submit(ctx, signed);
        }
        "cancel" => {
            let (id, fee) = match args {
                [id] => (*id, None),
                [id, fee] => (*id, Some(*fee)),
                _ => return Err("usage: cancel ID [FEE]".into()),
            };
            let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
            let slates: Vec<_> = ctx
                .wallet()?
                .pending_slates()?
                .into_iter()
                .map(|(s, _)| s)
                .filter(|s| hex(s).starts_with(id))
                .collect();
            let rtxn = ctx.chain.env().read_txn()?;
            let sent: Vec<_> = ctx
                .wallet()?
                .sent(ctx.chain.utxo(), &rtxn)?
                .into_iter()
                .filter(|s| hex(&digest_to_bytes(&s.txid)).starts_with(id))
                .collect();
            drop(rtxn);
            if slates.len() + sent.len() > 1 {
                return Err(
                    "more than one pending slate or unconfirmed payment starts with that id; give more of it".into()
                );
            }
            if let Some(slate) = slates.first() {
                ctx.wallet()?.cancel_slate(slate)?;
                println!("slate cancelled; its inputs are spendable again");
                return Ok(());
            }
            let s = sent.into_iter().next().ok_or("no pending slate or unconfirmed payment starts with that id")?;
            let rtxn = ctx.chain.env().read_txn()?;
            let signed = ctx.wallet()?.cancel_sent(&s.txid, parse_fee(ctx, fee)?, ctx.chain.utxo(), &rtxn)?;
            drop(rtxn);
            println!(
                "payment {} replaced; the inputs come back less a fee of {}",
                short(&s.txid),
                fmt_coins(signed.tx.balance() as u128)
            );
            submit(ctx, signed);
        }
        "sent" => {
            let rtxn = ctx.chain.env().read_txn()?;
            let sent = ctx.wallet()?.sent(ctx.chain.utxo(), &rtxn)?;
            if sent.is_empty() {
                println!("no unconfirmed payments");
            }
            for s in sent {
                println!(
                    "{}  fee {}  {} inputs  {}  (cancel from {})",
                    hex_digest(&s.txid),
                    fmt_coins(s.fee as u128),
                    s.inputs.len(),
                    log::timestamp_of(s.created),
                    fmt_coins(Wallet::min_replacement_fee(&s) as u128)
                );
            }
        }
        "bump" => {
            let (prefix, fee) = match args {
                [id] => (*id, None),
                [id, fee] => (*id, Some(*fee)),
                _ => return Err("usage: bump TXID [FEE]".into()),
            };
            let rtxn = ctx.chain.env().read_txn()?;
            let sent = ctx.wallet()?.sent(ctx.chain.utxo(), &rtxn)?;
            drop(rtxn);
            let found: Vec<_> = sent.iter().filter(|s| hex_digest(&s.txid).starts_with(prefix)).collect();
            let s = match &found[..] {
                [s] => *s,
                [] => return Err(format!("no unconfirmed payment with a txid starting {prefix}").into()),
                _ => {
                    return Err(
                        format!("{} payments have txids starting {prefix}: give more digits", found.len()).into()
                    );
                }
            };
            // Without a FEE, the rate for about a block.
            let fee = parse_fee(ctx, Some(fee.unwrap_or("block")))?;
            let rtxn = ctx.chain.env().read_txn()?;
            let signed = ctx.wallet()?.bump_sent(&s.txid, fee, ctx.chain.utxo(), &rtxn)?;
            drop(rtxn);
            println!(
                "payment {} replaced by {}, paying a fee of {} (was {})",
                short(&s.txid),
                short(&signed.tx.txid()),
                fmt_coins(signed.tx.balance() as u128),
                fmt_coins(s.fee as u128)
            );
            submit(ctx, signed);
        }
        "fees" => {
            use tabminer::mempool::{TARGET_BLOCK, TARGET_DAY, TARGET_HOUR, unix_now};
            let now = unix_now();
            let pool = ctx.mempool.lock().unwrap();
            let size = Wallet::payment_size(1);
            let floor = pool.policy().min_fee_per_byte;
            println!("floor {floor} base units a byte; the pool admits from {}", pool.admission_fee(now));
            for (what, t) in [("block", TARGET_BLOCK), ("hour", TARGET_HOUR), ("day", TARGET_DAY)] {
                let seen = if pool.estimate(t, now).is_some() { "" } else { " (too little seen yet: the minimum)" };
                println!("  {what:<8} {} base units a byte{seen}", pool.suggest(t, size, now));
            }
            println!(
                "  economy  {} base units a byte: at most about {} blocks, by the aged reserve",
                pool.admission_fee(now),
                pool.reserve_wait(size)
            );
            println!("a simple payment is about {size} bytes");
        }
        "resend" => {
            let [prefix] = args else {
                return Err("usage: resend TXID".into());
            };
            let rtxn = ctx.chain.env().read_txn()?;
            let sent = ctx.wallet()?.sent(ctx.chain.utxo(), &rtxn)?;
            drop(rtxn);
            let found: Vec<_> = sent.iter().filter(|s| hex_digest(&s.txid).starts_with(prefix)).collect();
            let s = match &found[..] {
                [s] => *s,
                [] => return Err(format!("no unconfirmed payment with a txid starting {prefix}").into()),
                _ => {
                    return Err(
                        format!("{} payments have txids starting {prefix}: give more digits", found.len()).into()
                    );
                }
            };
            let tx = ctx.wallet()?.resend(&s.txid)?;
            println!("sending {} again", short(&s.txid));
            submit(ctx, Signed { tx, last_signatures: Vec::new() });
        }
        "payments" => {
            let tip = ctx.chain.tip()?.map_or(0, |t| t.height);
            let payments = ctx.wallet()?.payments()?;
            if payments.is_empty() {
                println!("no payments or burns");
            }
            for p in payments {
                let what = match &p.claim {
                    tabminer::proofs::Claim::Payment { receipt, .. } => {
                        format!("to {}", tabminer::address::encode(&receipt.recipient()))
                    }
                    tabminer::proofs::Claim::Burn(b) => {
                        format!(
                            "burned for {} ({})",
                            tabminer::address::encode(&b.beneficiary),
                            String::from_utf8_lossy(&b.purpose)
                        )
                    }
                };
                let status = match (p.landed, &p.path) {
                    (None, _) => "not in a block yet".to_string(),
                    (Some((h, _)), Some(_)) => {
                        format!("block {h}, {} confirmations, proof ready", tip.saturating_sub(h) + 1)
                    }
                    (Some((h, _)), None) => format!("block {h}, no proof (its block left the undo window)"),
                };
                println!("{}  {}  {what}  {status}", hex_digest(&p.txid), fmt_coins(p.output.amount as u128));
            }
        }
        "payment-proof" | "burn-proof" => {
            let (prefix, file) = match args {
                [prefix] => (*prefix, None),
                [prefix, file] => (*prefix, Some(*file)),
                _ => return Err(format!("usage: {cmd} TXID [FILE]").into()),
            };
            let proof = payment_by_prefix(ctx, prefix, cmd == "burn-proof")?;
            let text = proof.to_text();
            match file {
                Some(f) => {
                    std::fs::write(f, &text)?;
                    println!("proof written to {f}: {}", check_proof(ctx, &proof)?);
                }
                None => print!("{text}"),
            }
        }
        "burn" => {
            let (amount, purpose, rest) = match args {
                [amount, purpose, rest @ ..] if rest.len() <= 2 => (*amount, *purpose, rest),
                _ => return Err("usage: burn AMOUNT PURPOSE [FOR] [FEE]".into()),
            };
            let amount = parse_coins(amount).ok_or("bad amount")?;
            let (beneficiary, fee) = match rest {
                [] => (ctx.wallet()?.id(), None),
                [one] => match recipient(ctx, one)? {
                    Some(id) => (id, None),
                    None => (ctx.wallet()?.id(), Some(*one)),
                },
                [who, fee] => (
                    recipient(ctx, who)?.ok_or("FOR is a tab1… address or @NAME")?,
                    Some(*fee),
                ),
                _ => unreachable!(),
            };
            let rtxn = ctx.chain.env().read_txn()?;
            let fee = parse_fee(ctx, fee)?;
            let signed = ctx.wallet()?.burn(amount, &beneficiary, purpose.as_bytes(), fee, ctx.chain.utxo(), &rtxn)?;
            drop(rtxn);
            println!(
                "burning {} coins for {} (transaction {}); burn-proof {} once it is in a block",
                fmt_coins(amount as u128),
                tabminer::address::encode(&beneficiary),
                short(&signed.tx.txid()),
                &hex_digest(&signed.tx.txid())[..16]
            );
            submit(ctx, signed);
        }
        "verify-proof" => {
            let text = match args {
                [file] => std::fs::read_to_string(file)?,
                [] => {
                    println!("paste the proof; it ends at its END line");
                    let mut text = String::new();
                    let stdin = std::io::stdin();
                    while !tabminer::proofs::Proof::text_ends(&text) {
                        if stdin.lock().read_line(&mut text)? == 0 {
                            break;
                        }
                    }
                    text
                }
                _ => return Err("usage: verify-proof [FILE]".into()),
            };
            let proof = tabminer::proofs::Proof::from_text(&text).ok_or("no proof between BEGIN and END markers")?;
            println!("{}", check_proof(ctx, &proof)?);
        }
        "scan" => {
            let rtxn = ctx.chain.env().read_txn()?;
            let (n, total) = ctx.wallet()?.scan(ctx.chain.utxo(), &rtxn)?;
            let (names, commits) = ctx.wallet()?.scan_names(ctx.chain.utxo(), ctx.chain.names(), &rtxn)?;
            println!("found {n} outputs worth {}, {names} names and {commits} pending commits", fmt_coins(total));
            if commits > 0 {
                println!("a pending commit's name is matched when you reveal it: name-reveal NAME");
            }
        }
        "name-commit" => {
            let (name, value, fee) = match args {
                [name] => (*name, None, None),
                [name, value] => (*name, Some(*value), None),
                [name, value, fee] => (*name, Some(*value), Some(*fee)),
                _ => return Err("usage: name-commit NAME [VALUE] [FEE]".into()),
            };
            // By default the name points at this wallet, so @NAME reaches it.
            let value = match value {
                Some(v) => parse_value(Some(v))?,
                None => ctx.wallet()?.id(),
            };
            let op = ctx.wallet()?.name_commit(name.as_bytes(), value)?;
            carry(ctx, vec![op], fee)?;
            println!("committed to {name}; reveal it with name-reveal {name} once the commit is 12 blocks old");
        }
        "name-reveal" => {
            let (name, wait, fee) = match args {
                [name] => (*name, tabminer::names::MIN_REVEAL, None),
                [name, wait] => (*name, wait.parse().map_err(|_| "bad wait")?, None),
                [name, wait, fee] => {
                    (*name, wait.parse().map_err(|_| "bad wait")?, Some(*fee))
                }
                _ => return Err("usage: name-reveal NAME [WAIT] [FEE]".into()),
            };
            let height = ctx.chain.tip()?.map_or(1, |t| t.height + 1);
            let op = {
                let rtxn = ctx.chain.env().read_txn()?;
                ctx.wallet()?.name_reveal(name.as_bytes(), wait, ctx.chain.names(), &rtxn, height)?
            };
            if wait <= tabminer::names::MIN_REVEAL {
                println!(
                    "note: revealing at the minimum wait; a reorganization of {} blocks could let another take the name",
                    tabminer::names::MIN_REVEAL
                );
            }
            carry(ctx, vec![op], fee)?;
            println!("revealing {name}");
        }
        "name-update" => {
            let (name, value, fee) = match args {
                [name, value] => (*name, *value, None),
                [name, value, fee] => (*name, *value, Some(*fee)),
                _ => return Err("usage: name-update NAME VALUE [FEE]".into()),
            };
            let (op, last) = ctx.wallet()?.name_update(name.as_bytes(), parse_value(Some(value))?)?;
            carry(ctx, vec![op], fee)?;
            println!("updating {name}; its owner key rotates when the update confirms");
            if last {
                println!(
                    "warning: this was the last signature {name}'s current key can make; the update cannot be cancelled and replaced"
                );
            }
        }
        "name-offer" => {
            let (name, file, value) = match args {
                [name, file] => (*name, *file, None),
                [name, file, value] => (*name, *file, Some(*value)),
                _ => return Err("usage: name-offer NAME FILE [VALUE]".into()),
            };
            let record = ctx.wallet()?.name_offer(name.as_bytes(), parse_value(value)?)?;
            let text = offer_text(&record);
            if file == "-" {
                print!("{text}");
                println!("the offer for {name}, above; give it to the name's owner to sign over");
            } else {
                std::fs::write(file, text)?;
                println!("the offer for {name} written to {file}; give it to the name's owner to sign over");
            }
        }
        "name-transfer" => {
            let (file, fee) = match args {
                [file] => (*file, None),
                [file, fee] => (*file, Some(*fee)),
                _ => return Err("usage: name-transfer FILE [FEE]".into()),
            };
            let text = if file == "-" {
                println!("paste the offer; it ends at its END line");
                let mut text = String::new();
                let stdin = std::io::stdin();
                while !text.contains(&format!("-----END {OFFER_MARKER}-----")) {
                    if stdin.lock().read_line(&mut text)? == 0 {
                        break;
                    }
                }
                text
            } else {
                String::from_utf8_lossy(&std::fs::read(file)?).into_owned()
            };
            let record = offer_from_text(&text).ok_or("no name offer between BEGIN and END markers")?;
            let name = String::from_utf8_lossy(&record.name).into_owned();
            let (op, last) = ctx.wallet()?.name_transfer(record)?;
            carry(ctx, vec![op], fee)?;
            println!("transferring {name}; it leaves this wallet when the update confirms");
            if last {
                println!(
                    "warning: this was the last signature {name}'s key can make; the transfer cannot be cancelled and replaced"
                );
            }
        }
        "names" => {
            // One chain read transaction per thread: the tip comes first.
            let height = ctx.chain.tip()?.map_or(0, |t| t.height);
            let rtxn = ctx.chain.env().read_txn()?;
            let names = ctx.wallet()?.owned_names()?;
            let commits = ctx.wallet()?.pending_commits()?;
            if names.is_empty() && commits.is_empty() {
                println!("no names");
            }
            for n in names {
                let stage = match (n.stage, n.pending.is_some(), n.transferring) {
                    (tabminer::wallet::NameStage::Revealed, _, _) => "revealed, awaiting the chain",
                    (tabminer::wallet::NameStage::Offered, _, _) => "offered, awaiting the transfer",
                    (_, true, _) => "owned, update pending",
                    (_, _, true) => "owned, transfer pending",
                    _ => "owned",
                };
                println!(
                    "{:<32}  {}  value {}{}",
                    String::from_utf8_lossy(&n.name),
                    stage,
                    hex_digest(&n.value),
                    if n.recovered { "  recovered" } else { "" }
                );
            }
            for c in commits {
                let on_chain = ctx.chain.names().commit_position(&rtxn, &c.commit)?;
                let status = match on_chain {
                    None => "not on chain yet".to_string(),
                    Some(p) => match ctx.chain.names().commit_at(&rtxn, p)? {
                        Some(k) if height >= k.height + tabminer::names::MIN_REVEAL => {
                            format!("committed at block {}, ready to reveal", k.height)
                        }
                        Some(k) => format!(
                            "committed at block {}, ready in {} blocks",
                            k.height,
                            k.height + tabminer::names::MIN_REVEAL - height
                        ),
                        None => "not on chain yet".to_string(),
                    },
                };
                println!(
                    "{:<32}  commit {}  {}",
                    c.name.as_deref().map_or("(name unknown)".to_string(), |n| String::from_utf8_lossy(n).into_owned()),
                    short(&c.commit),
                    status
                );
            }
        }
        "name" => {
            let [name] = args else {
                return Err("usage: name NAME".into());
            };
            let rtxn = ctx.chain.env().read_txn()?;
            match ctx.chain.names().lookup(&rtxn, name.as_bytes())? {
                None => println!("{name} is not registered"),
                Some(r) => {
                    let ours = ctx.wallet()?.owned_name(name.as_bytes())?.is_some();
                    println!("owner {}", hex_digest(&r.owner));
                    println!("value {}", hex_digest(&r.value));
                    println!("      {}", tabminer::address::encode(&r.value));
                    println!("memo  {}{}", hex_digest(&r.memo), if ours { "  (this wallet's)" } else { "" });
                }
            }
        }
        "subname" => {
            let w = ctx.wallet()?;
            match args {
                ["issuer", "none"] => {
                    ctx.subnames.lock().unwrap().issuers.clear();
                    println!("this wallet signs its sub-names' certificates itself only");
                }
                ["issuer", ids @ ..] if !ids.is_empty() && ids.len() <= tabminer::subnames::MAX_ISSUERS => {
                    let mut issuers = Vec::new();
                    for a in ids {
                        let id = recipient(ctx, a)?.ok_or_else(|| format!("{a} is not a tab1… address or @NAME"))?;
                        if !issuers.contains(&id) {
                            issuers.push(id);
                        }
                    }
                    if w.address_off() {
                        return Err("the address is off: there is no id to delegate".into());
                    }
                    let list: Vec<String> = issuers.iter().map(tabminer::address::encode).collect();
                    ctx.subnames.lock().unwrap().issuers = issuers;
                    println!(
                        "certificates for sub-names of every name pointing at {} may be signed by {}",
                        w.address(),
                        list.join(", ")
                    );
                    println!("(the delegation is signed for a week and renewed daily while this wallet runs)");
                }
                ["set", sub, to] => {
                    let (label, name) = parse_subname(sub)?;
                    let id = recipient(ctx, to)?.ok_or_else(|| format!("{to} is not a tab1… address or @NAME"))?;
                    let value = chain_value(ctx, &name).ok_or_else(|| format!("{} is not registered", String::from_utf8_lossy(&name)))?;
                    // Whether this wallet may sign for the name: asked now,
                    // so a mistake shows here, not in the log.
                    let delegation = issuing_for(ctx, &name, &value)?;
                    let mut s = ctx.subnames.lock().unwrap();
                    // Given out again: its withdrawal is no longer published.
                    s.withdrawn.retain(|b| (b.cert.name.as_slice(), b.cert.label.as_slice()) != (&name[..], &label[..]));
                    let zone = s.table.entry(name.clone()).or_default();
                    let old = zone.entries.insert(label.clone(), id);
                    drop(s);
                    // A holder that loses it is told so.
                    if let Some(old) = old.filter(|o| *o != id)
                        && let Ok(b) = sign_cert(ctx, &name, &label, Some(&id), delegation)
                    {
                        send_cert(ctx, &old, &b);
                    }
                    println!(
                        "{sub} given to {}: its certificate is signed and sent; it holds it once it is online",
                        tabminer::address::encode(&id)
                    );
                }
                ["del", sub] => {
                    let (label, name) = parse_subname(sub)?;
                    let holder = ctx
                        .subnames
                        .lock()
                        .unwrap()
                        .table
                        .get(&name)
                        .and_then(|z| z.entries.get(&label).copied())
                        .ok_or_else(|| format!("no sub-name {sub} issued here"))?;
                    // The withdrawal: published by this wallet until the
                    // last certificate it issued for the sub-name would have
                    // expired, and sent to the holder.
                    let value = chain_value(ctx, &name).ok_or_else(|| format!("{} is not registered", String::from_utf8_lossy(&name)))?;
                    let none = sign_cert(ctx, &name, &label, None, issuing_for(ctx, &name, &value)?)?;
                    send_cert(ctx, &holder, &none);
                    let mut s = ctx.subnames.lock().unwrap();
                    s.withdrawn.retain(|b| (b.cert.name.as_slice(), b.cert.label.as_slice()) != (&name[..], &label[..]));
                    s.withdrawn.push(none);
                    if let Some(zone) = s.table.get_mut(&name) {
                        zone.entries.remove(&label);
                        if zone.entries.is_empty() {
                            s.table.remove(&name);
                        }
                    }
                    drop(s);
                    println!("{sub} withdrawn: its points take the withdrawal in place of the holder's certificate");
                }
                _ => {
                    return Err(
                        "usage: subname issuer ADDRESS… | subname issuer none | subname set LABEL.NAME TO | subname del LABEL.NAME"
                            .into(),
                    );
                }
            }
            ctx.subnames.lock().unwrap().save(&ctx.subnames_file)?;
            publish_subnames(ctx);
        }
        "subnames" => {
            let s = ctx.subnames.lock().unwrap();
            match s.issuers.as_slice() {
                [] => println!("issuers  this wallet only (no delegation)"),
                ids => {
                    let list: Vec<String> = ids.iter().map(tabminer::address::encode).collect();
                    println!("issuers  {}", list.join(", "));
                }
            }
            let issued = ctx.issued.lock().unwrap();
            let mut names: Vec<&Vec<u8>> = s.table.keys().collect();
            names.sort();
            for name in names {
                for (label, id) in &s.table[name].entries {
                    let state = match issued.get(&(name.clone(), label.clone())) {
                        Some(i) if i.delivered => format!("delivered, valid until {}", log::timestamp_of(i.bundle.cert.expiry)),
                        Some(_) => "sent, not yet delivered".to_string(),
                        None => "not yet issued".to_string(),
                    };
                    println!(
                        "issued   {}.{} to {} ({state})",
                        String::from_utf8_lossy(label),
                        String::from_utf8_lossy(name),
                        tabminer::address::encode(id)
                    );
                }
            }
            for b in &s.withdrawn {
                println!(
                    "withdrawn {}.{}, published until {}",
                    String::from_utf8_lossy(&b.cert.label),
                    String::from_utf8_lossy(&b.cert.name),
                    log::timestamp_of(b.cert.expiry)
                );
            }
            for b in s.held.certs.values() {
                let full = format!("{}.{}", String::from_utf8_lossy(&b.cert.label), String::from_utf8_lossy(&b.cert.name));
                println!(
                    "held     {full}, until {}, signed by {}",
                    log::timestamp_of(b.cert.expiry),
                    tabminer::address::encode(&b.cert.issuer())
                );
            }
            if s.table.is_empty() && s.held.certs.is_empty() && s.withdrawn.is_empty() {
                println!("no sub-names issued or held");
            }
        }
        "slates" => {
            let slates = ctx.wallet()?.pending_slates()?;
            if slates.is_empty() {
                println!("no pending slates");
            }
            for (id, reserved) in slates {
                println!(
                    "{}  {} reserved",
                    id.iter().map(|b| format!("{b:02x}")).collect::<String>(),
                    fmt_coins(reserved)
                );
            }
        }
        "prune" => {
            // Outputs of pooled transactions and the reward being mined
            // may yet land.
            let mut keep: std::collections::HashSet<_> =
                ctx.mempool.lock().unwrap().entries().flat_map(|e| e.tx.outputs.iter().map(|o| o.commitment)).collect();
            keep.extend(*ctx.in_flight.lock().unwrap());
            // Commits a pooled transaction carries may yet land too.
            let pooled: std::collections::HashSet<_> = ctx
                .mempool
                .lock()
                .unwrap()
                .entries()
                .flat_map(|e| {
                    e.tx.ops
                        .iter()
                        .filter_map(|op| match op {
                            NameOp::Commit { commit, .. } => Some(*commit),
                            _ => None,
                        })
                        .collect::<Vec<_>>()
                })
                .collect();
            let rtxn = ctx.chain.env().read_txn()?;
            let n = ctx.wallet()?.prune_pending(ctx.chain.utxo(), &rtxn, &keep)?;
            println!("{n} pending outputs forgotten");
            for name in ctx.wallet()?.prune_commits(ctx.chain.names(), &rtxn, &pooled)? {
                println!("commit to {name} forgotten: it never reached the chain");
            }
        }
        "phrase" => {
            let w = ctx.wallet()?;
            let password = if w.locked()? { read_secret("wallet password: ")? } else { String::new() };
            println!("{}", w.phrase(&password)?);
            println!("anyone with these words (and the passphrase, if one was used) can take the funds");
        }
        "password" => {
            let w = ctx.wallet()?;
            let old = if w.locked()? { read_secret("current password: ")? } else { String::new() };
            w.phrase(&old)?;
            let new = new_password()?;
            w.set_password(&old, &new)?;
            if new.is_empty() {
                println!("the wallet's phrase is no longer locked");
            } else {
                println!("the wallet's phrase is locked; the password is asked at every start");
            }
        }
        _ => println!("unknown command {cmd}; type help"),
    }
    Ok(())
}

fn hex_digest(d: &Digest) -> String {
    hex(d)
}

/// Pools a signed transaction here, so that a refusal reaches the prompt,
/// then hands it to the node to announce; warns of inputs that made their
/// last signature.
/// A FEE argument (`docs/FEES.md`): coins in all, `N/byte`, or a wait,
/// `block`, `hour` (the default) or `day`, for the rate this node's pool
/// suggests, or `economy`: its admission minimum, to wait for the aged
/// reserve.
fn parse_fee(ctx: &Ctx, arg: Option<&str>) -> AnyResult<Fee> {
    use tabminer::mempool::{MIN_FEE_PER_BYTE, TARGET_BLOCK, TARGET_DAY, TARGET_HOUR, unix_now};
    let now = unix_now();
    let pool = ctx.mempool.lock().unwrap();
    let size = Wallet::payment_size(1);
    let rate = |r: u64| Fee::PerByte(r.max(MIN_FEE_PER_BYTE));
    Ok(match arg.unwrap_or("hour") {
        "block" => rate(pool.suggest(TARGET_BLOCK, size, now)),
        "hour" => rate(pool.suggest(TARGET_HOUR, size, now)),
        "day" => rate(pool.suggest(TARGET_DAY, size, now)),
        "economy" => rate(pool.admission_fee(now)),
        s => match s.strip_suffix("/byte") {
            Some(n) => Fee::PerByte(n.parse().map_err(|_| "bad fee rate: N/byte, N base units")?),
            None => Fee::Total(parse_coins(s).ok_or("bad fee: coins, N/byte, block, hour, day or economy")?),
        },
    })
}

/// What a transaction's fee buys, from this node's pool, and a warning
/// if it pays less than most peers' floors.
fn fee_report(ctx: &Ctx, tx: &Transaction) {
    use tabminer::mempool::{TARGET_BLOCK, TARGET_DAY, TARGET_HOUR, unix_now};
    let size = tx.size();
    let fee = tx.balance().max(0) as u64;
    let rate = fee / size.max(1) as u64;
    let now = unix_now();
    let wait = {
        let pool = ctx.mempool.lock().unwrap();
        let within = |t| rate >= pool.suggest(t, size, now);
        if within(TARGET_BLOCK) {
            "about a block".to_string()
        } else if within(TARGET_HOUR) {
            "about an hour".to_string()
        } else if within(TARGET_DAY) {
            "about a day".to_string()
        } else {
            let blocks = pool.reserve_wait(size);
            format!("at most about {blocks} blocks, by the aged reserve, if miners keep it")
        }
    };
    println!("fee {} ({rate} base units a byte): expect it within {wait}", fmt_coins(fee as u128));
    let floors: Vec<u64> =
        ctx.stats.lock().unwrap().peers.iter().filter(|p| p.handshaken).filter_map(|p| p.min_fee).collect();
    let above = floors.iter().filter(|f| **f > rate).count();
    if above * 2 > floors.len() {
        println!(
            "warning: {above} of {} peers ask more than {rate} base units a byte and will not relay it; \
             it may never reach a miner",
            floors.len()
        );
    }
}

fn submit(ctx: &Ctx, signed: Signed) {
    let txid = signed.tx.txid();
    fee_report(ctx, &signed.tx);
    if !signed.last_signatures.is_empty() {
        println!(
            "warning: this was the last signature {} can make; it cannot be cancelled again",
            if signed.last_signatures.len() == 1 { "an input" } else { "some inputs" }
        );
    }
    let height = ctx.chain.tip().ok().flatten().map_or(1, |t| t.height + 1);
    let pooled = match ctx.chain.env().read_txn() {
        Ok(rtxn) => {
            ctx.mempool.lock().unwrap().insert(signed.tx.clone(), ctx.chain.utxo(), ctx.chain.names(), &rtxn, height)
        }
        Err(e) => {
            println!("transaction {} signed, but not pooled: {e}", short(&txid));
            return;
        }
    };
    if let Err(e) = pooled {
        println!("transaction {} signed, but the pool refused it: {e}", short(&txid));
        println!("its inputs stay locked until it is cancelled (cancel {})", short(&txid));
        return;
    }
    match ctx.events.send(Event::Transaction(signed.tx)) {
        Ok(()) => println!("transaction {} pooled; broadcasting it", short(&txid)),
        Err(_) => println!("transaction {} pooled, but the node has stopped", short(&txid)),
    }
}

/// Reads a line from the terminal without echoing it (stty turns the echo
/// off when stdin is a terminal), without its line ending.
fn read_secret(prompt: &str) -> std::io::Result<String> {
    use std::process::{Command, Stdio};
    print!("{prompt}");
    std::io::stdout().flush()?;
    let stty = |arg: &str| Command::new("stty").arg(arg).stdin(Stdio::inherit()).stderr(Stdio::null()).status();
    let hidden = matches!(stty("-echo"), Ok(s) if s.success());
    let mut line = String::new();
    let read = std::io::stdin().lock().read_line(&mut line);
    if hidden {
        let _ = stty("echo");
        println!();
    }
    read?;
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

/// Asks for a new wallet password, twice; empty for none.
fn new_password() -> AnyResult<String> {
    loop {
        let p = read_secret("new wallet password, asked at every start (empty for none): ")?;
        if p.is_empty() {
            println!("the phrase is kept unlocked: anyone who reads the wallet directory can take the funds");
            return Ok(p);
        }
        if read_secret("again: ")? == p {
            return Ok(p);
        }
        println!("the two differ; again");
    }
}

/// The wallet's password at startup: from --password-file, else asked
/// unless --no-prompt (a new wallet is then left unlocked). A new dev
/// wallet is left unlocked without asking.
fn wallet_password(args: &Args, ask: Ask) -> Result<String, tabminer::wallet::WalletError> {
    let io = tabminer::wallet::WalletError::Io;
    if let Some(file) = &args.password_file {
        let text = std::fs::read_to_string(file).map_err(io)?;
        return Ok(text.lines().next().unwrap_or("").to_string());
    }
    match (ask, args.no_prompt) {
        // Dev coins are worth nothing: a dev wallet is made unlocked,
        // without asking (one locked later with `password` still asks).
        (Ask::New, _) if args.network != Network::Mainnet => Ok(String::new()),
        (Ask::Unlock, true) => {
            Err(io(std::io::Error::other("the wallet is locked: give --password-file with --no-prompt")))
        }
        (Ask::New, true) => Ok(String::new()),
        (Ask::Unlock, false) => read_secret("wallet password: ").map_err(io),
        (Ask::New, false) => {
            println!("a new wallet is being created");
            new_password().map_err(|e| io(std::io::Error::other(e.to_string())))
        }
    }
}

/// A relay's key seed from `file` (64 hex digits), if there is one.
fn read_relay_seed(file: &std::path::Path) -> AnyResult<Option<[u8; 32]>> {
    match std::fs::read_to_string(file) {
        Ok(text) => {
            let bytes = tabminer::wallet::digest_from_hex(text.trim())
                .ok_or_else(|| format!("{}: not a relay key", file.display()))?;
            Ok(Some(bytes))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("{}: {e}", file.display()).into()),
    }
}

/// Writes a relay's key seed, readable by its owner only.
fn write_relay_seed(file: &std::path::Path, seed: &[u8; 32]) -> AnyResult<()> {
    use std::io::Write as _;
    let hex: String = seed.iter().map(|b| format!("{b:02x}")).collect();
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut f = options.open(file)?;
    writeln!(f, "{hex}")?;
    Ok(())
}

/// Rebuilds a wallet from its phrase in an empty data directory.
fn restore(args: &Args) -> AnyResult<()> {
    let dir = args.data.join("wallet");
    if dir.join("data.mdb").exists() {
        return Err(format!("{} already has a wallet; restore into another --data directory", dir.display()).into());
    }
    let phrase = read_secret("recovery phrase (12 words): ")?.split_whitespace().collect::<Vec<_>>().join(" ");
    tabminer::bip39::entropy(&phrase)?;
    let pass = read_secret("BIP39 passphrase (empty if none): ")?;
    let password = if args.network == Network::Mainnet { new_password()? } else { String::new() };
    std::fs::create_dir_all(&args.data)?;
    Wallet::restore(&dir, &phrase, &pass, &password)?;
    println!("wallet restored in {}", dir.display());
    println!("start tabminer with this --data directory: once it has synced, it finds the wallet's outputs");
    Ok(())
}

/// Waits up to 15 s for one of the wallet's rendezvous sessions to be
/// live: the answer to a slate comes back through one, and before it is
/// (just after a start) the point may still hold the session of the
/// process before, and the answer would be lost.
fn await_reachable(ctx: &Ctx) -> AnyResult<()> {
    let live = || ctx.stats.lock().unwrap().rendezvous.iter().any(|(_, l)| *l);
    if live() {
        return Ok(());
    }
    println!("waiting for this wallet's rendezvous session, for the answer to come back through");
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(250));
        if live() {
            return Ok(());
        }
    }
    Err("no rendezvous session of this wallet is live, so no answer could reach it; try again shortly \
         (`status` shows the sessions)"
        .into())
}

/// Where `send` sends: an id (a `tab1…` address or 64 hex digits) or a
/// registered `@name`'s value; `None` for a file.
fn recipient(ctx: &Ctx, to: &str) -> AnyResult<Option<Digest>> {
    recipient_in(ctx, to, 0)
}

/// [`recipient`], a sub-name's lookups in `group` (`Outbound::group`):
/// over the circuit the send that follows them then takes.
fn recipient_in(ctx: &Ctx, to: &str, group: u64) -> AnyResult<Option<Digest>> {
    if let Some(name) = to.strip_prefix('@') {
        if let Some((label, name)) = name.split_once('.') {
            return resolve_subname(ctx, label, name, group).map(Some);
        }
        return name_value(ctx, name).map(Some);
    }
    Ok(onion::parse_id(to))
}

/// Why `to` is no one `send` can send to, with a hint when it is a
/// registered name missing its `@`.
fn not_a_recipient(ctx: &Ctx, to: &str) -> Box<dyn std::error::Error> {
    let registered = ctx.chain.env().read_txn().ok().is_some_and(|rtxn| {
        tabminer::names::valid_name(to.as_bytes())
            && ctx.chain.names().lookup(&rtxn, to.as_bytes()).ok().flatten().is_some()
    });
    let hint = if registered { format!(" (did you mean @{to}?)") } else { String::new() };
    format!("{to} is not a tab1… address, @NAME or @LABEL.NAME{hint}; to write a slate to a file, use send-file").into()
}

/// A registered name's value.
fn name_value(ctx: &Ctx, name: &str) -> AnyResult<Digest> {
    let rtxn = ctx.chain.env().read_txn()?;
    let record =
        ctx.chain.names().lookup(&rtxn, name.as_bytes())?.ok_or_else(|| format!("{name} is not registered"))?;
    if record.value == [tabminer::poseidon2::Fp::ZERO; 8] {
        return Err(format!("{name} has no value: its owner has not set an address").into());
    }
    Ok(record.value)
}

/// How often the wallet's sub-names are seen to: certificates not yet
/// delivered sent again, and those due renewed (`docs/SUBNAME_CERT.md`:
/// daily, as the delegation).
const SUBNAMES_EVERY: Duration = Duration::from_secs(3600);
/// How long a sub-name lookup waits on the message layer.
const RESOLVE_WAIT: Duration = Duration::from_secs(45);
/// How long a sub-name's certificate, once found, is used before a send
/// asks for it again: a withdrawal reaches senders within this
/// (`docs/SUBNAME_CERT.md`).
const CERT_CACHE: u64 = 3600;

/// The wallet's sub-names (`docs/SUBNAME_CERT.md`), kept in the data
/// directory: the issuers its id delegates to, the sub-names it issues
/// (label to holder, by name), and the certificates it holds for
/// sub-names of others'.
#[derive(Default)]
struct Subnames {
    issuers: Vec<Digest>,
    table: tabminer::subnames::Table,
    held: tabminer::subnames::HeldCerts,
    /// Withdrawals (`none` certificates) this wallet issued, published
    /// until the certificates they withdraw would have expired: a
    /// withdrawn holder cannot put its own back at a later epoch's points.
    withdrawn: Vec<tabminer::subnames::Bundle>,
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
    (s.len().is_multiple_of(2) && s.is_ascii())
        .then(|| (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect())
        .flatten()
}

impl Subnames {
    /// Lines `server ID…`, `entry NAME LABEL ID` (ids as tab1…
    /// addresses) and `held BUNDLE` (a certificate held, in hex); none
    /// when the file is missing. Every zone's sequence
    /// number is the file's time.
    fn load(path: &std::path::Path) -> AnyResult<Subnames> {
        let mut out = Subnames::default();
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(e.into()),
        };
        let bad = |n: usize| format!("{}: line {}: malformed", path.display(), n + 1);
        for (n, line) in text.lines().enumerate() {
            let f: Vec<&str> = line.split_whitespace().collect();
            match f.as_slice() {
                [] => {}
                ["issuer", ids @ ..] => {
                    out.issuers = ids.iter().map(|a| onion::parse_id(a).ok_or(bad(n))).collect::<Result<_, _>>()?;
                }
                ["entry", name, label, id] => {
                    let id = onion::parse_id(id).ok_or(bad(n))?;
                    if !tabminer::names::valid_name(name.as_bytes()) || !tabminer::names::valid_name(label.as_bytes()) {
                        return Err(bad(n).into());
                    }
                    let zone = out.table.entry(name.as_bytes().to_vec()).or_default();
                    zone.entries.insert(label.as_bytes().to_vec(), id);
                }
                ["held", hex] => {
                    let b = from_hex(hex).and_then(|b| tabminer::subnames::Bundle::from_bytes(&b)).ok_or(bad(n))?;
                    out.held.certs.insert((b.cert.name.clone(), b.cert.label.clone()), b);
                }
                ["withdrawn", hex] => {
                    let b = from_hex(hex).and_then(|b| tabminer::subnames::Bundle::from_bytes(&b)).ok_or(bad(n))?;
                    out.withdrawn.push(b);
                }
                _ => return Err(bad(n).into()),
            }
        }
        Ok(out)
    }

    fn save(&self, path: &std::path::Path) -> AnyResult<()> {
        let mut text = String::new();
        if !self.issuers.is_empty() {
            let ids: Vec<String> = self.issuers.iter().map(tabminer::address::encode).collect();
            text.push_str(&format!("issuer {}\n", ids.join(" ")));
        }
        let mut names: Vec<&Vec<u8>> = self.table.keys().collect();
        names.sort();
        for name in names {
            for (label, id) in &self.table[name].entries {
                text.push_str(&format!(
                    "entry {} {} {}\n",
                    String::from_utf8_lossy(name),
                    String::from_utf8_lossy(label),
                    tabminer::address::encode(id)
                ));
            }
        }
        for b in self.held.certs.values() {
            text.push_str(&format!("held {}\n", to_hex(&b.to_bytes())));
        }
        for b in &self.withdrawn {
            text.push_str(&format!("withdrawn {}\n", to_hex(&b.to_bytes())));
        }
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, text)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }
}

/// What a sub-name lookup waits for: a note under its tag, or an owner's
/// answer for a label (init mode).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum Wait {
    Tag(u64),
    Answer(Digest, Vec<u8>, Vec<u8>),
}

/// Sub-names resolved lately: their certificates by name and label, with
/// when to ask again.
#[derive(Default)]
struct Resolved {
    certs: std::collections::HashMap<(Vec<u8>, Vec<u8>), (tabminer::subnames::Bundle, u64)>,
}

fn unix_millis() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64)
}

/// A tag for a lookup of ours: random, clear of the node's own.
fn lookup_tag() -> u64 {
    tabminer::wallet::random_bytes::<8>().map(u64::from_le_bytes).unwrap_or(1) >> 1
}

/// A name's value on this node's chain, if registered.
fn chain_value(ctx: &Ctx, name: &[u8]) -> Option<Digest> {
    let rtxn = ctx.chain.env().read_txn().ok()?;
    ctx.chain.names().lookup(&rtxn, name).ok().flatten().map(|r| r.value)
}

/// The delegation under which this wallet may sign certificates for
/// `name`, whose value is `value`: none needed when the value is this
/// wallet's own id; the owner's delegation, fetched from its points, when
/// it names this wallet; an error otherwise.
fn issuing_for(ctx: &Ctx, name: &[u8], value: &Digest) -> AnyResult<Option<tabminer::subnames::Delegation>> {
    let me = ctx.wallet()?.id();
    let shown = String::from_utf8_lossy(name).into_owned();
    if *value == me {
        return Ok(None);
    }
    let mut wait = Waiter::new(ctx);
    let tag = lookup_tag();
    wait.add(Wait::Tag(tag));
    ctx.events.send(Event::GetDelegation(tag, *value, 0)).map_err(|_| "the node has stopped")?;
    let d = loop {
        match wait.rx.recv_timeout(RESOLVE_WAIT) {
            Ok(Note::Delegation { result, .. }) => break result.map_err(|e| format!("{shown}'s delegation: {e}"))?,
            Ok(_) => {}
            Err(_) => return Err(format!("{shown}'s delegation: no answer").into()),
        }
    };
    match d {
        Some(d) if d.verify(value, now()) && d.issuers.contains(&me) => Ok(Some(d)),
        _ => Err(format!("{shown} is not this wallet's, and its owner's delegation does not name this wallet").into()),
    }
}

/// A certificate for `label.name`, signed by this wallet: `to` gets it,
/// or none (a withdrawal); with the delegation that lets this wallet sign
/// it, if any. Its `seq` is above any this wallet issued for it.
fn sign_cert(
    ctx: &Ctx,
    name: &[u8],
    label: &[u8],
    to: Option<&Digest>,
    delegation: Option<tabminer::subnames::Delegation>,
) -> AnyResult<tabminer::subnames::Bundle> {
    use tabminer::subnames::{Bundle, Cert, LIFETIME_SECS};
    let key = ctx.wallet()?.identity_key();
    let issued = ctx.issued.lock().unwrap().get(&(name.to_vec(), label.to_vec())).map_or(0, |i| i.bundle.cert.seq);
    let withdrawn = ctx
        .subnames
        .lock()
        .unwrap()
        .withdrawn
        .iter()
        .filter(|b| b.cert.name == name && b.cert.label == label)
        .map(|b| b.cert.seq)
        .max()
        .unwrap_or(0);
    let last = issued.max(withdrawn);
    let seq = unix_millis().max(last + 1);
    let expiry = now() + LIFETIME_SECS;
    let cert = match to {
        Some(id) => Cert::id(&key, name, label, id, seq, expiry),
        None => Cert::none(&key, name, label, seq, expiry),
    }
    .ok_or("a malformed name or label")?;
    Ok(Bundle { cert, delegation })
}

/// Sends `b` to `to`, its holder (or the holder it withdraws), as a
/// certificate payload; the tag it goes under.
fn send_cert(ctx: &Ctx, to: &Digest, b: &tabminer::subnames::Bundle) -> u64 {
    let tag = lookup_tag();
    let out = Outbound {
        tag,
        to: *to,
        kind: onion::KIND_SUBNAME_CERT,
        inner: b.to_bytes(),
        recipient: None,
        reply: None,
        group: 0,
    };
    let _ = ctx.events.send(Event::Send(out));
    tag
}

/// Sees to the wallet's sub-names (`docs/SUBNAME_CERT.md`): drops the
/// certificates it holds that are no longer sound and the withdrawals past
/// their use; issues a certificate for every entry of its table that has
/// none, has a new holder, was not delivered (sent again each pass) or is
/// due for renewal (daily), and sends it to its holder; hands the node
/// every certificate to publish (held, issued and withdrawn), the sub-names
/// it answers for, and this wallet's delegation, signed afresh daily or
/// when its issuers change.
fn publish_subnames(ctx: &Ctx) {
    use tabminer::subnames::{LIFETIME_SECS, RENEW_SECS};
    let Some(w) = &ctx.wallet else { return };
    let _one = ctx.issuing.lock().unwrap();
    let (table, delegates, gone) = {
        let mut s = ctx.subnames.lock().unwrap();
        let gone = s.held.prune(|name| chain_value(ctx, name), now());
        let before = s.withdrawn.len();
        s.withdrawn.retain(|b| b.cert.expiry > now());
        if !gone.is_empty() || s.withdrawn.len() != before {
            let _ = s.save(&ctx.subnames_file);
        }
        (s.table.clone(), s.issuers.clone(), gone)
    };
    for name in gone {
        say(ctx, &format!("sub-name {name} lapsed: its certificate expired or its name changed hands"));
    }
    // Issue what is due, per name: whether this wallet may, once.
    if !w.address_off() {
        let mut names: Vec<&Vec<u8>> = table.keys().collect();
        names.sort();
        for name in names {
            let full = |label: &[u8]| format!("{}.{}", String::from_utf8_lossy(label), String::from_utf8_lossy(name));
            let due: Vec<(Vec<u8>, Digest)> = {
                let issued = ctx.issued.lock().unwrap();
                table[name]
                    .entries
                    .iter()
                    .filter(|(label, id)| match issued.get(&(name.clone(), (*label).clone())) {
                        Some(i) => {
                            i.bundle.cert.entry() != tabminer::subnames::Entry::Id(**id)
                                || !i.delivered
                                || now().saturating_sub(i.at) >= RENEW_SECS
                        }
                        None => true,
                    })
                    .map(|(l, id)| (l.clone(), *id))
                    .collect()
            };
            if due.is_empty() {
                continue;
            }
            let Some(value) = chain_value(ctx, name) else {
                log::line(&format!("sub-names of {}: not registered", String::from_utf8_lossy(name)));
                continue;
            };
            let delegation = match issuing_for(ctx, name, &value) {
                Ok(d) => d,
                Err(e) => {
                    log::line(&format!("sub-names: {e}"));
                    continue;
                }
            };
            for (label, id) in due {
                let b = match sign_cert(ctx, name, &label, Some(&id), delegation.clone()) {
                    Ok(b) => b,
                    Err(e) => {
                        log::line(&format!("sub-name {}: {e}", full(&label)));
                        continue;
                    }
                };
                let tag = send_cert(ctx, &id, &b);
                log::line(&format!(
                    "sub-name {}: certificate for {} sent, valid until {}",
                    full(&label),
                    tabminer::address::encode(&id),
                    log::timestamp_of(b.cert.expiry)
                ));
                let entry = Issued { bundle: b, at: now(), tag, delivered: false };
                ctx.issued.lock().unwrap().insert((name.clone(), label), entry);
            }
        }
    }
    // Issued entries no longer in the table were withdrawn (`subname del`).
    ctx.issued.lock().unwrap().retain(|(name, label), _| table.get(name).is_some_and(|z| z.entries.contains_key(label)));
    let mut certs: Vec<Vec<u8>> = {
        let s = ctx.subnames.lock().unwrap();
        s.held.bytes().into_iter().chain(s.withdrawn.iter().map(|b| b.to_bytes())).collect()
    };
    certs.extend(ctx.issued.lock().unwrap().values().map(|i| i.bundle.to_bytes()));
    let _ = ctx.events.send(Event::Certs(certs));
    // The delegation: signed afresh daily, or when its issuers change.
    let delegation = if delegates.is_empty() || w.address_off() {
        *ctx.delegation.lock().unwrap() = None;
        None
    } else {
        let mut d = ctx.delegation.lock().unwrap();
        let stale = d.as_ref().is_none_or(|(at, issuers, _)| *issuers != delegates || now().saturating_sub(*at) >= RENEW_SECS);
        if stale {
            *d = tabminer::subnames::Delegation::make(&w.identity_key(), unix_millis(), now() + LIFETIME_SECS, &delegates)
                .map(|x| (now(), delegates.clone(), x.to_bytes()));
        }
        d.as_ref().map(|(_, _, bytes)| bytes.clone())
    };
    let _ = ctx.events.send(Event::Delegate(delegation));
}

/// Waits for what `keys` name, registered for the time of the wait.
struct Waiter<'a> {
    ctx: &'a Ctx,
    keys: Vec<Wait>,
    rx: std::sync::mpsc::Receiver<Note>,
    tx: std::sync::mpsc::Sender<Note>,
}

impl<'a> Waiter<'a> {
    fn new(ctx: &'a Ctx) -> Waiter<'a> {
        let (tx, rx) = std::sync::mpsc::channel();
        Waiter { ctx, keys: Vec::new(), rx, tx }
    }

    fn add(&mut self, key: Wait) {
        self.ctx.waiting.lock().unwrap().insert(key.clone(), self.tx.clone());
        self.keys.push(key);
    }
}

impl Drop for Waiter<'_> {
    fn drop(&mut self) {
        let mut w = self.ctx.waiting.lock().unwrap();
        for k in &self.keys {
            w.remove(k);
        }
    }
}

/// `label.name` resolved to an id (`docs/SUBNAME_CERT.md`): the name's
/// value from the chain, then the sub-name's certificate (with the
/// delegation naming its issuer, when not the owner) from the full name's
/// rendezvous points in onion mode, or from the owner's node in init mode,
/// checked against that value. Cached for [`CERT_CACHE`] at most; the ask
/// and the send after it share one circuit by `group`.
fn resolve_subname(ctx: &Ctx, label: &str, name: &str, group: u64) -> AnyResult<Digest> {
    use tabminer::subnames::{Bundle, Cert, Entry};
    let (l, n) = (label.as_bytes().to_vec(), name.as_bytes().to_vec());
    if !tabminer::names::valid_name(&l) {
        return Err(format!("{label} is not a sub-name label: 1 to 32 of a-z, 0-9 and _").into());
    }
    let value = name_value(ctx, name)?;
    let id_of = |b: &Bundle| -> AnyResult<Digest> {
        match b.cert.entry() {
            Entry::Id(id) => Ok(id),
            Entry::None => Err(format!("{label}.{name} was withdrawn by {name}'s owner").into()),
            Entry::Other(k) => Err(format!("{label}.{name} is of a type this wallet does not know ({k})").into()),
        }
    };
    let cached = ctx.resolved.lock().unwrap().certs.get(&(n.clone(), l.clone())).cloned();
    if let Some((b, until)) = cached
        && until > now()
        && b.verify(&value, now())
    {
        return id_of(&b);
    }
    let missing = || format!("{label}.{name} does not exist: {name}'s owner has issued no certificate for it");
    let onion = ctx.chain.consensus_epoch()?.current.mode == tabminer::consensus::Mode::Onion;
    let started = std::time::Instant::now();
    let mut wait = Waiter::new(ctx);
    let tag = lookup_tag();
    wait.add(Wait::Tag(tag));
    let found: Option<Bundle> = if onion {
        // The full name's points hold it.
        ctx.events.send(Event::GetCert(tag, Cert::point(&n, &l), group)).map_err(|_| "the node has stopped")?;
        loop {
            match wait.rx.recv_timeout(RESOLVE_WAIT) {
                Ok(Note::Cert { result, .. }) => break result.map_err(|e| format!("{label}.{name}: {e}"))?,
                Ok(_) => {}
                Err(_) => return Err(format!("{label}.{name}: no answer").into()),
            }
        }
    } else {
        // Init mode: the owner's node answers with the certificate it issued.
        wait.add(Wait::Answer(value, n.clone(), l.clone()));
        let out = Outbound {
            tag,
            to: value,
            kind: onion::KIND_SUBNAME_QUERY,
            inner: tabminer::subnames::query(&n, &l),
            recipient: None,
            reply: None,
            group,
        };
        ctx.events.send(Event::Send(out)).map_err(|_| "the node has stopped")?;
        loop {
            match wait.rx.recv_timeout(RESOLVE_WAIT) {
                Ok(Note::Received(o)) => match tabminer::subnames::parse_answer(&o.inner) {
                    Some((_, _, b)) => break b,
                    None => return Err(format!("{label}.{name}: a malformed answer from {name}'s owner").into()),
                },
                Ok(Note::Failed { why, .. }) => return Err(format!("{label}.{name}: {why}").into()),
                Ok(_) => {}
                Err(_) => return Err(format!("{label}.{name}: {name}'s owner did not answer").into()),
            }
        }
    };
    let b = found.ok_or_else(missing)?;
    if b.cert.name != n || b.cert.label != l || !b.verify(&value, now()) {
        return Err(format!("{label}.{name}: its certificate is not signed by {name}'s owner or an issuer it names").into());
    }
    log::line(&format!(
        "sub-name {label}.{name} resolved in {:.2}s ({})",
        started.elapsed().as_secs_f64(),
        if onion { "from its points" } else { "from its owner" }
    ));
    // Only what resolves is cached: a withdrawal is asked again each time,
    // so a sub-name given out again resolves at once.
    if matches!(b.cert.entry(), Entry::Id(_)) {
        let until = b.cert.expiry.min(now() + CERT_CACHE);
        let mut r = ctx.resolved.lock().unwrap();
        r.certs.retain(|_, (_, until)| *until > now());
        r.certs.insert((n, l), (b.clone(), until));
    }
    id_of(&b)
}

/// `LABEL.NAME`, each well formed.
fn parse_subname(s: &str) -> AnyResult<(Vec<u8>, Vec<u8>)> {
    let (label, name) = s.trim_start_matches('@').split_once('.').ok_or("LABEL.NAME, as cool.example")?;
    if !tabminer::names::valid_name(label.as_bytes()) || !tabminer::names::valid_name(name.as_bytes()) {
        return Err("a label and a name are 1 to 32 of a-z, 0-9 and _".into());
    }
    Ok((label.as_bytes().to_vec(), name.as_bytes().to_vec()))
}

/// Says something from the message layer: logged, and shown at the prompt.
fn say(ctx: &Ctx, msg: &str) {
    log::line(msg);
    if ctx.prompt {
        println!("\n{msg}");
    }
}

/// What the message layer delivers: a slate to answer or to finalize, or
/// what became of a send.
fn on_note(ctx: &Ctx, note: Note) {
    // A sub-name lookup's: to the command waiting for it.
    let key = match &note {
        Note::Delegation { tag, .. }
        | Note::Cert { tag, .. }
        | Note::Failed { tag, .. }
        | Note::Delivered { tag, .. } => Some(Wait::Tag(*tag)),
        // From whoever answers: the id sent to (along the way back) or
        // the sender named.
        Note::Received(o) if o.kind == onion::KIND_SUBNAME_ANSWER => {
            let owner = o.answers.or(o.from.as_ref().map(|a| a.id));
            let Some((owner, (name, label, _))) = owner.zip(tabminer::subnames::parse_answer(&o.inner)) else {
                return;
            };
            Some(Wait::Answer(owner, name, label))
        }
        _ => None,
    };
    if let Some(key) = key
        && let Some(tx) = ctx.waiting.lock().unwrap().get(&key)
    {
        let _ = tx.send(note);
        return;
    }
    match note {
        Note::Received(o) if o.kind == onion::KIND_SUBNAME_ANSWER => {}
        Note::Received(o) if o.kind == onion::KIND_SUBNAME_CERT => on_cert(ctx, &o.inner),
        Note::Received(opened) => {
            if let Err(e) = on_message(ctx, opened) {
                say(ctx, &format!("message: {e}"));
            }
        }
        Note::Delivered { tag, to, via } => {
            let mut issued = ctx.issued.lock().unwrap();
            if let Some(((name, label), i)) = issued.iter_mut().find(|(_, i)| i.tag == tag) {
                i.delivered = true;
                log::line(&format!(
                    "sub-name {}.{}: certificate delivered to {} via {via}",
                    String::from_utf8_lossy(label),
                    String::from_utf8_lossy(name),
                    tabminer::address::encode(&to)
                ));
                return;
            }
            drop(issued);
            if ctx.outgoing.lock().unwrap().keys().any(|id| slate_tag(id) == tag) {
                say(
                    ctx,
                    &format!("slate delivered to {} via {via}; waiting for the answer", tabminer::address::encode(&to)),
                );
            }
        }
        Note::Broadcast { txid, how } => match how {
            Ok(how) => say(ctx, &format!("transaction {} {how}", short(&txid))),
            Err(why) => say(
                ctx,
                &format!(
                    "transaction {} not broadcast: {why} (it stays pooled here; cancel {} to free its inputs)",
                    short(&txid),
                    short(&txid)
                ),
            ),
        },
        // A lookup given up on.
        Note::Delegation { .. } | Note::Cert { .. } => {}
        Note::Failed { tag, to, why } => {
            let to = tabminer::address::encode(&to);
            if let Some((name, label)) =
                ctx.issued.lock().unwrap().iter().find(|(_, i)| i.tag == tag).map(|(k, _)| k.clone())
            {
                log::line(&format!(
                    "sub-name {}.{}: certificate not delivered to {to} ({why}); sent again within the hour",
                    String::from_utf8_lossy(&label),
                    String::from_utf8_lossy(&name)
                ));
                return;
            }
            let mut outgoing = ctx.outgoing.lock().unwrap();
            let id = outgoing.keys().find(|id| slate_tag(id) == tag).copied();
            match id.and_then(|id| outgoing.remove(&id).map(|_| id)) {
                // It never reached the recipient: its inputs are freed.
                Some(id) => {
                    let freed = ctx.wallet().is_ok_and(|w| w.cancel_slate(&id).is_ok());
                    say(
                        ctx,
                        &format!(
                            "could not deliver the slate to {to}: {why}{}",
                            if freed { "; it is cancelled and its inputs are spendable again" } else { "" }
                        ),
                    );
                }
                None => say(ctx, &format!("could not answer {to}: {why}")),
            }
        }
    }
}

/// A sub-name certificate sent to this wallet by its issuer
/// (`docs/SUBNAME_CERT.md`): kept and published if it is sound and names
/// this wallet, or the sub-name given up if it withdraws or moves one held.
fn on_cert(ctx: &Ctx, bytes: &[u8]) {
    use tabminer::subnames::Took;
    let (Some(b), Ok(w)) = (tabminer::subnames::Bundle::from_bytes(bytes), ctx.wallet()) else { return };
    let full = format!("{}.{}", String::from_utf8_lossy(&b.cert.label), String::from_utf8_lossy(&b.cert.name));
    let expiry = b.cert.expiry;
    let value = chain_value(ctx, &b.cert.name);
    let (took, held) = {
        let mut s = ctx.subnames.lock().unwrap();
        let took = s.held.take(b, value, &w.id(), now());
        if matches!(took, Took::Held | Took::Withdrawn)
            && let Err(e) = s.save(&ctx.subnames_file)
        {
            say(ctx, &format!("sub-names: {e}"));
        }
        (took, s.held.bytes())
    };
    match took {
        Took::Held => {
            log::line(&format!("sub-name {full}: certificate held until {}", log::timestamp_of(expiry)));
            let _ = ctx.events.send(Event::Certs(held));
        }
        Took::Withdrawn => {
            say(ctx, &format!("sub-name {full} was withdrawn by its owner"));
            let _ = ctx.events.send(Event::Certs(held));
        }
        Took::Ignored(why) => log::line(&format!("sub-name {full}: a certificate ignored: {why}")),
    }
}

/// The tag a send of slate `id` goes under: its first eight bytes.
fn slate_tag(id: &[u8; 32]) -> u64 {
    u64::from_le_bytes(id[..8].try_into().unwrap())
}

/// A message: a stage-1 slate is answered with an output of ours, a
/// stage-2 one (the answer to ours) signed and pooled.
fn on_message(ctx: &Ctx, opened: onion::Opened) -> AnyResult<()> {
    if opened.kind != onion::KIND_SLATE {
        return Err(format!("a message of unknown kind {}", opened.kind).into());
    }
    // Who it is from, if anyone: a sender that named itself (init mode), or
    // the id we sent the payload this answers to.
    let from = opened.answers.or(opened.from.as_ref().map(|a| a.id));
    let who = from.map_or("an unnamed sender".to_string(), |id| tabminer::address::encode(&id));
    let slate = Slate::from_bytes(&opened.inner).ok_or("a malformed slate")?;
    let id = slate.id;
    if slate.stage == 1 && opened.route.is_none() && opened.from.is_none() {
        return Err("a slate with no way to answer it".into());
    }
    // Answering creates an output: a flood of slates is refused. An
    // unnamed sender is counted by its route, so only the total binds.
    let key = match (&opened.from, &opened.route) {
        (Some(a), _) => a.id,
        (None, Some(r)) => r.reply_id(),
        (None, None) => onion::NOBODY,
    };
    if slate.stage == 1 && !ctx.slates.lock().unwrap().allow(&key, Instant::now()) {
        return Err(format!("too many slates from {who} lately; ignored").into());
    }
    let sent_to = ctx.outgoing.lock().unwrap().get(&id).copied();
    sync_wallet(ctx)?;
    match ctx.wallet()?.take_slate(&opened.inner, from.as_ref(), sent_to.as_ref())? {
        Incoming::Answered(slate) => {
            // Back along the payload's own path when it gave one
            // (docs/PRIVACY.md, fix 4); to the named sender otherwise.
            let out = match (opened.route, opened.from) {
                (Some(route), _) => Outbound {
                    tag: 0,
                    to: route.reply_id(),
                    kind: onion::KIND_SLATE,
                    inner: slate.to_bytes(),
                    recipient: None,
                    reply: Some(route),
                    group: 0,
                },
                (None, Some(a)) => Outbound {
                    tag: 0,
                    to: a.id,
                    kind: onion::KIND_SLATE,
                    inner: slate.to_bytes(),
                    recipient: Some(a),
                    reply: None,
                    group: 0,
                },
                (None, None) => unreachable!(),
            };
            ctx.events.send(Event::Send(out)).map_err(|_| "the node has stopped")?;
            say(
                ctx,
                &format!(
                    "receiving {} coins (fee {}) from {who}; slate {} answered",
                    fmt_coins(slate.amount as u128),
                    fmt_coins(slate.fee as u128),
                    &slate.id_hex()[..16]
                ),
            );
        }
        Incoming::Finalized(slate, signed) => {
            ctx.outgoing.lock().unwrap().remove(&slate.id);
            say(ctx, &format!("slate {} answered by {who}; signing and pooling", &slate.id_hex()[..16]));
            submit(ctx, signed);
        }
    }
    Ok(())
}

/// What a node started with `--relay` prints: its `relay` line for a
/// `consensus.txt`, ready to paste, and a note when the listening address
/// is not one others can reach as written.
fn relay_lines(address: &str, listen: SocketAddr) -> Vec<String> {
    let mut lines = vec!["relay mode: add this line to consensus.txt to be listed as a relay:".to_string()];
    if listen.ip().is_unspecified() {
        lines.push(format!("  relay {address} HOST:{}", listen.port()));
        lines.push("  (replace HOST with this node's public host name or IP)".to_string());
    } else {
        lines.push(format!("  relay {address} {listen}"));
    }
    lines
}

/// A name offer's text markers: `-----BEGIN TAB NAME OFFER-----` and its end.
const OFFER_MARKER: &str = "TAB NAME OFFER";

/// A name offer (the record the offering wallet wants signed over to it)
/// as text: base64 between markers, 64 characters a line, as slates and
/// proofs are passed around.
fn offer_text(record: &tabminer::names::Record) -> String {
    let b64 = tabminer::proofs::base64_encode(&record.to_bytes());
    let mut out = format!("-----BEGIN {OFFER_MARKER}-----\n");
    for line in b64.as_bytes().chunks(64) {
        out.push_str(core::str::from_utf8(line).unwrap());
        out.push('\n');
    }
    out.push_str(&format!("-----END {OFFER_MARKER}-----\n"));
    out
}

/// A name offer from text holding one between its markers.
fn offer_from_text(text: &str) -> Option<tabminer::names::Record> {
    let begin = format!("-----BEGIN {OFFER_MARKER}-----");
    let end = format!("-----END {OFFER_MARKER}-----");
    let body = &text[text.find(&begin)? + begin.len()..];
    let b64: String = body[..body.find(&end)?].chars().filter(|c| !c.is_whitespace()).collect();
    tabminer::names::Record::from_bytes(&tabminer::proofs::base64_decode(&b64)?)
}

/// A slate from FILE (text: slates have no other form); `-`: pasted at
/// the prompt, read up to its END line.
fn read_slate(file: &str) -> AnyResult<Slate> {
    if file == "-" {
        println!("paste the slate; it ends at its END line");
        let mut text = String::new();
        let stdin = std::io::stdin();
        while !Slate::text_ends(&text) {
            if stdin.lock().read_line(&mut text)? == 0 {
                break;
            }
        }
        return Slate::from_text(&text).ok_or_else(|| "no slate between BEGIN and END markers".into());
    }
    let bytes = std::fs::read(Path::new(file))?;
    let text = String::from_utf8_lossy(&bytes);
    Slate::from_text(&text).ok_or_else(|| {
        format!("{file} holds no slate (a slate is text: -----BEGIN {}----- and base64)", tabminer::wallet::SLATE_MARKER)
            .into()
    })
}

/// Writes a slate as text to FILE; `-`: printed.
fn write_slate(file: &str, slate: &Slate) -> std::io::Result<()> {
    if file == "-" {
        print!("{}", slate.to_text());
        return Ok(());
    }
    std::fs::write(file, slate.to_text())
}

/// Searches nonces on every thread from a time-based start until one meets
/// `target` or `cancel` says to stop. Returns the nonce, its output and the
/// hashes tried.
fn solve(
    dataset: &Dataset,
    header_hash: &Digest,
    target: &Target,
    cancel: &(dyn Fn() -> bool + Sync),
) -> Option<(Nonce, PowOutput, u64)> {
    let threads = tabminer::parallel::threads() as u64;
    let start = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(0) << 8;
    let found = AtomicBool::new(false);
    let tried = AtomicU64::new(0);
    let result = std::sync::Mutex::new(None);
    std::thread::scope(|s| {
        for t in 0..threads {
            let (found, tried, result) = (&found, &tried, &result);
            s.spawn(move || {
                let mut n = start.wrapping_add(t);
                let mut local = 0u64;
                while !found.load(Ordering::Relaxed) {
                    let nonce = nonce_from_u64(n);
                    let out = hashimoto(dataset, header_hash, &nonce);
                    local += 1;
                    if target.is_met_by(&out.result) && !found.swap(true, Ordering::Relaxed) {
                        *result.lock().unwrap() = Some((nonce, out));
                    }
                    if local % 64 == 0 && t == 0 && cancel() {
                        found.store(true, Ordering::Relaxed);
                    }
                    n = n.wrapping_add(threads);
                }
                tried.fetch_add(local, Ordering::Relaxed);
            });
        }
    });
    let (nonce, out) = result.into_inner().unwrap()?;
    Some((nonce, out, tried.into_inner()))
}

/// The block reward transaction and the wallet's new output in it.
fn reward(wallet: &Wallet, amount: u64) -> AnyResult<(Transaction, Output)> {
    let out = wallet.receive(amount)?;
    Ok((UnsignedTransaction::new(vec![], vec![out]).sign(|_, _, _| Err::<Sig, ()>(())).unwrap(), out))
}

/// The mining loop: builds, proves, mines and submits blocks on the tip
/// until `blocks` are accepted (0 for no limit) or the node stops.
fn mine(ctx: &Ctx, dataset: &Dataset, blocks: u64, jobs: usize, delay: Duration) -> AnyResult<()> {
    let params = ctx.params;
    let agg = params.aggregator;
    let chain = &ctx.chain;
    let wallet = ctx.wallet()?;
    let tip = chain.tip()?.unwrap();
    log::line(&format!(
        "mining from height {}; segments of 2^{} rows at rate 1/{}, up to {} per block; {}",
        tip.height,
        agg.segment_log_n,
        1 << agg.segment.log_blowup,
        agg.max_segments,
        if agg.direct {
            "proofs checked segment by segment, no chain proof".to_string()
        } else {
            format!("nodes at rate 1/{}, wrap at 1/{}", 1 << agg.outer.log_blowup, 1 << agg.wrap.log_blowup)
        }
    ));

    let mut mined = 0u64;
    let mut waited = false;
    let unchecked = chain.verifier().is_unchecked();
    // Debugging: a generator for random outputs and spends.
    let mut rng = now() ^ 0x9e37_79b9_7f4a_7c15;
    // Rounds in a row whose transactions no longer applied: more than a
    // race with the pool's revalidation, past a few.
    let mut stale = 0;
    while !ctx.stop.load(Ordering::Acquire) && (blocks == 0 || mined < blocks) {
        // Mining on a stale tip wastes the proof: wait until caught up.
        if ctx.syncing.load(Ordering::Acquire) {
            if !waited {
                log::line("waiting for the node to catch up before mining");
                waited = true;
            }
            std::thread::sleep(Duration::from_millis(500));
            continue;
        }
        waited = false;
        // Follow the chain: rewards land or are settled, also without a
        // prompt.
        if let Err(e) = sync_wallet(ctx) {
            log::line(&format!("wallet: {e}"));
        }
        let started = Instant::now();
        // The node bumps the counter after its applier reports, so the bump
        // for our last block may come after we read the tip: a change counts
        // only if the tip is another.
        let generation = AtomicU64::new(ctx.tip_changes.load(Ordering::Acquire));
        let tip = chain.tip()?.unwrap();
        let tip_id = tip.hash();
        let cancel = || {
            if ctx.stop.load(Ordering::Acquire) {
                return true;
            }
            let now = ctx.tip_changes.load(Ordering::Acquire);
            if now == generation.load(Ordering::Acquire) {
                return false;
            }
            if chain.tip().ok().flatten().is_some_and(|t| t.hash() == tip_id) {
                generation.store(now, Ordering::Release);
                return false;
            }
            true
        };
        let height = tip.height + 1;
        if height > params.final_height() {
            log::line("the chain has reached its final block; nothing left to mine");
            break;
        }
        let subsidy = params.subsidy(height);

        // Transactions: the reward, then the pooled ones, the aged reserve
        // first and the rest by fee rate, while they fit the block's segment and size limits. Size: header, body
        // counts, input positions, outputs, the name section and room for
        // the proof. The name section also sweeps expired commits.
        let sweeps: Vec<u64> = {
            let rtxn = chain.env().read_txn()?;
            Mempool::sweeps(chain.names(), &rtxn, height)
        };
        let sweep_bytes = sweeps.len() * POSITION_SIZE;
        let size = |ins: usize, outs: usize, names: usize| {
            HEADER_SIZE + Body::size_of(ins, outs, names + sweep_bytes, PROOF_SIZE_ALLOWANCE)
        };
        let fits = |ins: usize, outs: usize, names: usize, items: &dyn Fn(usize) -> (Vec<usize>, bool), n: usize| {
            pack(n, items, agg.segment_rows()).len() <= agg.max_segments
                && size(ins, outs, names) <= params.max_block_size
        };
        let pooled: Vec<Transaction> = {
            let rtxn = chain.env().read_txn()?;
            ctx.mempool.lock().unwrap().select(chain.names(), &rtxn, height, ctx.reserve_bytes, |chosen| {
                let ins: usize = chosen.iter().map(|t| t.inputs.len()).sum();
                let outs: usize = 1 + chosen.iter().map(|t| t.outputs.len()).sum::<usize>();
                let names: usize = chosen.iter().flat_map(|t| t.ops.iter()).map(|op| op.block_op().size()).sum();
                // the name segment holds them all, with the sweeps
                let name_rows = sweeps.len() * tabminer::name_air::SWEEP_ROWS
                    + chosen.iter().flat_map(|t| t.ops.iter()).map(tabminer::name_air::op_rows_bound).sum::<usize>();
                if name_rows >= agg.name_rows() {
                    return false;
                }
                let items = |t: usize| {
                    if t == 0 {
                        (vec![tabminer::block_air::ROWS_PER_OUTPUT], false)
                    } else {
                        tabminer::block_air::item_rows_of(chosen[t - 1])
                    }
                };
                fits(ins, outs, names, &items, chosen.len() + 1)
            })
        };
        let fees = Mempool::fees(&pooled);
        let balance = {
            let rtxn = chain.env().read_txn()?;
            wallet.balance(chain.utxo(), &rtxn)?
        };
        let (reward_tx, reward_out) = reward(wallet, subsidy + fees)?;
        wallet.note_reward(&reward_out.commitment, height)?;
        *ctx.in_flight.lock().unwrap() = Some(reward_out.commitment);
        // A block that never gets mined leaves no record behind.
        let abandon = || {
            if let Err(e) = wallet.forget(&reward_out.commitment) {
                log::line(&format!("  forgetting the reward of block {height}: {e}"));
            }
        };
        let mut txs = vec![reward_tx];
        txs.extend(pooled);
        let build_time = started.elapsed();

        // Witnesses: apply the transactions and the name section in a
        // transaction that is thrown away, recording the tree paths.
        let (segments, names, statement, inputs, outputs) = {
            let mut wtxn = chain.env().write_txn()?;
            let utxo = chain.utxo();
            let prev_state_root = utxo.root(&wtxn)?;
            let first_output_position = utxo.next_position(&wtxn)?;
            let segments = match SegmentWitness::collect_by_rows(utxo, &mut wtxn, &txs, agg.segment_rows(), height) {
                Ok(s) => s,
                // A block applied since the transactions were chosen, or
                // just before (the node revalidates the pool right after),
                // spent or moved one of their inputs.
                Err(utxo::Error::CorruptIndex) if stale < 20 => {
                    stale += 1;
                    drop(wtxn);
                    abandon();
                    let why = if cancel() { "the tip changed" } else { "a pooled transaction no longer applies" };
                    log::line(&format!("  {why} while building block {height}; starting over"));
                    std::thread::sleep(Duration::from_millis(200));
                    continue;
                }
                Err(e) => return Err(e.into()),
            };
            stale = 0;
            let ops: Vec<NameOp> = txs.iter().flat_map(|t| t.ops.iter().cloned()).collect();
            let names = match NameWitness::collect(utxo, chain.names(), &mut wtxn, height, &ops, &sweeps) {
                Ok(n) => n,
                // The pool admitted an operation the state no longer
                // allows; it is revalidated after every block. Start over.
                Err(e) => {
                    drop(wtxn);
                    abandon();
                    log::line(&format!("  name operations no longer apply ({e}); starting over"));
                    std::thread::sleep(Duration::from_millis(500));
                    continue;
                }
            };
            let new_state_root = utxo.root(&wtxn)?;
            wtxn.abort();
            let inputs: Vec<u64> = segments.iter().flat_map(|s| s.positions()).collect();
            let outputs: Vec<_> = segments.iter().flat_map(|s| s.block_outputs()).collect();
            let body = Body {
                inputs: inputs.clone(),
                outputs: outputs.clone(),
                ops: names.block_ops(),
                sweeps: names.sweeps(),
                proof: vec![],
            };
            let statement = Statement::from_block(&BlockStatement {
                height,
                prev_state_root,
                new_state_root,
                first_output_position,
                subsidy,
                body: &body,
                parent_work: chain.parent_work(&tip),
                parent_hash: tip.hash(),
            });
            (segments, names, statement, inputs, outputs)
        };

        log::line(&format!(
            "{} block {height} on {}: {} txs ({} in, {} out, {} name ops, {} sweeps, {} in fees) in {} segment{}, wallet {} confirmed",
            if unchecked { "building (debug: not proving)" } else { "proving" },
            short(&tip.hash()),
            txs.len(),
            inputs.len(),
            outputs.len(),
            names.ops.len() - names.sweeps().len(),
            names.sweeps().len(),
            fmt_coins(fees as u128),
            segments.len(),
            if segments.len() == 1 { "" } else { "s" },
            fmt_coins(balance.confirmed)
        ));
        // The chain proof builds on the previous block's.
        let planned = chain.verifier().needs_plan();
        let prev = if height > 1 && planned { chain.proof_statement(height - 1)? } else { None };
        let t = Instant::now();
        if planned {
            chain.verifier().shape(segments.len());
        }
        let plan_time = t.elapsed();
        let t = Instant::now();
        let report = |p: Progress| match p {
            Progress::Segment { index, count, elapsed } => {
                log::line(&format!("  segment {}/{count} proven in {}", index + 1, secs(elapsed)))
            }
            Progress::Name { elapsed } => log::line(&format!("  name segment proven in {}", secs(elapsed))),
            Progress::Work { elapsed } => log::line(&format!("  parent's work proven in {}", secs(elapsed))),
            Progress::Node { segments, log_n, hash_log_n, root, elapsed } => log::line(&format!(
                "  {} over {segments} segment{} (2^{log_n} + 2^{hash_log_n} rows) proven in {}",
                if root { "root node" } else { "node" },
                if segments == 1 { "" } else { "s" },
                secs(elapsed)
            )),
            Progress::Wrap { log_n, hash_log_n, elapsed } => {
                log::line(&format!("  wrap (2^{log_n} + 2^{hash_log_n} rows) proven in {}", secs(elapsed)))
            }
            Progress::Chain { elapsed } => log::line(&format!("  chain step proven in {}", secs(elapsed))),
        };
        let prev_ref = prev.as_ref().map(|(st, proof)| (height - 1, st, proof.as_slice(), &tip));
        let proof = if unchecked {
            // Debugging: a stand-in the size of a real proof.
            Some(vec![0u8; DEBUG_PROOF_SIZE])
        } else {
            chain.verifier().prove_block(height, &statement, &segments, &names, prev_ref, jobs, &report, &cancel)
        };
        let Some(proof) = proof else {
            abandon();
            if ctx.stop.load(Ordering::Acquire) {
                break;
            }
            log::line(&format!("  tip changed while proving block {height}; starting over"));
            continue;
        };
        let prove_time = t.elapsed();

        let (mut inputs, mut outputs) = (inputs, outputs);
        // Debugging: random outputs, and spends of unspent outputs picked
        // at random from the whole set (not the wallet's), up to the block
        // size limit.
        if let Some((n_out, n_spend)) = ctx.debug_fill {
            let used = HEADER_SIZE + Body::size_of(inputs.len(), outputs.len(), 0, DEBUG_PROOF_SIZE);
            let room = params.max_block_size.saturating_sub(used);
            let need = n_out * BLOCK_OUTPUT_SIZE + n_spend * POSITION_SIZE;
            let (n_out, n_spend) =
                if need > room { (n_out * room / need, n_spend * room / need) } else { (n_out, n_spend) };
            let mut next_random = || {
                rng ^= rng << 13;
                rng ^= rng >> 7;
                rng ^= rng << 17;
                rng
            };
            let ours: std::collections::HashSet<_> = wallet.outputs()?.into_iter().map(|o| o.commitment).collect();
            let mut taken: std::collections::HashSet<u64> = inputs.iter().copied().collect();
            let rtxn = chain.env().read_txn()?;
            let made = chain.utxo().next_position(&rtxn)?;
            let (mut spends, mut spent) = (0, 0u128);
            for _ in 0..n_spend * 4 {
                if spends == n_spend || made == 0 {
                    break;
                }
                let from = next_random() % made;
                let window = chain.utxo().unspent_in(&rtxn, from, (from + 256).min(made))?;
                if let Some((p, (_, slot, _))) =
                    window.iter().find(|(p, (c, _, _))| !taken.contains(p) && !ours.contains(c))
                {
                    taken.insert(*p);
                    inputs.push(*p);
                    spent += tabminer::transaction::slot_parts(slot).map_or(0, |(_, a)| a as u128);
                    spends += 1;
                }
            }
            drop(rtxn);
            // The random outputs carry what the random spends took, so the
            // supply still balances (docs/AMOUNTS.md).
            let n_out = if spent > 0 { n_out.max(1) } else { n_out };
            for i in 0..n_out {
                let mut random_fp = || tabminer::poseidon2::Fp::new((next_random() % P as u64) as u32);
                let commitment = core::array::from_fn(|_| random_fp());
                let memo = core::array::from_fn(|_| random_fp());
                let share = spent / n_out as u128 + if i == 0 { spent % n_out as u128 } else { 0 };
                let amount = u64::try_from(share).unwrap_or(u64::MAX);
                outputs.push(BlockOutput { commitment, memo, amount });
            }
            log::line(&format!("  debug fill: {n_out} random outputs, {spends} random spends"));
        }
        let body = Body { inputs, outputs, ops: names.block_ops(), sweeps: names.sweeps(), proof };
        let timestamp = now().max(chain.earliest_timestamp(&tip)?);
        let mut header = match chain.template(&body, timestamp) {
            Ok(h) => h,
            // Another node spent or reorganized away outputs of ours.
            Err(e) if ctx.debug_fill.is_some() => {
                log::line(&format!("  debug fill: {e}; trying again"));
                abandon();
                continue;
            }
            // A block applied since the proof was made (the tip changed
            // after the prover's last look) spent one of the inputs: as for
            // a change while building or proving, start over, never stop.
            Err(e) if cancel() || matches!(e, tabminer::chain::ChainError::UnknownInput(_)) => {
                abandon();
                let why = if cancel() { "the tip changed" } else { "a pooled transaction no longer applies" };
                log::line(&format!("  {why} while finishing block {height} ({e}); starting over"));
                continue;
            }
            Err(e) => return Err(e.into()),
        };
        let target = chain.expected_target(&tip)?;
        let t = Instant::now();
        let Some((nonce, out, hashes)) = solve(dataset, &header.pow_hash(), &target, &cancel) else {
            abandon();
            if ctx.stop.load(Ordering::Acquire) {
                break;
            }
            log::line(&format!("  tip changed while mining block {height}; starting over"));
            continue;
        };
        let mine_time = t.elapsed();
        header.nonce = nonce;
        header.mix = out.mix;
        let block = Block { header, body };
        log::line(&format!(
            "  mined {} after {} hashes in {} (work 2^{:.1}); {} KB proof",
            short(&header.hash()),
            hashes,
            secs(mine_time),
            work_bits(&target),
            block.body.proof.len() / 1000,
        ));

        // The node applies and announces it; wait for the tip to move.
        let t = Instant::now();
        wallet.reward_found(&reward_out.commitment, &digest_to_bytes(&header.hash()))?;
        ctx.events.send(Event::Mined(block))?;
        // Until the node has applied it, whatever the verdict: a tip change
        // from a peer's block meanwhile says nothing of ours.
        let mut said = 0;
        while !ctx.stop.load(Ordering::Acquire) && t.elapsed() < ACCEPT_TIMEOUT {
            if chain.entry(&header.hash())?.is_some_and(|e| !e.header_only) {
                break;
            }
            // Refused with nothing kept of it (a clock or storage fault).
            if let Some((_, why)) = ctx.refused.lock().unwrap().as_ref().filter(|(id, _)| *id == header.hash()) {
                log::line(&format!("  block {height}: refused by the node: {why}"));
                break;
            }
            if t.elapsed().as_secs() / 60 > said {
                said += 1;
                log::line(&format!("  block {height}: the node is still applying it after {said} min"));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let accepted = chain.tip()?.unwrap().hash() == header.hash();
        if !accepted {
            // A side block may yet win a reorganization, so its reward stays
            // on record; a block the node did not keep at all is forgotten.
            if chain.entry(&header.hash())?.is_some_and(|e| !e.invalid) {
                log::line(&format!("  lost block {height}: {} is a side block, not the tip", short(&header.hash())));
            } else {
                abandon();
                log::line(&format!("  lost block {height}: {} was not accepted", short(&header.hash())));
            }
        }
        mined += u64::from(accepted);
        if accepted {
            // Where applying it went, phase by phase.
            let phases = chain.last_timings();
            let sum: f64 = phases.iter().map(|(_, s)| s).sum();
            let parts: Vec<String> = phases.iter().map(|(n, s)| format!("{n} {s:.3}s")).collect();
            log::line(&format!("  applied in {sum:.3}s: {}", parts.join(", ")));
        }
        log::line(&format!(
            "  total {} (build {}, plan {}, prove {}, mine {}, accept {})",
            secs(started.elapsed()),
            secs(build_time),
            secs(plan_time),
            secs(prove_time),
            secs(mine_time),
            secs(t.elapsed())
        ));
        // `--delay-blocks`: a pause before the next block, cut short by a
        // stop.
        if !delay.is_zero() && (blocks == 0 || mined < blocks) {
            let until = Instant::now() + delay;
            while Instant::now() < until && !ctx.stop.load(Ordering::Acquire) {
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
    Ok(())
}
