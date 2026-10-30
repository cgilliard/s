//! Makes mainnet's genesis: writes `src/genesis.rs` with the current time,
//! the hash of the latest Bitcoin block (so the chain provably did not exist
//! before it) and the initial difficulty for an expected hashrate.
//!
//! ```text
//! cargo run --release --bin genesis -- [--hashrate H] [--bitcoin-hash HEX] [--timestamp T] [--out FILE]
//! ```
//!
//! `--hashrate` is the network's expected proof-of-work rate in hashes per
//! second at launch: the first blocks then average ten minutes. Without it
//! the target is the testing one, 2^232, about 65,536 hashes per block, so
//! blocks come as fast as they can be proven; use it for a real launch. Without `--bitcoin-hash` the tip of Bitcoin is fetched from
//! mempool.space with `curl`. Every run makes a new chain: run it just
//! before launch, rebuild, and publish the genesis id it prints.

use std::process::Command;

use tabminer::chain::ChainParams;
use tabminer::difficulty::{IDEAL_BLOCK_TIME, U256};
use tabminer::poseidon2::digest_to_bytes;

const API: &str = "https://mempool.space/api";
/// The testing target: 2^232, about 65,536 hashes per block.
const TEST_TARGET: U256 = U256([0, 0, 0, 1 << 40]);

struct Args {
    hashrate: Option<u64>,
    bitcoin_hash: Option<String>,
    timestamp: Option<u64>,
    out: String,
}

fn parse_args() -> Result<Args, String> {
    let mut a = Args {
        hashrate: None,
        bitcoin_hash: None,
        timestamp: None,
        out: concat!(env!("CARGO_MANIFEST_DIR"), "/src/genesis.rs").to_string(),
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut value = || it.next().ok_or(format!("{flag} needs a value"));
        match flag.as_str() {
            "--hashrate" => {
                a.hashrate = Some(value()?.parse().map_err(|_| "--hashrate: not a number".to_string())?)
            }
            "--bitcoin-hash" => a.bitcoin_hash = Some(value()?),
            "--timestamp" => a.timestamp = Some(value()?.parse().map_err(|_| "--timestamp: not a number".to_string())?),
            "--out" => a.out = value()?,
            "-h" | "--help" => return Err(String::new()),
            _ => return Err(format!("unknown option {flag}")),
        }
    }
    if a.hashrate == Some(0) {
        return Err("--hashrate must be positive".into());
    }
    Ok(a)
}

fn get(url: &str) -> Result<String, String> {
    let out = Command::new("curl")
        .args(["-sSf", "--max-time", "20", url])
        .output()
        .map_err(|e| format!("running curl: {e}"))?;
    if !out.status.success() {
        return Err(format!("{url}: {}", String::from_utf8_lossy(&out.stderr).trim()));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// The integer after `"key":` in a flat JSON object.
fn json_u64(json: &str, key: &str) -> Option<u64> {
    let at = json.find(&format!("\"{key}\":"))? + key.len() + 3;
    let digits: String =
        json[at..].chars().skip_while(|c| c.is_whitespace()).take_while(char::is_ascii_digit).collect();
    digits.parse().ok()
}

fn parse_hash(hex: &str) -> Result<[u8; 32], String> {
    if hex.len() != 64 {
        return Err(format!("a block hash is 64 hex digits, got {}", hex.len()));
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).map_err(|_| format!("not hex: {hex}"))?;
    }
    Ok(out)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The target at which `hashrate` finds a block every ten minutes on
/// average: the proof-of-work result is a 248-bit number, so a hash
/// passes with probability `(target + 1) / 2^248`.
fn target_for(hashrate: u64, max: U256) -> U256 {
    let hashes = U256::from_u64(hashrate.saturating_mul(IDEAL_BLOCK_TIME as u64).max(1));
    let one = U256::ONE.shift_left(248);
    let t = one.div(hashes).checked_sub(U256::ONE).unwrap_or(U256::ZERO);
    if t > max { max } else { t }
}

fn run(a: &Args) -> Result<(), String> {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_err(|e| e.to_string())?.as_secs();
    let timestamp = a.timestamp.unwrap_or(now);
    let hash_hex = match &a.bitcoin_hash {
        Some(h) => h.to_ascii_lowercase(),
        None => get(&format!("{API}/blocks/tip/hash"))?.to_ascii_lowercase(),
    };
    let hash = parse_hash(&hash_hex)?;
    let info = get(&format!("{API}/block/{hash_hex}")).ok();
    let height = info.as_deref().and_then(|j| json_u64(j, "height"));
    let btc_time = info.as_deref().and_then(|j| json_u64(j, "timestamp"));
    if let Some(t) = btc_time
        && t > timestamp
    {
        return Err(format!("the Bitcoin block's time {t} is after the genesis time {timestamp}"));
    }
    let base = ChainParams::MAINNET;
    // The testing target unless a launch hashrate is given.
    let target = match a.hashrate {
        Some(h) => target_for(h, base.max_target),
        None => TEST_TARGET,
    };
    // Expected hashes per block: 2^248 / (target + 1).
    let per_block = U256::ONE.shift_left(248).div(target.saturating_add(U256::ONE));
    let params = ChainParams { genesis_timestamp: timestamp, genesis_nonce: hash, genesis_target: target, ..base };
    let id = hex(&digest_to_bytes(&params.genesis().header.hash()));
    let file = format!(
        r#"//! Mainnet's genesis, written by `tools/genesis.rs`: do not edit by hand.
//!
//! The genesis block is empty, timestamped {timestamp}, and its nonce is
//! the hash of Bitcoin block {height_doc}, so the chain did not exist before that block.
//! Its first blocks need about {per} hashes each ({rate}).

/// Genesis time, unix seconds; the ASERT anchor.
pub const TIMESTAMP: u64 = {timestamp};
/// The Bitcoin block hash, in the byte order block explorers show.
pub const BITCOIN_HASH_HEX: &str = "{hash_hex}";
pub const BITCOIN_HASH: [u8; 32] = {hash:?};
/// Height and time of that Bitcoin block, for reference.
pub const BITCOIN_HEIGHT: u64 = {bh};
pub const BITCOIN_TIME: u64 = {bt};
/// Target of the first block after genesis (little-endian 64-bit limbs).
pub const TARGET: [u64; 4] = {limbs:?};
/// Expected hashes per block at that target.
pub const HASHES_PER_BLOCK: u64 = {per};
/// The genesis block id, as `tabminer show` prints it.
pub const ID: &str = "{id}";
"#,
        height_doc = height.map_or("(height unknown)".to_string(), |h| h.to_string()),
        per = per_block.0[0],
        rate = a.hashrate.map_or("the testing target".to_string(), |h| format!("ten minutes at {h} hashes per second")),
        bh = height.unwrap_or(0),
        bt = btc_time.unwrap_or(0),
        limbs = target.0,
    );
    std::fs::write(&a.out, file).map_err(|e| format!("{}: {e}", a.out))?;
    println!("genesis written to {}", a.out);
    println!("  time       {timestamp}");
    println!("  bitcoin    {hash_hex}{}", height.map_or(String::new(), |h| format!(" (height {h})")));
    match a.hashrate {
        Some(h) => println!("  hashrate   {h} H/s: first blocks need about {} hashes", per_block.0[0]),
        None => println!("  target     testing: about {} hashes per block (pass --hashrate for a launch)", per_block.0[0]),
    }
    println!("  id         {id}");
    println!("rebuild tabminer; data directories of any earlier genesis will be refused");
    Ok(())
}

fn main() {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            if !e.is_empty() {
                eprintln!("error: {e}\n");
            }
            eprintln!("usage: genesis [--hashrate H] [--bitcoin-hash HEX] [--timestamp T] [--out FILE]");
            std::process::exit(2);
        }
    };
    if let Err(e) = run(&args) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
