//! The binary driven through its prompt, as a user drives it: nodes on a
//! `--network dev` chain of their own on loopback, commands written to
//! stdin, and their answers read from stdout. A step that does not happen
//! in time fails the test with every process's output.
//!
//! The dev networks are built in with the `dev` feature only, so these
//! tests are too. Each runs as a job of its own in CI (several miners on
//! one runner starve each other's blocks): locally,
//! `cargo test --release --features dev --test wallet -- --ignored`.

#![cfg(feature = "dev")]

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{Receiver, RecvTimeoutError, channel};
use std::time::{Duration, Instant};

/// A data directory under the system's temporary directory, removed when
/// dropped.
struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> TempDir {
        let p = std::env::temp_dir().join(format!("tabminer-bin-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }
}

impl Drop for TempDir {
    /// Removes the directory, unless the test failed: then it is kept,
    /// with the logs, for a look.
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!("kept {}", self.0.display());
        } else {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

/// One running `tabminer`, its stdout and stderr read line by line.
struct Proc {
    name: &'static str,
    child: Child,
    stdin: Option<ChildStdin>,
    lines: Receiver<String>,
    seen: Vec<String>,
    data: PathBuf,
    /// Where it listens, from its "listening on" line.
    addr: String,
}

impl Proc {
    /// Starts one on a port of the system's choosing, and waits until it
    /// listens.
    fn start(name: &'static str, data: &Path, args: &[&str]) -> Proc {
        Proc::start_with(name, data, args, &[])
    }

    /// [`Proc::start`] with `env` set too.
    fn start_with(name: &'static str, data: &Path, args: &[&str], env: &[(&str, &str)]) -> Proc {
        let mut child = Command::new(env!("CARGO_BIN_EXE_tabminer"))
            .args(args)
            .envs(env.iter().copied())
            .args(["--network", "dev", "--no-seeds", "--listen", "127.0.0.1:0", "--data"])
            .arg(data)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let (tx, lines) = channel();
        let out = child.stdout.take().unwrap();
        let err = child.stderr.take().unwrap();
        let tx2 = tx.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(out).lines().map_while(Result::ok) {
                let _ = tx.send(line);
            }
        });
        std::thread::spawn(move || {
            for line in BufReader::new(err).lines().map_while(Result::ok) {
                let _ = tx2.send(format!("stderr: {line}"));
            }
        });
        let stdin = child.stdin.take();
        let mut p = Proc { name, child, stdin, lines, seen: Vec::new(), data: data.to_path_buf(), addr: String::new() };
        let line = p.expect("listening line", 60, |l| l.starts_with("listening on "));
        p.addr = line["listening on ".len()..].split(';').next().unwrap().to_string();
        p
    }

    fn send(&mut self, command: &str) {
        let stdin = self.stdin.as_mut().expect("stdin is open");
        writeln!(stdin, "{command}").unwrap();
        stdin.flush().unwrap();
    }

    /// The next line meeting `want` within `wait`, the prompt's "> "
    /// taken off; `None` once `wait` has passed.
    fn next_matching(&mut self, want: &dyn Fn(&str) -> bool, wait: Duration) -> Option<String> {
        let deadline = Instant::now() + wait;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.lines.recv_timeout(left) {
                Ok(line) => {
                    self.seen.push(line.clone());
                    let line = line.trim_start_matches("> ").to_string();
                    if want(&line) {
                        return Some(line);
                    }
                }
                Err(RecvTimeoutError::Timeout) => return None,
                Err(RecvTimeoutError::Disconnected) => {
                    std::thread::sleep(left.min(Duration::from_millis(100)));
                    if Instant::now() >= deadline {
                        return None;
                    }
                }
            }
        }
    }

    /// Waits up to `secs` for a line meeting `want`.
    fn expect(&mut self, what: &str, secs: u64, want: impl Fn(&str) -> bool) -> String {
        match self.next_matching(&want, guard(secs)) {
            Some(line) => line,
            None => panic!("{}: no {what} within {secs} s", self.name),
        }
    }

    /// Runs `command` once a second until a line of its answer meets
    /// `want`, for up to `secs`.
    fn poll(&mut self, command: &str, what: &str, secs: u64, want: impl Fn(&str) -> bool) -> String {
        let deadline = Instant::now() + guard(secs);
        while Instant::now() < deadline {
            self.send(command);
            if let Some(line) = self.next_matching(&want, Duration::from_secs(1)) {
                return line;
            }
        }
        panic!("{}: `{command}` never showed {what} within {secs} s", self.name);
    }

    /// Writes `exit` and waits up to `secs` for the process to end.
    fn exit(&mut self, secs: u64) -> std::process::ExitStatus {
        self.send("exit");
        let deadline = Instant::now() + guard(secs);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status;
            }
            assert!(Instant::now() < deadline, "{}: still running {secs} s after exit", self.name);
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// Waits up to `secs` for the process to end by itself, and that it
    /// failed.
    fn dies(&mut self, secs: u64) {
        let deadline = Instant::now() + guard(secs);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(!status.success(), "{}: ended cleanly", self.name);
                return;
            }
            assert!(Instant::now() < deadline, "{}: still running after {secs} s", self.name);
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// Waits up to `secs` for a line of its log containing `text`.
    fn expect_log(&mut self, text: &str, secs: u64) {
        let deadline = Instant::now() + guard(secs);
        loop {
            let log = std::fs::read_to_string(self.data.join("tabminer.log")).unwrap_or_default();
            if log.contains(text) {
                return;
            }
            assert!(Instant::now() < deadline, "{}: no `{text}` in its log within {secs} s", self.name);
            std::thread::sleep(Duration::from_millis(250));
        }
    }

    /// Sends `amount` to `to` (an address or @name), trying again while
    /// the lookup or the send fails, for up to `secs`.
    fn pay(&mut self, amount: &str, to: &str, secs: u64) {
        let deadline = Instant::now() + guard(secs);
        loop {
            self.send(&format!("send {amount} {to}"));
            let line = self.expect("the send's outcome", 60, |l| {
                (l.starts_with("slate ") && l.contains("sent to")) || l.starts_with("error:")
            });
            if line.starts_with("slate ") {
                return;
            }
            assert!(Instant::now() < deadline, "{}: `send {amount} {to}` kept failing: {line}", self.name);
            std::thread::sleep(Duration::from_secs(2));
        }
    }

    /// Waits up to `secs` for the chain to reach `at_least`.
    fn reach(&mut self, at_least: u64, secs: u64) {
        let deadline = Instant::now() + guard(secs);
        while self.height() < at_least {
            assert!(Instant::now() < deadline, "{}: height {at_least} never came", self.name);
            std::thread::sleep(Duration::from_millis(500));
        }
    }

    /// Waits up to `secs` for the wallet to hold nothing: no outputs, none
    /// confirmed, none pending.
    fn holds_nothing(&mut self, secs: u64) {
        self.poll("outputs", "no outputs", secs, |l| l == "no outputs");
        self.send("balance");
        let confirmed = self.expect("the confirmed line", 10, |l| l.starts_with("confirmed"));
        let pending = self.expect("the pending line", 10, |l| l.starts_with("pending"));
        assert_eq!(amount(&confirmed, "confirmed"), Some(0.0), "{}: {confirmed}", self.name);
        assert_eq!(amount(&pending, "pending"), Some(0.0), "{}: {pending}", self.name);
    }

    /// The chain's height, from `status`.
    fn height(&mut self) -> u64 {
        self.send("status");
        let line = self.expect("the tip", 10, |l| l.starts_with("tip      height "));
        line["tip      height ".len()..].split_whitespace().next().unwrap().parse().unwrap()
    }

    /// The recovery phrase it printed when it made its wallet.
    fn phrase(&self) -> String {
        let words = |l: &str| {
            l.split_whitespace().count() == 12 && l.trim().chars().all(|c| c == ' ' || c.is_ascii_lowercase())
        };
        self.seen
            .iter()
            .find(|l| words(l))
            .unwrap_or_else(|| panic!("{}: printed no phrase", self.name))
            .trim()
            .to_string()
    }

    /// The wallet's address, from `address`.
    fn address(&mut self) -> String {
        self.send("address");
        self.expect("address", 10, |l| l.starts_with("tab1"))
    }
}

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if std::thread::panicking() {
            while let Ok(line) = self.lines.try_recv() {
                self.seen.push(line);
            }
            eprintln!("---- {} output ----", self.name);
            for line in &self.seen {
                eprintln!("{line}");
            }
            if let Ok(log) = std::fs::read_to_string(self.data.join("tabminer.log")) {
                eprintln!("---- {} log (last 60 lines) ----", self.name);
                let lines: Vec<&str> = log.lines().collect();
                for line in &lines[lines.len().saturating_sub(60)..] {
                    eprintln!("{line}");
                }
            }
        }
    }
}

/// Runs `tabminer restore` into `data` with `phrase` and no passphrase.
fn restore(data: &Path, phrase: &str) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_tabminer"))
        .args(["restore", "--network", "dev", "--data"])
        .arg(data)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    writeln!(child.stdin.take().unwrap(), "{phrase}\n").unwrap();
    let out = child.wait_with_output().unwrap();
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    assert!(out.status.success() && text.contains("wallet restored in"), "restore failed: {text}");
}

/// How long a step may take before the test calls it stuck: generous, and
/// longer in debug builds.
fn guard(secs: u64) -> Duration {
    Duration::from_secs(if cfg!(debug_assertions) { 3 * secs } else { secs })
}

/// A coin amount line such as `confirmed 12.50000000  spendable`: the
/// amount.
fn amount(line: &str, label: &str) -> Option<f64> {
    line.strip_prefix(label)?.split_whitespace().next()?.parse().ok()
}

/// A seed relay S, a miner A and a node B, all peers on loopback; S is the
/// rendezvous point of both wallets (init mode).
struct Net {
    s: Proc,
    a: Proc,
    b: Proc,
    _dirs: [TempDir; 3],
}

impl Net {
    fn start(name: &str) -> Net {
        let dirs = [
            TempDir::new(&format!("{name}-s")),
            TempDir::new(&format!("{name}-a")),
            TempDir::new(&format!("{name}-b")),
        ];
        // S first, then B and A pointed at what they listen on.
        let s = Proc::start("S", &dirs[0].0, &["node", "--no-wallet", "--relay"]);
        let seed = s.addr.clone();
        let b = Proc::start("B", &dirs[2].0, &["node", "--seed", &seed, "--peer", &seed]);
        let a = Proc::start("A", &dirs[1].0, &["mine", "--seed", &seed, "--peer", &seed, "--peer", &b.addr]);
        Net { s, a, b, _dirs: dirs }
    }

    /// Waits for A to have mined spendable coins.
    fn funded(&mut self) {
        self.a.poll("balance", "spendable coins", 120, |l| amount(l, "confirmed").is_some_and(|c| c > 0.0));
    }
}

/// A pays B over the message layer: B's wallet answers the slate, A's
/// finalizes it, and A mines it.
#[test]
#[ignore = "slow: one job each in .github/workflows/test.yml"]
fn a_payment_goes_through_the_prompt() {
    let mut net = Net::start("pay");
    net.funded();
    let to = net.b.address();
    net.a.send(&format!("send 1 {to}"));
    net.a.expect("the slate sent", 30, |l| l.starts_with("slate ") && l.contains("sent to"));
    net.b.poll("balance", "the coin", 120, |l| amount(l, "confirmed").is_some_and(|c| c == 1.0));
    net.a.poll("sent", "the payment confirmed", 60, |l| l == "no unconfirmed payments");
    assert!(net.a.exit(30).success());
    assert!(net.b.exit(30).success());
    assert!(net.s.exit(30).success());
}

/// A registers a name; B finds it on chain, pointing at A's address.
#[test]
#[ignore = "slow: one job each in .github/workflows/test.yml"]
fn a_name_is_registered_through_the_prompt() {
    let mut net = Net::start("name");
    net.funded();
    let a_address = net.a.address();
    net.a.send("name-commit example");
    net.a.expect("the commit", 30, |l| l.starts_with("committed to example"));
    net.a.poll("names", "the commit ready", 120, |l| l.starts_with("example") && l.contains("ready to reveal"));
    net.a.send("name-reveal example");
    net.a.expect("the reveal", 30, |l| l == "revealing example");
    net.a.poll("names", "the name owned", 120, |l| l.starts_with("example") && l.contains("  owned  "));
    net.b.poll("name example", "the name's value", 120, |l| l.starts_with("value"));
    // The line after `value` is its address form.
    net.b.send("name example");
    let shown = net.b.expect("the value's address", 10, |l| l.trim_start().starts_with("tab1"));
    assert_eq!(shown.trim(), a_address);
}

/// `exit` while the miner is working ends the process (it once hung).
#[test]
#[ignore = "slow: one job each in .github/workflows/test.yml"]
fn exit_while_mining_ends_the_process() {
    let dir = TempDir::new("exit");
    let mut a = Proc::start("A", &dir.0, &["mine"]);
    a.poll("status", "a block mined", 60, |l| {
        l.strip_prefix("tip      height ")
            .and_then(|r| r.split_whitespace().next()?.parse::<u64>().ok())
            .is_some_and(|h| h > 0)
    });
    assert!(a.exit(30).success());
}

/// Sub-names end to end, in both modes. Init mode: the owner A's own node
/// answers for `cool.example`, and P pays C through it. Then A votes for a
/// consensus file listing the four relays, the network switches to onion
/// mode at block 144, A delegates its sub-names to B, and with A offline P
/// pays C through `ex2.example`, which only B knows.
#[test]
#[ignore = "slow: one job each in .github/workflows/test.yml"]
fn sub_names_resolve_in_both_modes() {
    let dirs: Vec<TempDir> =
        ["s1", "s2", "s3", "s4", "a", "b", "c", "p"].iter().map(|n| TempDir::new(&format!("sub-{n}"))).collect();
    // Four relays, the seeds of init mode and the relays of onion mode,
    // each a peer of those before it.
    let mut relays: Vec<Proc> = Vec::new();
    for (i, name) in ["S1", "S2", "S3", "S4"].into_iter().enumerate() {
        let mut args: Vec<String> = ["node", "--no-wallet", "--relay"].map(String::from).to_vec();
        for r in &relays {
            args.extend(["--peer".to_string(), r.addr.clone()]);
        }
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        relays.push(Proc::start(name, &dirs[i].0, &args));
    }
    let mut net: Vec<String> = Vec::new();
    for r in &relays {
        net.extend(["--seed".to_string(), r.addr.clone(), "--peer".to_string(), r.addr.clone()]);
    }
    let start = |name: &'static str, dir: &TempDir, first: &[&str]| {
        let args: Vec<&str> = first.iter().copied().chain(net.iter().map(String::as_str)).collect();
        Proc::start(name, &dir.0, &args)
    };
    let mut a = start("A", &dirs[4], &["mine", "--verbose"]);
    let mut b = start("B", &dirs[5], &["node"]);
    let mut c = start("C", &dirs[6], &["node"]);
    let mut p = start("P", &dirs[7], &["mine"]);

    // A votes for onion mode from its first blocks; it takes effect at 144.
    let mut file = String::from("mode onion\n");
    for r in &mut relays {
        r.send("address");
        let line = r.expect("relay id", 10, |l| l.starts_with("relay tab1"));
        let id = line.split_whitespace().nth(1).unwrap().to_string();
        file.push_str(&format!("relay {id} {}\n", r.addr));
    }
    let path = dirs[4].0.join("consensus.txt");
    std::fs::write(&path, &file).unwrap();
    a.send(&format!("set-leaf 0 {}", path.display()));
    a.expect("the leaf set", 10, |l| l.starts_with("leaf 0"));

    // Init mode: A registers example and answers cool.example itself.
    a.poll("balance", "spendable coins", 120, |l| amount(l, "confirmed").is_some_and(|c| c > 0.0));
    a.send("name-commit example");
    a.expect("the commit", 30, |l| l.starts_with("committed to example"));
    a.poll("names", "the commit ready", 120, |l| l.starts_with("example") && l.contains("ready to reveal"));
    a.send("name-reveal example");
    a.expect("the reveal", 30, |l| l == "revealing example");
    a.poll("names", "the name owned", 120, |l| l.starts_with("example") && l.contains("  owned  "));
    let c_address = c.address();
    a.send(&format!("subname set cool.example {c_address}"));
    a.expect("the sub-name set", 10, |l| l.starts_with("cool.example is"));
    p.poll("name example", "the name on chain", 60, |l| l.starts_with("value"));
    p.poll("balance", "spendable coins", 120, |l| amount(l, "confirmed").is_some_and(|c| c > 0.0));
    p.pay("1", "@cool.example", 120);
    c.poll("balance", "the first coin", 120, |l| amount(l, "confirmed").is_some_and(|c| c == 1.0));

    // The switch, and past its grace period.
    a.poll("consensus", "onion mode", 600, |l| l.starts_with("mode     onion"));
    let deadline = Instant::now() + guard(120);
    while a.height() < 150 {
        assert!(Instant::now() < deadline, "A: block 150 never came");
        std::thread::sleep(Duration::from_secs(1));
    }

    // Onion mode: B answers for A's names; A goes offline once its
    // delegation is held at its rendezvous points.
    b.send(&format!("subname set ex2.example {c_address}"));
    b.expect("the sub-name set", 10, |l| l.starts_with("ex2.example is"));
    let b_address = b.address();
    a.send(&format!("subname server {b_address}"));
    a.expect("the delegation", 10, |l| l.contains("are answered by"));
    a.expect_log("our delegation is held at our rendezvous point", 120);
    assert!(a.exit(30).success());
    p.pay("1", "@ex2.example", 180);
    c.poll("balance", "the second coin", 180, |l| amount(l, "confirmed").is_some_and(|c| c == 2.0));
}

/// A reorganization takes the rewards of lost blocks out of the wallet,
/// without a `scan`: B mines three blocks alone and stops; A mines a longer
/// chain alone; B comes back as a node peered with A, its node switches to
/// A's chain while it runs, and B's wallet forgets those rewards.
#[test]
#[ignore = "slow: one job each in .github/workflows/test.yml"]
fn a_reorganization_takes_lost_rewards_out_of_the_wallet() {
    let (dir_a, dir_b) = (TempDir::new("reorg-a"), TempDir::new("reorg-b"));
    let mut b = Proc::start("B", &dir_b.0, &["mine", "--blocks", "3"]);
    b.reach(3, 120);
    b.poll("balance", "its rewards", 30, |l| amount(l, "confirmed").is_some_and(|c| c > 0.0));
    assert!(b.exit(30).success());
    drop(b);
    let mut a = Proc::start("A", &dir_a.0, &["mine"]);
    a.reach(12, 120);
    let mut b = Proc::start("B", &dir_b.0, &["node", "--peer", &a.addr]);
    b.reach(12, 120);
    b.holds_nothing(60);
    a.poll("balance", "its rewards", 30, |l| amount(l, "confirmed").is_some_and(|c| c > 0.0));
}

/// A reorganization takes a payment received in a lost block out of the
/// wallet, without a `scan`: C mines alone from the start; A mines and
/// pays B on a chain of their own, then both stop; B comes back peered
/// with C only, whose heavier chain lacks the payment (and can never hold
/// it: its inputs are A's rewards on the lost chain).
#[test]
#[ignore = "slow: one job each in .github/workflows/test.yml"]
fn a_reorganization_takes_a_lost_payment_out_of_the_wallet() {
    let dirs = ["lost-s", "lost-a", "lost-b", "lost-c"].map(TempDir::new);
    let mut c = Proc::start("C", &dirs[3].0, &["mine"]);
    // A and B meet at S, their seed relay (init mode), for the slate.
    let s = Proc::start("S", &dirs[0].0, &["node", "--no-wallet", "--relay"]);
    let mut b = Proc::start("B", &dirs[2].0, &["node", "--seed", &s.addr, "--peer", &s.addr]);
    let mut a = Proc::start("A", &dirs[1].0, &["mine", "--seed", &s.addr, "--peer", &s.addr, "--peer", &b.addr]);
    a.poll("balance", "spendable coins", 120, |l| amount(l, "confirmed").is_some_and(|c| c > 0.0));
    let to = b.address();
    a.send(&format!("send 1 {to}"));
    a.expect("the slate sent", 30, |l| l.starts_with("slate ") && l.contains("sent to"));
    b.poll("balance", "the coin", 120, |l| amount(l, "confirmed").is_some_and(|c| c == 1.0));
    let lost = b.height();
    assert!(a.exit(30).success());
    assert!(b.exit(30).success());
    drop((a, b));
    c.reach(lost + 10, 120);
    let mut b = Proc::start("B", &dirs[2].0, &["node", "--peer", &c.addr]);
    b.reach(lost + 10, 120);
    b.holds_nothing(60);
}

/// A wallet restored from its phrase while the original runs: the restored
/// copy, on an address of its own, finds the coin by itself once synced (no
/// `scan`) and spends it; the original then sees the coin gone, again by
/// itself.
#[test]
#[ignore = "slow: one job each in .github/workflows/test.yml"]
fn a_restored_wallet_finds_and_spends_beside_its_original() {
    let mut net = Net::start("restore");
    net.funded();
    let to = net.b.address();
    net.a.send(&format!("send 1 {to}"));
    net.a.expect("the slate sent", 30, |l| l.starts_with("slate ") && l.contains("sent to"));
    net.b.poll("balance", "the coin", 120, |l| amount(l, "confirmed").is_some_and(|c| c == 1.0));
    let dir_r = TempDir::new("restore-r");
    restore(&dir_r.0, &net.b.phrase());
    let seed = net.s.addr.clone();
    let mut r = Proc::start("R", &dir_r.0, &["node", "--seed", &seed, "--peer", &seed, "--peer", &net.a.addr]);
    r.expect_log("restored wallet: found 1 outputs", 120);
    r.poll("balance", "the coin", 30, |l| amount(l, "confirmed").is_some_and(|c| c == 1.0));
    r.poll("outputs", "the coin, recovered", 10, |l| l.contains("recovered"));
    assert_ne!(r.address(), to, "a restore starts on a fresh address");
    // R spends it to A.
    let back = net.a.address();
    r.pay("0.5", &back, 120);
    r.poll("sent", "the payment confirmed", 120, |l| l == "no unconfirmed payments");
    r.poll("balance", "the change", 60, |l| amount(l, "confirmed").is_some_and(|c| c > 0.0 && c < 0.5));
    net.b.holds_nothing(60);
    assert!(r.exit(30).success());
    assert!(net.a.exit(30).success());
    assert!(net.b.exit(30).success());
    assert!(net.s.exit(30).success());
}

/// A crash at each step of a payment loses nothing: A dies (an abort, as
/// a power loss) once the slate's inputs are reserved, while it signs the
/// answer, and once it has signed but before the pool has the payment.
/// Started again, A frees the first two slates with `cancel` and sends the
/// third with `resend`; then a payment goes through as usual.
#[test]
#[ignore = "slow: one job each in .github/workflows/test.yml"]
fn a_crash_at_each_step_of_a_payment_loses_nothing() {
    let mut net = Net::start("crash");
    net.funded();
    let to = net.b.address();
    let dir_a = net.a.data.clone();
    let (seed, b_addr) = (net.s.addr.clone(), net.b.addr.clone());
    let args = ["mine", "--seed", &seed, "--peer", &seed, "--peer", &b_addr];
    assert!(net.a.exit(30).success());
    for step in ["send:reserved", "finalize:signing", "finalize:signed"] {
        let mut a = Proc::start_with("A", &dir_a, &args, &[("TABMINER_CRASH_AT", step)]);
        a.poll("balance", "spendable coins", 60, |l| amount(l, "confirmed").is_some_and(|c| c > 1.0));
        a.send(&format!("send 1 {to}"));
        a.dies(120);
        drop(a);
        let mut a = Proc::start("A", &dir_a, &args);
        if step == "finalize:signed" {
            let line = a.poll("sent", "the signed payment", 30, |l| l.contains("  fee "));
            let txid = line.split_whitespace().next().unwrap().to_string();
            a.send(&format!("resend {txid}"));
            a.expect("the payment sent again", 10, |l| l.starts_with("sending "));
            a.poll("sent", "the payment confirmed", 120, |l| l == "no unconfirmed payments");
        } else {
            let line = a.poll("slates", "the pending slate", 30, |l| l.ends_with(" reserved"));
            let id = line.split_whitespace().next().unwrap().to_string();
            a.send(&format!("cancel {id}"));
            a.expect("the slate cancelled", 10, |l| l.starts_with("slate cancelled"));
            a.poll("balance", "nothing reserved", 10, |l| amount(l, "reserved") == Some(0.0));
        }
        net.a = a;
        assert!(net.a.exit(30).success(), "{step}");
    }
    net.a = Proc::start("A", &dir_a, &args);
    net.a.pay("1", &to, 60);
    net.b.poll("balance", "both coins", 120, |l| amount(l, "confirmed").is_some_and(|c| c == 2.0));
    net.a.poll("sent", "the payment confirmed", 60, |l| l == "no unconfirmed payments");
    net.a.poll("slates", "no slate left", 10, |l| l == "no pending slates");
    assert!(net.a.exit(30).success());
    assert!(net.b.exit(30).success());
    assert!(net.s.exit(30).success());
}
