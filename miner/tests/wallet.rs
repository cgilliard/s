//! The binary driven through its prompt, as a user drives it: nodes on a
//! `--network dev` chain of their own on loopback, commands written to
//! stdin, and their answers read from stdout. A step that does not happen
//! in time fails the test with every process's output.
//!
//! The dev networks are built in with the `dev` feature only, so these
//! tests are too: `cargo test --release --features dev --test wallet`.

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
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
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
        let mut child = Command::new(env!("CARGO_BIN_EXE_tabminer"))
            .args(args)
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
