//! Logging to a file, so the terminal is free for the prompt.
//!
//! [`init`] names the file (appended to) and whether lines are echoed to
//! standard output as well; before it is called, or when no file is set,
//! lines go to standard output. Every line gets a UTC timestamp.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

struct Sink {
    file: Option<File>,
    echo: bool,
}

static SINK: Mutex<Option<Sink>> = Mutex::new(None);

/// Logs to `path` (created or appended), echoing to standard output when
/// `echo` is set.
pub fn init(path: Option<&Path>, echo: bool) -> std::io::Result<()> {
    let file = match path {
        Some(p) => Some(OpenOptions::new().create(true).append(true).open(p)?),
        None => None,
    };
    *SINK.lock().unwrap() = Some(Sink { file, echo });
    Ok(())
}

/// Writes one timestamped line.
pub fn line(msg: &str) {
    let stamp = timestamp();
    let mut guard = SINK.lock().unwrap();
    match guard.as_mut() {
        Some(Sink { file: Some(f), echo }) => {
            let _ = writeln!(f, "{stamp} {msg}");
            if *echo {
                println!("{msg}");
            }
        }
        _ => println!("{msg}"),
    }
}

/// `YYYY-MM-DD HH:MM:SS` in UTC, now.
pub fn timestamp() -> String {
    timestamp_of(SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0))
}

/// `YYYY-MM-DD HH:MM:SS` in UTC of a unix time.
pub fn timestamp_of(secs: u64) -> String {
    let (y, m, d) = civil_from_days((secs / 86_400) as i64);
    let s = secs % 86_400;
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}", s / 3600, (s / 60) % 60, s % 60)
}

/// Gregorian date of a day count since 1970-01-01 (Howard Hinnant's
/// algorithm).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(19_723), (2024, 1, 1));
        assert_eq!(civil_from_days(20_454), (2026, 1, 1));
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
        assert_eq!(timestamp().len(), 19);
    }
}
