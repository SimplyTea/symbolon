//! `symbolon`: a minimal command-line client for trying the library on a real
//! network (two terminals, a laptop and a Pi, etc.). It is a TEST HARNESS,
//! not the product: one peer, plain text lines, no groups yet.
//!
//! Run `symbolon` with no arguments for the full usage text.
//!
//! # Debug mode (`--debug`, or `P2P_DEBUG=1`)
//!
//! Adds a timestamped trace of everything the CLI can observe: how long each
//! handshake step took, the exact plaintext of every message sent/received
//! (text and hex), the size each message occupies on the wire, approximate
//! acknowledgement latency, the ratchet's position after each message, and
//! a summary on exit. `--log FILE` also writes the trace to a file.
//!
//! WHAT IS *NOT* PRINTED, EVEN IN DEBUG MODE: your passphrase, your private
//! key, and any session/ratchet/message key. Those would defeat the purpose
//! of the test, and a log file that contained them would be a liability.
//! Plaintext messages ARE printed, so treat debug logs as sensitive.
//!
//! To see the *encrypted* bytes that actually cross the network, use
//! `tcpdump`/Wireshark on port 7000 alongside this trace.
//!
//! # In-chat commands
//!
//! A line starting with `/` is a command, not a message:
//! `/ping [N]` (measure round-trip time through the whole stack),
//! `/state` (show session + ratchet state), `/help`. To send a message that
//! really starts with a slash, start it with two (`//hello` sends `/hello`).

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{BufRead, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use symbolon::handshake::HandshakeProgress;
use symbolon::identity::{decode_public_key, encode_public_key, Identity, PeerRegistry};
use symbolon::persistence::EncryptedIdentity;
use symbolon::session::{Reconnected, Role, Session, SessionConfig};
use symbolon::ChatError;

// ---------------------------------------------------------------------------
// Debug logging
// ---------------------------------------------------------------------------

/// Process-wide trace sink. `on == false` makes every `dlog!` a no-op.
struct Dbg {
    on: bool,
    start: Instant,
    file: Mutex<Option<std::fs::File>>,
}

static DBG: OnceLock<Dbg> = OnceLock::new();

fn dbg() -> &'static Dbg {
    DBG.get()
        .expect("logger is initialised first thing in main")
}

/// Days since 1970-01-01 to (year, month, day), proleptic Gregorian
/// (Howard Hinnant's civil-from-days algorithm). Avoids a date crate.
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

/// Wall-clock UTC timestamp like `2026-10-27 21:46:02.123Z`.
fn wall_clock() -> String {
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = d.as_secs();
    let (y, mo, da) = civil_from_days((secs / 86_400) as i64);
    let (h, mi, s) = ((secs / 3600) % 24, (secs / 60) % 60, secs % 60);
    format!(
        "{y:04}-{mo:02}-{da:02} {h:02}:{mi:02}:{s:02}.{:03}Z",
        d.subsec_millis()
    )
}

impl Dbg {
    /// Write one trace line to stderr (and the log file, if any):
    /// `[wall clock UTC | +seconds since start] tag   message`.
    fn emit(&self, tag: &str, msg: &str) {
        let line = format!(
            "[{} | +{:>8.3}s] {tag:<9} {msg}",
            wall_clock(),
            self.start.elapsed().as_secs_f64()
        );
        eprintln!("{line}");
        if let Some(f) = self.file.lock().unwrap().as_mut() {
            let _ = writeln!(f, "{line}");
        }
    }
}

macro_rules! dlog {
    ($tag:expr, $($arg:tt)*) => {
        if dbg().on {
            dbg().emit($tag, &format!($($arg)*));
        }
    };
}

/// Library trace events go through the same `--debug` sink as everything
/// else (a no-op when debug is off). Events never contain secrets.
fn cli_tracer() -> std::sync::Arc<dyn symbolon::trace::Tracer> {
    std::sync::Arc::new(symbolon::trace::FnTracer::new(|e| dlog!("trace", "{e:?}")))
}

fn session_config() -> SessionConfig {
    let mut c = SessionConfig {
        tracer: cli_tracer(),
        ..SessionConfig::default()
    };
    // Command-line overrides (see `init_timing`); unset flags keep the library defaults.
    if let Some(t) = TIMING.get() {
        if let Some(h) = t.handshake {
            c.handshake_timeout = h;
        }
        if let Some(h) = t.heartbeat {
            c.heartbeat_interval = h;
        }
        if let Some(d) = t.dead_after {
            c.dead_after = d;
        }
        if let Some(p) = t.padding {
            c.padding = p;
        }
    }
    c
}

/// Timing values given on the command line. `Some(None)` means "disabled"
/// (the flag was given as 0); `None` means "flag not given, use the default".
#[derive(Default)]
struct Timing {
    handshake: Option<Option<Duration>>,
    heartbeat: Option<Option<Duration>>,
    dead_after: Option<Duration>,
    connect: Option<Duration>,
    /// `--padding`: how outgoing messages are padded (None = library default, off).
    padding: Option<symbolon::padding::Padding>,
}
static TIMING: std::sync::OnceLock<Timing> = std::sync::OnceLock::new();

/// Parse `--heartbeat`, `--dead-after`, `--handshake-timeout` and
/// `--connect-timeout` (whole seconds; 0 turns heartbeat/handshake timeout off
/// and is refused for the others). Rejects settings that would kill healthy
/// links: `dead-after` must be at least twice `heartbeat`.
fn init_timing(args: &[String]) {
    let secs = |name: &str| -> Option<u64> {
        flag(args, name).map(|v| {
            v.parse::<u64>()
                .unwrap_or_else(|_| die(&format!("{name} takes a whole number of seconds")))
        })
    };
    let off_if_zero = |n: u64| {
        if n == 0 {
            None
        } else {
            Some(Duration::from_secs(n))
        }
    };
    let handshake = secs("--handshake-timeout").map(off_if_zero);
    let heartbeat = secs("--heartbeat").map(off_if_zero);
    let dead_after = secs("--dead-after").map(|n| {
        if n == 0 {
            die("--dead-after must be above 0 (use --heartbeat 0 to turn liveness checks off)")
        }
        Duration::from_secs(n)
    });
    let connect = secs("--connect-timeout").map(|n| {
        if n == 0 {
            die("--connect-timeout must be above 0")
        }
        Duration::from_secs(n)
    });
    // `--padding off|standard|strong|BYTES`: pad what we send up to a multiple of
    // a block size (see the library's `padding` module). Default off.
    let padding = flag(args, "--padding").map(|v| match v.as_str() {
        "off" => symbolon::padding::Padding::OFF,
        "standard" => symbolon::padding::Padding::STANDARD,
        "strong" => symbolon::padding::Padding::STRONG,
        n => n
            .parse::<u16>()
            .ok()
            .and_then(|b| symbolon::padding::Padding::block(b).ok())
            .unwrap_or_else(|| {
                die("--padding takes off, standard (256), strong (1024) or a block size of 16 to 65535 bytes")
            }),
    });
    let t = Timing {
        handshake,
        heartbeat,
        dead_after,
        connect,
        padding,
    };
    let defaults = SessionConfig::default();
    let hb = t.heartbeat.unwrap_or(defaults.heartbeat_interval);
    let dead = t.dead_after.unwrap_or(defaults.dead_after);
    if let Some(hb) = hb {
        if dead < hb * 2 {
            die(&format!(
                "--dead-after ({}s) must be at least twice --heartbeat ({}s), or one lost ping kills a healthy link",
                dead.as_secs(),
                hb.as_secs()
            ));
        }
    }
    let _ = TIMING.set(t);
}

/// Open a TCP connection, giving up after `--connect-timeout` (default 10 s)
/// instead of waiting for the operating system's multi-minute default, which
/// made a wrong or unreachable address look like a hang.
pub(crate) fn dial(addr: &str) -> std::io::Result<TcpStream> {
    use std::net::ToSocketAddrs;
    let limit = TIMING
        .get()
        .and_then(|t| t.connect)
        .unwrap_or(Duration::from_secs(10));
    let mut last = std::io::Error::new(std::io::ErrorKind::NotFound, "address did not resolve");
    for a in addr.to_socket_addrs()? {
        match TcpStream::connect_timeout(&a, limit) {
            Ok(s) => return Ok(s),
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// `--announce [major|minor|full]`: opt-in LAN discovery beacon. Returns a
/// guard that stops announcing when dropped; `None` if not requested.
pub(crate) fn start_announce(args: &[String], port: u16) -> Option<symbolon::discovery::Announcer> {
    use symbolon::discovery::{Announcement, Announcer, Disclose};
    let level = flag(args, "--announce")?;
    let disclose = match level.as_str() {
        "major" => Disclose::Major,
        "minor" => Disclose::Minor,
        "full" => Disclose::Full,
        other => die(&format!(
            "--announce takes major, minor or full, not {other:?}"
        )),
    };
    let mut v = env!("CARGO_PKG_VERSION")
        .split('.')
        .map(|p| p.parse::<u8>().unwrap_or(0));
    let version = (
        v.next().unwrap_or(0),
        v.next().unwrap_or(0),
        v.next().unwrap_or(0),
    );
    let ann = Announcement::new("symbolon", version, disclose, port)
        .unwrap_or_else(|e| die(&format!("{e}")));
    println!(
        "DISCOVERY ON: announcing name + {disclose:?} version + port {port} on the LAN (no key)."
    );
    Some(
        Announcer::start_broadcast(ann, std::time::Duration::from_secs(3))
            .unwrap_or_else(|e| die(&format!("cannot start announcing: {e}"))),
    )
}

/// `discover`: print announcements heard on the LAN. They are unverified
/// hints; you still need the peer's key to connect.
fn discover(args: &[String]) {
    use symbolon::discovery::{DiscoveryListener, DEFAULT_PORT};
    let secs: u64 = flag(args, "--seconds")
        .and_then(|s| s.parse().ok())
        .unwrap_or(15);
    let l = DiscoveryListener::bind(([0, 0, 0, 0], DEFAULT_PORT).into()).unwrap_or_else(|e| {
        die(&format!(
            "cannot listen for announcements on UDP {DEFAULT_PORT}: {e}"
        ))
    });
    println!("Listening {secs}s for announcements (unverified hints)...");
    let end = std::time::Instant::now() + std::time::Duration::from_secs(secs);
    let mut seen = std::collections::HashSet::new();
    while let Some(left) = end.checked_duration_since(std::time::Instant::now()) {
        if let Some(d) = l.next(left) {
            if seen.insert((d.dial, d.announcement.clone())) {
                let a = &d.announcement;
                let ver = match (a.minor, a.patch) {
                    (None, _) => format!("{}", a.major),
                    (Some(m), None) => format!("{}.{}", a.major, m),
                    (Some(m), Some(p)) => format!("{}.{}.{}", a.major, m, p),
                };
                println!("  {} v{} at {}", a.name, ver, d.dial);
            }
        }
    }
}

// Group mode lives in its own file (declared after `dlog!` so it can use it).
mod group;

/// Milliseconds elapsed since `t`, as a float.
fn ms_since(t: Instant) -> f64 {
    t.elapsed().as_secs_f64() * 1000.0
}

/// Render bytes for the trace: length, (lossy) text, and hex. Long payloads
/// are truncated so one huge paste cannot flood the terminal.
fn describe(b: &[u8]) -> String {
    const MAX: usize = 256;
    let text = String::from_utf8_lossy(b);
    let mut shown: String = text.chars().take(200).collect();
    if text.chars().count() > 200 {
        shown.push('…');
    }
    let hex: Vec<String> = b.iter().take(MAX).map(|x| format!("{x:02x}")).collect();
    format!(
        "{} bytes | text={shown:?} | hex={}{}",
        b.len(),
        hex.join(" "),
        if b.len() > MAX { " …(truncated)" } else { "" }
    )
}

/// First 8 bytes of a key/hash as hex, enough to recognise it in a trace.
fn short_hex(b: &[u8]) -> String {
    b.iter().take(8).map(|x| format!("{x:02x}")).collect()
}

/// Bytes one application message occupies on the wire. Derived from the
/// protocol's fixed overheads: ratchet header 40 + AEAD tag 16, transport
/// header 9 + AEAD tag 16, frame length prefix 4 = 85 bytes in total.
fn expected_wire_len(plaintext_len: usize) -> usize {
    plaintext_len + 40 + 16 + 9 + 16 + 4
}

// ---------------------------------------------------------------------------
// Argument / identity helpers
// ---------------------------------------------------------------------------

/// Printed when the command is missing or unknown.
const USAGE: &str = "symbolon - minimal secure P2P chat test client

USAGE (via cargo, note the `--` before the program's own arguments):
  cargo run --release -- keygen
  cargo run --release -- show
  cargo run --release -- listen  --bind 0.0.0.0:7000 --trust <PEER PUBLIC KEY HEX>
  cargo run --release -- connect --addr <HOST>:7000  --trust <PEER PUBLIC KEY HEX>

COMMANDS:
  keygen    create an encrypted identity (asks for a new passphrase) and print
            your fingerprint + public key
  show      unlock your identity and print your fingerprint + public key
  listen    wait for an incoming connection from the pinned peer (re-accepts
            after a drop and resumes the same session, losing nothing)
  connect   dial the pinned peer (redials with backoff after a drop)
  group-new   create a group; prints the group id and an INVITE for the others
  group-run   join/resume a group and chat with every member (full mesh)
  bot-new     create a separate identity for a BOT (needs --id FILE) and print how to add it
  bot-run     run as a bot member: prints events (--format tsv for programs), posts
              stdin lines verbatim or --say TEXT; --listen-only, --seconds N, --commands
  discover    listen on the LAN for nodes that opted in to announcing (--seconds N)

FLAGS:
  --id FILE     identity file (default ~/.symbolon/id.enc; an older ~/.p2pchat/id.enc
                is still used if it is the only one that exists)
  --trust HEX   the OTHER side's public key (64 hex chars, from their `show`)
  --bind ADDR   listen address (default 0.0.0.0:7000)
  --addr ADDR   address to connect to, e.g. 192.168.1.42:7000
  --announce L  opt in to LAN discovery while listening: L is major,
                minor or full = how much of the version number to reveal. Sends
                only name + version + port, never your key. Off unless given.
  --relay P     (group-new) open (default) or author-only: who may serve a message's
                content. In author-only groups others can only confirm it EXISTS.
  --hide-relayed  (group-run) don't accept content from non-authors; record that
                it exists and /fetch it from the author instead
  --no-receipts   (group-run) don't send delivery receipts (default: sent)
  --read-receipts (group-run) allow /read to send read receipts (default: off)
  --no-session-state  (group-run) don't save session state; a restart then starts
                fresh sessions (default: saved under STATE_DIR/sessions)
  --pass-file F read the passphrase from F (must be mode 600) - for unattended bots
  --say TEXT    (bot-run) post TEXT once when connected (repeatable)
  --format F    (bot-run) plain (default) or tsv: kind<TAB>who<TAB>seq<TAB>text
  --listen-only (bot-run) never read stdin; only listen
  --commands    (bot-run) treat stdin lines starting with / as commands
  --catchup S   (group-run, bot-run) also ask the mesh for missed messages every S seconds
                (default 0 = off: new posts are announced to the group as they are accepted;
                you still catch up on every connect and with /catchup)
  --heartbeat S ping after S seconds of silence (default 10; 0 = no heartbeat, no dead-peer detection)
  --dead-after S  declare the link dead after S seconds of silence (default 30; must be >= 2x --heartbeat)
  --handshake-timeout S  give up on a handshake after S seconds (default 10; 0 = wait forever)
  --connect-timeout S    give up dialling after S seconds (default 10)
  --relay-cache N (group-run, bot-run) messages kept per sender to help others catch up (default 256)
  --padding P   pad what you SEND to hide message length: off (default), standard (256-byte blocks),
                strong (1024) or a block size 16..65535. The other side needs no matching setting
  --no-reconnect  exit when the connection ends instead of reconnecting
  --members K,K create group with these OTHER members' public keys (group-new)
  --invite HEX  the creator's invite (first group-run); needs --trust CREATOR_KEY
  --group ID    resume a saved group (later group-run)
  --peer K=H:P  a member's public key and address to dial (repeatable; only used
                for members with a LARGER fingerprint than yours - they listen)
  --state-dir D where group state is kept (default ~/.symbolon/groups)
  --debug       timestamped trace: handshake step timings, exact plaintext of
                every message (text + hex), wire sizes, ack latency, ratchet
                position. Also enabled by P2P_DEBUG=1. Never prints keys or
                the passphrase.
  --log FILE    also append the trace to FILE (owner-only; contains plaintext!)

IN-CHAT COMMANDS (a line starting with a single `/`):
  /ping [N]     measure round-trip time through the whole stack (N times)
  /state        show session id, ratchet position, unacked count
  /help         list commands          (send a literal `/x` as `//x`)

ENV:
  P2P_PASSPHRASE   use this passphrase instead of prompting (scripts only)
  P2P_DEBUG=1      same as --debug

GROUP CHAT: see the header of src/bin/symbolon/group.rs for the workflow.
  1. everyone: keygen, then share `show` output (public key)
  2. creator:  group-new --members KEY1,KEY2          (prints an invite)
  3. members:  group-run --invite HEX --trust CREATORKEY --bind 0.0.0.0:7000 \\
                         --peer KEY=HOST:7000 ...
  In a group, typed lines are posts; /help lists /members /history /edit /delete ...

Type lines + Enter to send; Ctrl-D to quit.";

/// Default identity location, so most commands need no `--id`.
fn default_id_path() -> PathBuf {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    let current = home.join(".symbolon").join("id.enc");
    // The project was renamed from "p2pchat". If you made an identity before
    // the rename and have none under the new name, keep using the old one
    // instead of silently creating a second identity.
    let legacy = home.join(".p2pchat").join("id.enc");
    if !current.exists() && legacy.exists() {
        return legacy;
    }
    current
}

/// Fetch `--flag value` from the argument list.
fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1).cloned())
}

/// `--pass-file FILE`, recorded once at startup (see `main`).
static PASS_FILE: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

fn passphrase(prompt: &str) -> String {
    // An unattended bot cannot type a passphrase. A file is safer than an
    // environment variable (which child processes and /proc can leak), but
    // only if nobody else can read it, so refuse a group/world-readable one.
    if let Some(path) = PASS_FILE.get() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(path)
                .unwrap_or_else(|e| die(&format!("cannot read {}: {e}", path.display())))
                .permissions()
                .mode();
            if mode & 0o077 != 0 {
                die(&format!(
                    "{} is readable by others (mode {:o}); run: chmod 600 {}",
                    path.display(),
                    mode & 0o777,
                    path.display()
                ));
            }
        }
        let text = std::fs::read_to_string(path)
            .unwrap_or_else(|e| die(&format!("cannot read {}: {e}", path.display())));
        return text.trim_end_matches(['\n', '\r']).to_string();
    }
    if let Ok(p) = std::env::var("P2P_PASSPHRASE") {
        return p;
    }
    rpassword::prompt_password(prompt)
        .unwrap_or_else(|e| die(&format!("cannot read passphrase: {e}")))
}

fn die(msg: &str) -> ! {
    eprintln!("error: {msg}");
    dlog!("exit", "fatal: {msg}");
    std::process::exit(1)
}

fn load_identity(args: &[String]) -> Identity {
    let path = flag(args, "--id")
        .map(PathBuf::from)
        .unwrap_or_else(default_id_path);
    let pass = passphrase("Passphrase: ");
    let t = Instant::now();
    let result = EncryptedIdentity::load(&path, &pass);
    dlog!(
        "identity",
        "unlock of {} took {:.1} ms (ok={})",
        path.display(),
        ms_since(t),
        result.is_ok()
    );
    result.unwrap_or_else(|e| match e {
        // By design a wrong passphrase and a damaged file look identical
        // (telling them apart would help an attacker), so say both.
        ChatError::DecryptionFailed => die(&format!(
            "cannot unlock {}: wrong passphrase, or the file is corrupted/tampered",
            path.display()
        )),
        other => die(&format!("cannot unlock {}: {other}", path.display())),
    })
}

fn registry_from(args: &[String]) -> PeerRegistry {
    let hex =
        flag(args, "--trust").unwrap_or_else(|| die("--trust <peer public key hex> is required"));
    let key = decode_public_key(&hex).unwrap_or_else(|e| match e {
        ChatError::InvalidPublicKey => {
            die("bad --trust key: not a valid public key (check for a typo or a missing character)")
        }
        other => die(&format!("bad --trust key: {other}")),
    });
    let mut reg = PeerRegistry::new();
    let pinned = reg.trust(key);
    dlog!("trust", "pinned peer fingerprint {pinned}");
    reg
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    // Logger first, so every later step can trace.
    let on = args.iter().any(|a| a == "--debug")
        || std::env::var("P2P_DEBUG")
            .map(|v| v == "1")
            .unwrap_or(false);
    let file = flag(&args, "--log").map(|path| {
        let mut opts = OpenOptions::new();
        opts.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600); // the trace contains plaintext
        }
        opts.open(&path).unwrap_or_else(|e| {
            eprintln!("error: cannot open log file {path}: {e}");
            std::process::exit(1)
        })
    });
    let _ = DBG.set(Dbg {
        on: on || file.is_some(),
        start: Instant::now(),
        file: Mutex::new(file),
    });
    if dbg().on {
        dbg().emit(
            "debug",
            "DEBUG ON: plaintext of every message is printed/logged. Passphrase, private keys and session keys never are.",
        );
        dlog!(
            "args",
            "{:?}",
            args.iter().filter(|a| *a != "--debug").collect::<Vec<_>>()
        );
    }

    reject_unknown_arguments(&args);
    init_timing(&args);
    if let Some(f) = flag(&args, "--pass-file") {
        let _ = PASS_FILE.set(PathBuf::from(f));
    }

    match args.first().map(String::as_str) {
        Some("keygen") => keygen(&args),
        Some("show") => show(&args),
        Some("listen") => run(&args, true),
        Some("connect") => run(&args, false),
        Some("group-new") => group::group_new(&args),
        Some("group-run") => group::group_run(&args),
        Some("bot-new") => bot_new(&args),
        Some("bot-run") => group::bot_run(&args),
        Some("discover") => discover(&args),
        _ => {
            eprintln!("{USAGE}");
            std::process::exit(2);
        }
    }
}

/// Refuse arguments we don't understand instead of silently ignoring them.
/// A security tool must not quietly drop something like a mistyped
/// `--bind`: you could end up listening somewhere other than you intended.
fn reject_unknown_arguments(args: &[String]) {
    const WITH_VALUE: [&str; 23] = [
        "--id",
        "--trust",
        "--bind",
        "--addr",
        "--log",
        "--members",
        "--invite",
        "--state-dir",
        "--peer",
        "--group",
        "--announce",
        "--seconds",
        "--relay",
        "--pass-file",
        "--say",
        "--format",
        "--catchup",
        "--heartbeat",
        "--dead-after",
        "--handshake-timeout",
        "--connect-timeout",
        "--relay-cache",
        "--padding",
    ];
    const SWITCHES: [&str; 8] = [
        "--debug",
        "--no-reconnect",
        "--hide-relayed",
        "--no-receipts",
        "--read-receipts",
        "--no-session-state",
        "--listen-only",
        "--commands",
    ];
    let mut i = 1; // args[0] is the command
    while i < args.len() {
        let a = args[i].as_str();
        if WITH_VALUE.contains(&a) {
            if i + 1 >= args.len() {
                die(&format!("{a} needs a value"));
            }
            i += 2;
        } else if SWITCHES.contains(&a) {
            i += 1;
        } else {
            let hint = if a.contains(':') {
                " (did you mean --bind or --addr before it?)"
            } else {
                ""
            };
            die(&format!(
                "unrecognised argument {a:?}{hint}; run with no arguments for usage"
            ));
        }
    }
}

fn keygen(args: &[String]) {
    keygen_inner(args);
}

/// `bot-new`: make an identity for a bot. Same as `keygen`, but it insists on
/// an explicit `--id` (so a bot can never overwrite or be confused with your
/// own identity) and prints the command its sponsor runs to add it.
fn bot_new(args: &[String]) {
    let Some(path) = flag(args, "--id") else {
        die("bot-new needs --id FILE (a separate file from your own identity)");
    };
    if default_id_path() == std::path::Path::new(&path) {
        die("that is your personal identity file; give the bot its own --id FILE");
    }
    let id = keygen_inner(args);
    println!();
    println!("A member with `can_add` adds it from inside group-run:");
    println!(
        "  /addbot {} [bot|listener]",
        encode_public_key(&id.public_key())
    );
    println!("Then run it with:");
    println!("  symbolon bot-run --id {path} --pass-file PASSFILE --invite HEX --trust CREATORKEY --bind ... [--peer ...]");
    println!("  flags: --listen-only  --say TEXT  --format tsv  --seconds N  --commands");
}

fn keygen_inner(args: &[String]) -> Identity {
    let path = flag(args, "--id")
        .map(PathBuf::from)
        .unwrap_or_else(default_id_path);
    if path.exists() {
        die(&format!(
            "{} already exists; refusing to overwrite",
            path.display()
        ));
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)
            .unwrap_or_else(|e| die(&format!("cannot create {}: {e}", dir.display())));
    }
    let pass = passphrase("New passphrase: ");
    let id = Identity::generate();
    let t = Instant::now();
    EncryptedIdentity::save(&id, &path, &pass)
        .unwrap_or_else(|e| die(&format!("cannot save identity: {e}")));
    dlog!("identity", "encrypting + saving took {:.1} ms", ms_since(t));
    println!("saved {}", path.display());
    println!("fingerprint: {}", id.fingerprint());
    println!("public key : {}", encode_public_key(&id.public_key()));
    id
}

fn show(args: &[String]) {
    let id = load_identity(args);
    println!("fingerprint: {}", id.fingerprint());
    println!("public key : {}", encode_public_key(&id.public_key()));
}

// ---------------------------------------------------------------------------
// The chat session
// ---------------------------------------------------------------------------

/// Counters for the end-of-run summary.
#[derive(Default)]
struct Stats {
    sent_msgs: AtomicU64,
    sent_bytes: AtomicU64,
    recv_msgs: AtomicU64,
    recv_bytes: AtomicU64,
}

/// Application-level ping/pong payload prefixes. They travel through the
/// real encrypted session like any message, so a round trip measures the
/// whole stack (ratchet + transport + TCP + the peer's processing).
const PING: &[u8] = b"\x01PING:";
const PONG: &[u8] = b"\x01PONG:";

/// Log the ratchet's position and flag a DH step (our public key changed).
fn trace_ratchet(session: &Session, last_pub: &Mutex<[u8; 32]>, when: &str) {
    if !dbg().on {
        return;
    }
    let info = session.ratchet_info();
    let mut last = last_pub.lock().unwrap();
    let rotated = *last != info.own_public;
    *last = info.own_public;
    dlog!(
        "ratchet",
        "{when}: own_pub={}… sent_in_chain={} recv_in_chain={} prev_chain={} cached_skipped={} unacked={}{}",
        short_hex(&info.own_public),
        info.sent_in_chain,
        info.received_in_chain,
        info.previous_chain_len,
        info.cached_skipped_keys,
        session.pending_unacked(),
        if rotated { "  <-- DH STEP: our ratchet key rotated" } else { "" }
    );
}

/// Approximate acknowledgement latency: the first moment after a send when
/// nothing is awaiting an ack. (With several messages in flight this is the
/// time until ALL are acked, hence "approx".)
fn watch_ack(session: Arc<Session>, seq: u64, t0: Instant) {
    if !dbg().on {
        return;
    }
    std::thread::spawn(move || loop {
        if session.pending_unacked() == 0 {
            dlog!(
                "ack",
                "seq {seq}: nothing pending {:.2} ms after send (approx ack round trip)",
                ms_since(t0)
            );
            return;
        }
        if t0.elapsed() > Duration::from_secs(10) {
            dlog!(
                "ack",
                "seq {seq}: STILL UNACKED after 10 s ({} pending)",
                session.pending_unacked()
            );
            return;
        }
        std::thread::sleep(Duration::from_millis(1));
    });
}

/// Send one payload, with tracing. Returns false if the send failed.
fn send_traced(
    session: &Arc<Session>,
    payload: &[u8],
    stats: &Stats,
    last_pub: &Mutex<[u8; 32]>,
) -> bool {
    let t0 = Instant::now();
    match session.send(payload) {
        Ok(seq) => {
            stats.sent_msgs.fetch_add(1, Ordering::Relaxed);
            stats
                .sent_bytes
                .fetch_add(payload.len() as u64, Ordering::Relaxed);
            dlog!(
                "send",
                "seq {seq} accepted in {:.3} ms | expect {} bytes on the wire | plaintext: {}",
                ms_since(t0),
                expected_wire_len(payload.len()),
                describe(payload)
            );
            trace_ratchet(session, last_pub, "after send");
            watch_ack(Arc::clone(session), seq, t0);
            true
        }
        Err(e) => {
            eprintln!("[send failed: {e}]");
            dlog!(
                "send",
                "FAILED after {:.3} ms: {e:?} | plaintext was: {}",
                ms_since(t0),
                describe(payload)
            );
            false
        }
    }
}

/// Shared by `listen` (we accept, so we are the responder) and `connect`.
fn run(args: &[String], listening: bool) {
    let identity = load_identity(args);
    let registry = registry_from(args);
    println!("you are {}", identity.fingerprint());

    // How to get the NEXT connection if this one drops: a listener keeps
    // accepting, a dialer redials (see `reconnect`).
    let mut _announcer: Option<symbolon::discovery::Announcer> = None; // dropped (stops) when `run` ends
    let mut keep_listener: Option<TcpListener> = None;
    let mut keep_addr: Option<String> = None;
    let stream = if listening {
        let bind = flag(args, "--bind").unwrap_or_else(|| "0.0.0.0:7000".to_string());
        let listener =
            TcpListener::bind(&bind).unwrap_or_else(|e| die(&format!("cannot bind {bind}: {e}")));
        println!("Listening on {}", listener.local_addr().unwrap());
        _announcer = start_announce(args, listener.local_addr().unwrap().port());
        dlog!(
            "net",
            "listening on {} - waiting for a connection",
            listener.local_addr().unwrap()
        );
        let (s, from) = listener
            .accept()
            .unwrap_or_else(|e| die(&format!("accept failed: {e}")));
        eprintln!("connection from {from}");
        dlog!(
            "net",
            "accepted connection from {from} (local {})",
            s.local_addr().map(|a| a.to_string()).unwrap_or_default()
        );
        keep_listener = Some(listener);
        s
    } else {
        let addr = flag(args, "--addr").unwrap_or_else(|| die("--addr host:port is required"));
        dlog!("net", "connecting to {addr} ...");
        let t = Instant::now();
        let s = dial(&addr).unwrap_or_else(|e| die(&format!("cannot connect to {addr}: {e}")));
        keep_addr = Some(addr.clone());
        dlog!(
            "net",
            "TCP connected in {:.2} ms: local {} -> peer {}",
            ms_since(t),
            s.local_addr().map(|a| a.to_string()).unwrap_or_default(),
            s.peer_addr().map(|a| a.to_string()).unwrap_or_default()
        );
        s
    };

    // ---- handshake, with per-step timing ----
    let role = if listening {
        Role::Responder
    } else {
        Role::Initiator
    };
    let hs_start = Instant::now();
    let mut step_start = Instant::now();
    let mut last_step = String::from("(none yet)");
    let mut progress = |p: HandshakeProgress| {
        let desc = format!("{p:?}");
        if !dbg().on {
            eprintln!("[handshake] {desc}");
        }
        dlog!(
            "handshake",
            "{desc}  (+{:.3} ms since previous step, {:.3} ms total)",
            ms_since(step_start),
            ms_since(hs_start)
        );
        step_start = Instant::now();
        last_step = desc;
    };
    let established = Session::establish_with(
        stream,
        role,
        &identity,
        &registry,
        session_config(),
        Some(&mut progress),
    );
    let session = match established {
        Ok(s) => s,
        Err(e) => {
            // The debug trace is the place for "everything we know about why".
            dlog!(
                "handshake",
                "FAILED after {:.2} ms. Last completed step: {last_step}",
                ms_since(hs_start)
            );
            dlog!("handshake", "error (Display): {e}");
            dlog!("handshake", "error (Debug)  : {e:?}");
            dlog!(
                "handshake",
                "no application data was exchanged; nothing was decrypted"
            );
            die(&format!("handshake failed: {e}"));
        }
    };
    println!(
        "secure session with {} (protocol v{})",
        session.peer_id(),
        session.negotiated_version()
    );
    println!(
        "session id: {}   (should be IDENTICAL on both sides)",
        session.session_id()
    );
    dlog!(
        "session",
        "ESTABLISHED in {:.2} ms (handshake) | {:.2} ms since process start",
        ms_since(hs_start),
        dbg().start.elapsed().as_secs_f64() * 1000.0
    );
    dlog!(
        "session",
        "peer={} protocol_version={} session_id={}",
        session.peer_id(),
        session.negotiated_version(),
        session.session_id()
    );
    dlog!(
        "session",
        "wire cost per message: 85 bytes fixed overhead (ratchet 56 + transport 25 + frame 4)"
    );

    let session = Arc::new(session);
    // The CURRENT session. It is swapped for a new one if the peer restarts
    // (and so cannot resume the old one), so every user takes it from here.
    let current: Arc<Mutex<Arc<Session>>> = Arc::new(Mutex::new(Arc::clone(&session)));
    let identity = Arc::new(identity);
    let registry = Arc::new(registry);
    let reconnect_how = Arc::new(Mutex::new((keep_listener, keep_addr)));
    let auto_reconnect = !args.iter().any(|a| a == "--no-reconnect");
    let stats = Arc::new(Stats::default());
    let last_pub = Arc::new(Mutex::new(session.ratchet_info().own_public));
    trace_ratchet(&session, &last_pub, "initial state");

    let pings: Arc<Mutex<HashMap<u64, Instant>>> = Arc::new(Mutex::new(HashMap::new()));
    let next_ping = Arc::new(AtomicU64::new(1));
    let quitting = Arc::new(AtomicBool::new(false));

    // ---- receiver thread ----
    let printer = {
        let (current, stats, pings, quitting, last_pub) = (
            Arc::clone(&current),
            Arc::clone(&stats),
            Arc::clone(&pings),
            Arc::clone(&quitting),
            Arc::clone(&last_pub),
        );
        let (identity, registry, reconnect_how) = (
            Arc::clone(&identity),
            Arc::clone(&registry),
            Arc::clone(&reconnect_how),
        );
        std::thread::spawn(move || {
            let mut last_recv = Instant::now();
            loop {
                let rx = current.lock().unwrap().clone();
                match rx.recv() {
                    Ok(m) => {
                        stats.recv_msgs.fetch_add(1, Ordering::Relaxed);
                        stats
                            .recv_bytes
                            .fetch_add(m.len() as u64, Ordering::Relaxed);
                        dlog!(
                            "recv",
                            "{:.1} ms after previous | plaintext: {}",
                            ms_since(last_recv),
                            describe(&m)
                        );
                        last_recv = Instant::now();
                        trace_ratchet(&rx, &last_pub, "after receive");

                        if let Some(id) = m.strip_prefix(PING) {
                            // Reply with the same id so the sender can match it.
                            let reply = [PONG, id].concat();
                            dlog!("ping", "got ping {}; replying", String::from_utf8_lossy(id));
                            send_traced(&rx, &reply, &stats, &last_pub);
                        } else if let Some(id) = m.strip_prefix(PONG) {
                            let id: u64 = String::from_utf8_lossy(id).parse().unwrap_or(0);
                            match pings.lock().unwrap().remove(&id) {
                                Some(t0) => println!(
                                    "pong #{id}: round trip {:.2} ms (encrypt + wire + peer decrypt/encrypt + wire + decrypt)",
                                    ms_since(t0)
                                ),
                                None => println!("pong #{id}: no matching ping (late or duplicate)"),
                            }
                        } else {
                            println!("peer> {}", String::from_utf8_lossy(&m));
                        }
                    }
                    Err(e) => {
                        if quitting.load(Ordering::SeqCst) {
                            break;
                        }
                        dlog!(
                            "session",
                            "link ended: {e:?} (heard from peer {:.1} s ago)",
                            rx.time_since_heard().as_secs_f64()
                        );
                        if !auto_reconnect {
                            eprintln!("[connection ended: {e}] - exiting (--no-reconnect)");
                            print_summary(&rx, &stats);
                            std::process::exit(1);
                        }
                        eprintln!("[connection lost: {e}] - reconnecting; unsent/unacked messages are kept and will be delivered");
                        match reconnect(
                            &rx,
                            listening,
                            &identity,
                            &registry,
                            &reconnect_how,
                            &quitting,
                        ) {
                            Some(Reconnected::Resumed) => {
                                eprintln!(
                                    "[reconnected] same session resumed; session id: {}",
                                    rx.session_id()
                                );
                            }
                            Some(Reconnected::Replaced(fresh)) => {
                                eprintln!(
                                    "[reconnected] the peer RESTARTED and lost its state, so this is a NEW session (messages the old one had not delivered are gone); session id: {}",
                                    fresh.session_id()
                                );
                                dlog!("session", "old session replaced: peer epoch changed");
                                *current.lock().unwrap() = Arc::new(fresh);
                            }
                            None => break, // quitting
                        }
                        last_recv = Instant::now();
                    }
                }
            }
        })
    };

    // ---- keyboard loop ----
    for line in std::io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        let session = current.lock().unwrap().clone();
        if line.starts_with("//") {
            if !send_traced(&session, &line.as_bytes()[1..], &stats, &last_pub) {
                break;
            }
        } else if line.starts_with('/') {
            command(&line, &session, &stats, &pings, &next_ping, &last_pub);
        } else if !send_traced(&session, line.as_bytes(), &stats, &last_pub) {
            break;
        }
    }

    let session = current.lock().unwrap().clone();
    quitting.store(true, Ordering::SeqCst);
    dlog!(
        "session",
        "stdin closed; waiting up to 5 s for in-flight messages to be acked"
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    while session.pending_unacked() > 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    // For scripted use: linger briefly so the peer's replies can arrive.
    std::thread::sleep(Duration::from_millis(
        std::env::var("P2P_LINGER_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0),
    ));
    print_summary(&session, &stats);
    drop(printer);
}

/// Get a new connection to the SAME peer and resume this session on it.
/// A listener waits for the peer to come back; a dialer redials with
/// exponential backoff (1 s, 2 s, ... capped at 15 s). The session keeps its
/// ratchet and its unacked messages, so nothing sent meanwhile is lost.
/// A reconnect that authenticates a different peer is refused by the library.
fn reconnect(
    session: &Arc<Session>,
    listening: bool,
    identity: &Identity,
    registry: &PeerRegistry,
    how: &Mutex<(Option<TcpListener>, Option<String>)>,
    quitting: &AtomicBool,
) -> Option<Reconnected> {
    let role = if listening {
        Role::Responder
    } else {
        Role::Initiator
    };
    let mut backoff = Duration::from_secs(1);
    while !quitting.load(Ordering::SeqCst) {
        let stream = {
            let guard = how.lock().unwrap();
            match (&guard.0, &guard.1) {
                (Some(listener), _) => match listener.accept() {
                    Ok((s, from)) => {
                        eprintln!("[connection from {from}]");
                        Some(s)
                    }
                    Err(e) => {
                        eprintln!("[accept failed: {e}]");
                        None
                    }
                },
                (_, Some(addr)) => match dial(addr) {
                    Ok(s) => Some(s),
                    Err(e) => {
                        eprintln!("[cannot reach {addr}: {e}; retrying in {backoff:?}]");
                        None
                    }
                },
                _ => None,
            }
        };
        if let Some(stream) = stream {
            let t = Instant::now();
            match session.reconnect_or_replace(
                Box::new(stream),
                role,
                identity,
                registry,
                session_config(),
                None,
            ) {
                Ok(outcome) => {
                    dlog!(
                        "session",
                        "RECONNECTED in {:.1} ms; unacked carried over: {}",
                        ms_since(t),
                        session.pending_unacked()
                    );
                    return Some(outcome);
                }
                Err(e) => {
                    eprintln!("[reconnect handshake failed: {e}]");
                    dlog!("session", "reconnect failed: {e:?}");
                }
            }
        }
        std::thread::sleep(backoff);
        backoff = (backoff * 2).min(Duration::from_secs(15));
    }
    None
}

/// Handle one `/command` typed by the user.
fn command(
    line: &str,
    session: &Arc<Session>,
    stats: &Arc<Stats>,
    pings: &Arc<Mutex<HashMap<u64, Instant>>>,
    next_ping: &Arc<AtomicU64>,
    last_pub: &Arc<Mutex<[u8; 32]>>,
) {
    let mut parts = line.split_whitespace();
    match parts.next() {
        Some("/ping") => {
            let n: u32 = parts
                .next()
                .and_then(|v| v.parse().ok())
                .unwrap_or(1)
                .clamp(1, 100);
            for _ in 0..n {
                let id = next_ping.fetch_add(1, Ordering::Relaxed);
                pings.lock().unwrap().insert(id, Instant::now());
                send_traced(
                    session,
                    format!("\x01PING:{id}").as_bytes(),
                    stats,
                    last_pub,
                );
                std::thread::sleep(Duration::from_millis(200));
            }
        }
        Some("/state") => {
            let info = session.ratchet_info();
            println!("peer        : {}", session.peer_id());
            println!("session id  : {}", session.session_id());
            println!("protocol    : {}", session.negotiated_version());
            println!("unacked     : {}", session.pending_unacked());
            println!(
                "link        : {} (last heard {:.1} s ago, last keepalive rtt {})",
                if session.link_alive() {
                    "alive"
                } else {
                    "DOWN"
                },
                session.time_since_heard().as_secs_f64(),
                session
                    .last_ping_rtt()
                    .map(|d| format!("{:.2} ms", d.as_secs_f64() * 1000.0))
                    .unwrap_or_else(|| "n/a yet".into())
            );
            println!(
                "ratchet     : own_pub={}… sent_in_chain={} recv_in_chain={} prev_chain={} cached_skipped={}",
                short_hex(&info.own_public),
                info.sent_in_chain,
                info.received_in_chain,
                info.previous_chain_len,
                info.cached_skipped_keys
            );
            println!(
                "traffic     : sent {} msgs / {} bytes, received {} msgs / {} bytes (plaintext sizes)",
                stats.sent_msgs.load(Ordering::Relaxed),
                stats.sent_bytes.load(Ordering::Relaxed),
                stats.recv_msgs.load(Ordering::Relaxed),
                stats.recv_bytes.load(Ordering::Relaxed)
            );
        }
        Some("/help") | None => println!(
            "commands: /ping [N]   /state   /help   (start with // to send a literal slash)"
        ),
        Some(other) => println!(
            "unknown command {other}; try /help (use //{} to send it as text)",
            &other[1..]
        ),
    }
}

/// End-of-run summary for the trace.
fn print_summary(session: &Session, stats: &Stats) {
    dlog!(
        "summary",
        "ran {:.1} s | sent {} msgs / {} plaintext bytes | received {} msgs / {} plaintext bytes | unacked at exit: {}",
        dbg().start.elapsed().as_secs_f64(),
        stats.sent_msgs.load(Ordering::Relaxed),
        stats.sent_bytes.load(Ordering::Relaxed),
        stats.recv_msgs.load(Ordering::Relaxed),
        stats.recv_bytes.load(Ordering::Relaxed),
        session.pending_unacked()
    );
}
