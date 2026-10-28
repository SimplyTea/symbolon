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
use symbolon::session::{Role, Session, SessionConfig};
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
    DBG.get().expect("logger is initialised first thing in main")
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
    let d = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = d.as_secs();
    let (y, mo, da) = civil_from_days((secs / 86_400) as i64);
    let (h, mi, s) = ((secs / 3600) % 24, (secs / 60) % 60, secs % 60);
    format!("{y:04}-{mo:02}-{da:02} {h:02}:{mi:02}:{s:02}.{:03}Z", d.subsec_millis())
}

impl Dbg {
    /// Write one trace line to stderr (and the log file, if any):
    /// `[wall clock UTC | +seconds since start] tag   message`.
    fn emit(&self, tag: &str, msg: &str) {
        let line = format!("[{} | +{:>8.3}s] {tag:<9} {msg}", wall_clock(), self.start.elapsed().as_secs_f64());
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
  listen    wait for ONE incoming connection from the pinned peer
  connect   dial the pinned peer

FLAGS:
  --id FILE     identity file (default ~/.symbolon/id.enc; an older ~/.p2pchat/id.enc
                is still used if it is the only one that exists)
  --trust HEX   the OTHER side's public key (64 hex chars, from their `show`)
  --bind ADDR   listen address (default 0.0.0.0:7000)
  --addr ADDR   address to connect to, e.g. 192.168.1.42:7000
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

Type lines + Enter to send; Ctrl-D to quit.";

/// Default identity location, so most commands need no `--id`.
fn default_id_path() -> PathBuf {
    let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."));
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
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1).cloned())
}

fn passphrase(prompt: &str) -> String {
    if let Ok(p) = std::env::var("P2P_PASSPHRASE") {
        return p;
    }
    rpassword::prompt_password(prompt).unwrap_or_else(|e| die(&format!("cannot read passphrase: {e}")))
}

fn die(msg: &str) -> ! {
    eprintln!("error: {msg}");
    dlog!("exit", "fatal: {msg}");
    std::process::exit(1)
}

fn load_identity(args: &[String]) -> Identity {
    let path = flag(args, "--id").map(PathBuf::from).unwrap_or_else(default_id_path);
    let pass = passphrase("Passphrase: ");
    let t = Instant::now();
    let result = EncryptedIdentity::load(&path, &pass);
    dlog!("identity", "unlock of {} took {:.1} ms (ok={})", path.display(), ms_since(t), result.is_ok());
    result.unwrap_or_else(|e| match e {
        // By design a wrong passphrase and a damaged file look identical
        // (telling them apart would help an attacker), so say both.
        ChatError::DecryptionFailed => {
            die(&format!("cannot unlock {}: wrong passphrase, or the file is corrupted/tampered", path.display()))
        }
        other => die(&format!("cannot unlock {}: {other}", path.display())),
    })
}

fn registry_from(args: &[String]) -> PeerRegistry {
    let hex = flag(args, "--trust").unwrap_or_else(|| die("--trust <peer public key hex> is required"));
    let key = decode_public_key(&hex).unwrap_or_else(|e| match e {
        ChatError::InvalidPublicKey => die("bad --trust key: not a valid public key (check for a typo or a missing character)"),
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
    let on = args.iter().any(|a| a == "--debug") || std::env::var("P2P_DEBUG").map(|v| v == "1").unwrap_or(false);
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
    let _ = DBG.set(Dbg { on: on || file.is_some(), start: Instant::now(), file: Mutex::new(file) });
    if dbg().on {
        dbg().emit(
            "debug",
            "DEBUG ON: plaintext of every message is printed/logged. Passphrase, private keys and session keys never are.",
        );
        dlog!("args", "{:?}", args.iter().filter(|a| *a != "--debug").collect::<Vec<_>>());
    }

    reject_unknown_arguments(&args);

    match args.first().map(String::as_str) {
        Some("keygen") => keygen(&args),
        Some("show") => show(&args),
        Some("listen") => run(&args, true),
        Some("connect") => run(&args, false),
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
    const WITH_VALUE: [&str; 5] = ["--id", "--trust", "--bind", "--addr", "--log"];
    const SWITCHES: [&str; 1] = ["--debug"];
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
            let hint = if a.contains(':') { " (did you mean --bind or --addr before it?)" } else { "" };
            die(&format!("unrecognised argument {a:?}{hint}; run with no arguments for usage"));
        }
    }
}

fn keygen(args: &[String]) {
    let path = flag(args, "--id").map(PathBuf::from).unwrap_or_else(default_id_path);
    if path.exists() {
        die(&format!("{} already exists; refusing to overwrite", path.display()));
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).unwrap_or_else(|e| die(&format!("cannot create {}: {e}", dir.display())));
    }
    let pass = passphrase("New passphrase: ");
    let id = Identity::generate();
    let t = Instant::now();
    EncryptedIdentity::save(&id, &path, &pass).unwrap_or_else(|e| die(&format!("cannot save identity: {e}")));
    dlog!("identity", "encrypting + saving took {:.1} ms", ms_since(t));
    println!("saved {}", path.display());
    println!("fingerprint: {}", id.fingerprint());
    println!("public key : {}", encode_public_key(&id.public_key()));
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
            dlog!("ack", "seq {seq}: nothing pending {:.2} ms after send (approx ack round trip)", ms_since(t0));
            return;
        }
        if t0.elapsed() > Duration::from_secs(10) {
            dlog!("ack", "seq {seq}: STILL UNACKED after 10 s ({} pending)", session.pending_unacked());
            return;
        }
        std::thread::sleep(Duration::from_millis(1));
    });
}

/// Send one payload, with tracing. Returns false if the send failed.
fn send_traced(session: &Arc<Session>, payload: &[u8], stats: &Stats, last_pub: &Mutex<[u8; 32]>) -> bool {
    let t0 = Instant::now();
    match session.send(payload) {
        Ok(seq) => {
            stats.sent_msgs.fetch_add(1, Ordering::Relaxed);
            stats.sent_bytes.fetch_add(payload.len() as u64, Ordering::Relaxed);
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
            dlog!("send", "FAILED after {:.3} ms: {e:?} | plaintext was: {}", ms_since(t0), describe(payload));
            false
        }
    }
}

/// Shared by `listen` (we accept, so we are the responder) and `connect`.
fn run(args: &[String], listening: bool) {
    let identity = load_identity(args);
    let registry = registry_from(args);
    println!("you are {}", identity.fingerprint());

    let stream = if listening {
        let bind = flag(args, "--bind").unwrap_or_else(|| "0.0.0.0:7000".to_string());
        let listener = TcpListener::bind(&bind).unwrap_or_else(|e| die(&format!("cannot bind {bind}: {e}")));
        println!("Listening on {}", listener.local_addr().unwrap());
        dlog!("net", "listening on {} - waiting for exactly one connection", listener.local_addr().unwrap());
        let (s, from) = listener.accept().unwrap_or_else(|e| die(&format!("accept failed: {e}")));
        eprintln!("connection from {from}");
        dlog!("net", "accepted connection from {from} (local {})", s.local_addr().map(|a| a.to_string()).unwrap_or_default());
        s
    } else {
        let addr = flag(args, "--addr").unwrap_or_else(|| die("--addr host:port is required"));
        dlog!("net", "connecting to {addr} ...");
        let t = Instant::now();
        let s = TcpStream::connect(&addr).unwrap_or_else(|e| die(&format!("cannot connect to {addr}: {e}")));
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
    let role = if listening { Role::Responder } else { Role::Initiator };
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
    let established = Session::establish_with(stream, role, &identity, &registry, SessionConfig::default(), Some(&mut progress));
    let session = match established {
        Ok(s) => s,
        Err(e) => {
            // The debug trace is the place for "everything we know about why".
            dlog!("handshake", "FAILED after {:.2} ms. Last completed step: {last_step}", ms_since(hs_start));
            dlog!("handshake", "error (Display): {e}");
            dlog!("handshake", "error (Debug)  : {e:?}");
            dlog!("handshake", "no application data was exchanged; nothing was decrypted");
            die(&format!("handshake failed: {e}"));
        }
    };
    println!("secure session with {} (protocol v{})", session.peer_id(), session.negotiated_version());
    println!("session id: {}   (should be IDENTICAL on both sides)", session.session_id());
    dlog!("session", "ESTABLISHED in {:.2} ms (handshake) | {:.2} ms since process start", ms_since(hs_start), dbg().start.elapsed().as_secs_f64() * 1000.0);
    dlog!("session", "peer={} protocol_version={} session_id={}", session.peer_id(), session.negotiated_version(), session.session_id());
    dlog!("session", "wire cost per message: 85 bytes fixed overhead (ratchet 56 + transport 25 + frame 4)");

    let session = Arc::new(session);
    let stats = Arc::new(Stats::default());
    let last_pub = Arc::new(Mutex::new(session.ratchet_info().own_public));
    trace_ratchet(&session, &last_pub, "initial state");

    let pings: Arc<Mutex<HashMap<u64, Instant>>> = Arc::new(Mutex::new(HashMap::new()));
    let next_ping = Arc::new(AtomicU64::new(1));
    let quitting = Arc::new(AtomicBool::new(false));

    // ---- receiver thread ----
    let printer = {
        let (rx, stats, pings, quitting, last_pub) =
            (Arc::clone(&session), Arc::clone(&stats), Arc::clone(&pings), Arc::clone(&quitting), Arc::clone(&last_pub));
        std::thread::spawn(move || {
            let mut last_recv = Instant::now();
            loop {
                match rx.recv() {
                    Ok(m) => {
                        stats.recv_msgs.fetch_add(1, Ordering::Relaxed);
                        stats.recv_bytes.fetch_add(m.len() as u64, Ordering::Relaxed);
                        dlog!("recv", "{:.1} ms after previous | plaintext: {}", ms_since(last_recv), describe(&m));
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
                        if !quitting.load(Ordering::SeqCst) {
                            // No reconnect in this test client yet, and the
                            // main thread is blocked on the keyboard, so exit
                            // here rather than leave a dead session looking alive.
                            eprintln!("[connection ended: {e}] - exiting (restart both sides to reconnect)");
                            dlog!("session", "ENDED by peer/network: {e:?}");
                            print_summary(&rx, &stats);
                            std::process::exit(1);
                        }
                        break;
                    }
                }
            }
        })
    };

    // ---- keyboard loop ----
    for line in std::io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        if line.starts_with("//") {
            if !send_traced(&session, line[1..].as_bytes(), &stats, &last_pub) {
                break;
            }
        } else if line.starts_with('/') {
            command(&line, &session, &stats, &pings, &next_ping, &last_pub);
        } else if !send_traced(&session, line.as_bytes(), &stats, &last_pub) {
            break;
        }
    }

    quitting.store(true, Ordering::SeqCst);
    dlog!("session", "stdin closed; waiting up to 5 s for in-flight messages to be acked");
    let deadline = Instant::now() + Duration::from_secs(5);
    while session.pending_unacked() > 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    // For scripted use: linger briefly so the peer's replies can arrive.
    std::thread::sleep(Duration::from_millis(
        std::env::var("P2P_LINGER_MS").ok().and_then(|v| v.parse().ok()).unwrap_or(0),
    ));
    print_summary(&session, &stats);
    drop(printer);
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
            let n: u32 = parts.next().and_then(|v| v.parse().ok()).unwrap_or(1).clamp(1, 100);
            for _ in 0..n {
                let id = next_ping.fetch_add(1, Ordering::Relaxed);
                pings.lock().unwrap().insert(id, Instant::now());
                send_traced(session, format!("\x01PING:{id}").as_bytes(), stats, last_pub);
                std::thread::sleep(Duration::from_millis(200));
            }
        }
        Some("/state") => {
            let info = session.ratchet_info();
            println!("peer        : {}", session.peer_id());
            println!("session id  : {}", session.session_id());
            println!("protocol    : v{}", session.negotiated_version());
            println!("unacked     : {}", session.pending_unacked());
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
        Some("/help") | None => println!("commands: /ping [N]   /state   /help   (start with // to send a literal slash)"),
        Some(other) => println!("unknown command {other}; try /help (use //{} to send it as text)", &other[1..]),
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
