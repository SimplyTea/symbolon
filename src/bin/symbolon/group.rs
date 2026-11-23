//! Group mode for the `symbolon` test client.
//!
//! Like the rest of the CLI this is a TEST HARNESS, not the product. It
//! builds a full mesh of real pairwise sessions on top of the library's
//! `GroupHub`, so you can try group chat on a LAN, on a Pi, or across the
//! internet (via a port-forward / Tailscale / WireGuard).
//!
//! # Workflow
//!
//! 1. Everyone runs `keygen` and shares their PUBLIC key (`show`).
//! 2. ONE person (the creator) runs `group-new --members KEY1,KEY2,...`.
//!    That prints a group id and an INVITE (hex). The invite is public, but
//!    members must receive it from the creator and check the creator's key
//!    (next step), otherwise an impostor could hand out a different group.
//! 3. Every other member runs `group-run --invite HEX --trust CREATORKEY ...`
//!    once; later runs only need `--group GROUPID` (state is saved, encrypted).
//!
//! # Who connects to whom
//!
//! Every pair of members needs exactly ONE connection. The rule: the member
//! with the SMALLER fingerprint dials, the one with the larger fingerprint
//! listens. So each member passes `--peer KEYHEX=HOST:PORT` only for peers
//! with a larger fingerprint than their own (extras are ignored with a
//! note) and `--bind` for everyone who must be dialled. Everyone can pass
//! all the addresses they know; the rule decides who actually dials.
//!
//! # Limits of this harness (library features not built yet)
//! * Membership is fixed at `group-new` time: a member added LATER cannot
//!   join, because roster history is not yet synced to newcomers.
//! * A reconnect makes a fresh pairwise session; anything the old session
//!   had not delivered is recovered through the group's relay catch-up.

use std::collections::HashSet;
use std::io::BufRead;
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use symbolon::group::{
    GroupEvent, GroupHub, GroupHubConfig, GroupMessage, MemberKind, Roster, RosterOpWire,
};
use symbolon::identity::{
    decode_public_key, encode_public_key, fingerprint, Identity, PeerId, PeerRegistry,
};
use symbolon::session::{Role, Session, SessionConfig};

use super::{dbg, die, flag, load_identity};

/// Print to stdout for people, to stderr for bots: a bot's stdout carries
/// ONLY its machine-readable event lines, so a program can pipe it safely.
macro_rules! info {
    ($bot:expr, $($arg:tt)*) => {
        if $bot { eprintln!($($arg)*) } else { println!($($arg)*) }
    };
}

/// Where group state (one encrypted log per group) lives by default.
fn state_dir(args: &[String]) -> PathBuf {
    if let Some(d) = flag(args, "--state-dir") {
        return PathBuf::from(d);
    }
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join(".symbolon").join("groups")
}

fn ensure_dir(dir: &PathBuf) {
    std::fs::create_dir_all(dir)
        .unwrap_or_else(|e| die(&format!("cannot create {}: {e}", dir.display())));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
}

/// Every value given for a repeatable flag (`--peer A --peer B`).
fn flag_all(args: &[String], name: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == name {
            if let Some(v) = args.get(i + 1) {
                out.push(v.clone());
            }
            i += 2;
        } else {
            i += 1;
        }
    }
    out
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) || !s.is_ascii() {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// Hub settings from the command line: library trace events go to the
/// `--debug` sink, and `--hide-relayed` keeps content that did not come from
/// its author out (only its existence is recorded; use `/fetch`).
fn hub_config(args: &[String]) -> GroupHubConfig {
    let mut cfg = GroupHubConfig {
        tracer: super::cli_tracer(),
        receipts: symbolon::group::ReceiptSettings {
            delivery: !args.iter().any(|a| a == "--no-receipts"),
            read: args.iter().any(|a| a == "--read-receipts"),
        },
        relayed_content: if args.iter().any(|a| a == "--hide-relayed") {
            symbolon::group::RelayedContent::ExistenceOnly
        } else {
            symbolon::group::RelayedContent::Deliver
        },
        ..Default::default()
    };
    if let Some(v) = flag(args, "--relay-cache") {
        cfg.relay_cache_capacity_per_sender = v
            .parse()
            .unwrap_or_else(|_| die("--relay-cache takes a whole number"));
    }
    cfg
}

/// `group-new`: found a group, save its log, print the invite.
pub fn group_new(args: &[String]) {
    let identity = load_identity(args);
    let list = flag(args, "--members").unwrap_or_else(|| {
        die("--members KEY1,KEY2,... is required (the OTHER members' public keys)")
    });
    let mut keys = Vec::new();
    for hex in list.split(',').filter(|s| !s.trim().is_empty()) {
        keys.push(
            decode_public_key(hex).unwrap_or_else(|e| die(&format!("bad member key {hex:?}: {e}"))),
        );
    }
    if keys.is_empty() {
        die("a group needs at least one other member");
    }

    let relay = match flag(args, "--relay").as_deref() {
        None | Some("open") => symbolon::group::RelayPolicy::Open,
        Some("author-only") => symbolon::group::RelayPolicy::AuthorOnly,
        Some(o) => die(&format!("--relay takes open or author-only, not {o:?}")),
    };
    let (roster, genesis) = {
        let tiers = vec![
            ("owner".to_string(), symbolon::group::Permissions::FULL),
            (
                "member".to_string(),
                symbolon::group::Permissions::READ_WRITE,
            ),
            // Tiers for bots (they may never hold can_add / can_remove):
            // "bot" reads and writes, "listener" can only read.
            ("bot".to_string(), symbolon::group::Permissions::READ_WRITE),
            (
                "listener".to_string(),
                symbolon::group::Permissions {
                    can_read: true,
                    ..symbolon::group::Permissions::NONE
                },
            ),
        ];
        let mut members = vec![(identity.public_key(), "owner".to_string())];
        members.extend(keys.into_iter().map(|k| (k, "member".to_string())));
        Roster::genesis_with_policy(
            &identity,
            symbolon::group::GroupKind::FullMesh,
            relay,
            tiers,
            members,
        )
    };
    let dir = state_dir(args);
    ensure_dir(&dir);
    let log_path = dir.join(format!("{}.log", roster.group_id));
    if log_path.exists() {
        die(&format!(
            "{} already exists; this exact group was already created",
            log_path.display()
        ));
    }
    GroupHub::create_persisted(&identity, roster, &genesis, &log_path, hub_config(args))
        .unwrap_or_else(|e| die(&format!("cannot create group: {e}")));

    let invite = to_hex(&GroupMessage::Roster(RosterOpWire::from(&genesis)).encode());
    let group_id = {
        let hub = GroupHub::load_persisted(
            &identity,
            &log_path,
            GroupHubConfig {
                auto_pump: false,
                tracer: super::cli_tracer(),
                ..Default::default()
            },
        )
        .unwrap_or_else(|e| die(&format!("cannot reopen group: {e}")));
        hub.group_id()
    };
    println!("group id   : {group_id}");
    println!("state file : {}", log_path.display());
    println!(
        "creator    : {}   (give members your PUBLIC key: they pass it as --trust)",
        encode_public_key(&identity.public_key())
    );
    println!("invite     : {invite}");
    println!();
    println!("Members run:  symbolon group-run --invite <invite> --trust <creator public key> --bind 0.0.0.0:7000 [--peer KEY=HOST:PORT ...]");
}

/// Build a registry that accepts exactly the group's other members.
fn registry_for(keys: &[ed25519_dalek::VerifyingKey], own: &PeerId) -> PeerRegistry {
    let mut r = PeerRegistry::new();
    for k in keys {
        if fingerprint(k) != *own {
            r.trust(*k);
        }
    }
    r
}

/// Print a one-line description of an event.
fn show_event(ev: GroupEvent) {
    let who = |id: &PeerId| id.short();
    match ev {
        GroupEvent::Message {
            sender,
            seq,
            payload,
        } => println!(
            "[{} #{seq}] {}",
            who(&sender),
            String::from_utf8_lossy(&payload)
        ),
        GroupEvent::MessageEdited {
            author,
            seq,
            new_payload,
        } => {
            println!(
                "[{} #{seq} edited] {}",
                who(&author),
                String::from_utf8_lossy(&new_payload)
            )
        }
        GroupEvent::MessageDeleted {
            author,
            seq,
            deleted_by,
        } => {
            println!("[{} #{seq}] deleted by {}", who(&author), who(&deleted_by))
        }
        GroupEvent::MembershipChanged { members } => {
            println!("[roster changed: {} members]", members.len())
        }
        GroupEvent::Receipt { from, seq, kind } => {
            println!("[receipt] {} {:?} your #{seq}", who(&from), kind)
        }
        GroupEvent::Existence { author, seq } => println!(
            "[{} #{seq}] exists but content not held (try /fetch {} {seq})",
            who(&author),
            who(&author)
        ),
        GroupEvent::FileOffered { sender, seq, offer } => println!(
            "[{} #{seq}] offers a file: {} ({} bytes)",
            who(&sender),
            offer.name.as_deref().unwrap_or("(no name)"),
            offer.size
        ),
        GroupEvent::FileProgress {
            author,
            seq,
            done,
            total,
        } => {
            println!("[file {} #{seq}] {done}/{total} chunks", who(&author))
        }
        GroupEvent::FileComplete { author, seq } => {
            println!("[file {} #{seq}] complete", who(&author))
        }
        GroupEvent::FileFailed {
            author,
            seq,
            reason,
        } => {
            println!("[file {} #{seq}] failed: {reason}", who(&author))
        }
    }
}

/// Attach a freshly established session to the hub and ask for catch-up.
fn attach(
    hub: &Arc<GroupHub>,
    session: Session,
    connected: &Arc<Mutex<HashSet<PeerId>>>,
) -> Arc<Session> {
    let peer = session.peer_id();
    let session = Arc::new(session);
    hub.attach_session(peer, Arc::clone(&session));
    connected.lock().unwrap().insert(peer);
    eprintln!(
        "[connected] {}  (session id {})",
        peer.short(),
        &session.session_id()[..16]
    );
    dlog!(
        "group",
        "attached session with {peer} (session_id {})",
        session.session_id()
    );
    let _ = hub.request_catchup();
    session
}

/// `group-run`: join the mesh and chat.
pub fn group_run(args: &[String]) {
    run_group(args, false)
}

/// `bot-run`: join the mesh as a BOT (see `bot_loop`). The bot must already
/// have been added by a member with `/addbot`.
pub fn bot_run(args: &[String]) {
    run_group(args, true)
}

fn run_group(args: &[String], bot: bool) {
    let identity = Arc::new(load_identity(args));
    let own_fp = identity.fingerprint();
    let dir = state_dir(args);
    ensure_dir(&dir);

    // ---- find or create our local copy of the group ----
    let hub = if let Some(invite_hex) = flag(args, "--invite") {
        let creator = decode_public_key(
            &flag(args, "--trust")
                .unwrap_or_else(|| die("--trust <creator public key> is required with --invite")),
        )
        .unwrap_or_else(|e| die(&format!("bad --trust key: {e}")));
        let bytes = from_hex(&invite_hex).unwrap_or_else(|| die("invite is not valid hex"));
        let GroupMessage::Roster(wire) =
            GroupMessage::decode(&bytes).unwrap_or_else(|e| die(&format!("bad invite: {e}")))
        else {
            die("invite is not a group genesis")
        };
        let signed = wire
            .to_signed()
            .unwrap_or_else(|e| die(&format!("bad invite: {e}")));
        if signed.proposer != fingerprint(&creator) {
            die("the invite was NOT created by the key you passed in --trust; refusing (possible impostor group)");
        }
        let roster = Roster::from_genesis(&signed)
            .unwrap_or_else(|e| die(&format!("invite failed verification: {e}")));
        if !roster.is_member(&own_fp) {
            // Normal for someone ADDED AFTER the group was created: the invite
            // is only the genesis. Connect to any member and the roster
            // (including your own membership) is synced automatically.
            eprintln!("[note] you are not in the group's founding roster; you will learn whether you were added after connecting to a member]");
        }
        let log_path = dir.join(format!("{}.log", roster.group_id));
        if log_path.exists() {
            GroupHub::load_persisted(&identity, &log_path, hub_config(args))
                .unwrap_or_else(|e| die(&format!("cannot load saved group: {e}")))
        } else {
            GroupHub::create_persisted(&identity, roster, &signed, &log_path, hub_config(args))
                .unwrap_or_else(|e| die(&format!("cannot save group: {e}")))
        }
    } else {
        let gid = flag(args, "--group").unwrap_or_else(|| {
            die("pass --invite HEX (first time) or --group GROUPID (afterwards)")
        });
        if !gid.chars().all(|c| c.is_ascii_hexdigit()) {
            die("--group must be the hex group id");
        }
        let log_path = dir.join(format!("{gid}.log"));
        GroupHub::load_persisted(&identity, &log_path, hub_config(args))
            .unwrap_or_else(|e| die(&format!("cannot load {}: {e}", log_path.display())))
    };

    // Receipts are signed with our identity (the hub never holds the key itself).
    hub.enable_receipts(Arc::clone(&identity));
    // Session state (ratchets, unacked messages) is saved by default, so
    // restarting this program resumes sessions; --no-session-state opts out.
    let persistence = if args.iter().any(|a| a == "--no-session-state") {
        None
    } else {
        let sdir = state_dir(args).join("sessions");
        let store = symbolon::storage::FileStateStore::open(&sdir)
            .unwrap_or_else(|e| die(&format!("cannot open {}: {e}", sdir.display())));
        Some(symbolon::sessionstate::SessionPersistence::new(
            Arc::new(store),
            &identity,
        ))
    };
    // Held for the life of group_run: dropping it would stop the announcements.
    let mut _announcer = None;
    let keys = hub.member_keys();
    info!(bot, "you are {}", own_fp);
    info!(bot, "group  {}  ({} members)", hub.group_id(), keys.len());
    for k in &keys {
        let fp = fingerprint(k);
        info!(
            bot,
            "  member {}{}{}",
            &fp.to_hex()[..16],
            if hub.kind_of(&fp) == Some(MemberKind::Bot) {
                " [bot]"
            } else {
                ""
            },
            if fp == own_fp { "  (you)" } else { "" }
        );
    }
    let connected: Arc<Mutex<HashSet<PeerId>>> = Arc::new(Mutex::new(HashSet::new()));

    // ---- listener: accept the members who dial us ----
    if let Some(bind) = flag(args, "--bind") {
        let listener =
            TcpListener::bind(&bind).unwrap_or_else(|e| die(&format!("cannot bind {bind}: {e}")));
        info!(bot, "listening on {}", listener.local_addr().unwrap());
        _announcer = super::start_announce(args, listener.local_addr().unwrap().port());
        let (hub, identity, connected, own, persistence) = (
            Arc::clone(&hub),
            Arc::clone(&identity),
            Arc::clone(&connected),
            own_fp,
            persistence.clone(),
        );
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let (hub, identity, connected, own, persistence) = (
                    Arc::clone(&hub),
                    Arc::clone(&identity),
                    Arc::clone(&connected),
                    own,
                    persistence.clone(),
                );
                // One thread per incoming connection so a slow/hostile
                // handshake cannot block the others.
                std::thread::spawn(move || {
                    // The CURRENT roster decides who may connect (so members
                    // added since startup, or learned by sync, are accepted).
                    let registry = registry_for(&hub.member_keys(), &own);
                    match Session::establish_with(
                        stream,
                        Role::Responder,
                        &identity,
                        &registry,
                        SessionConfig {
                            persistence,
                            ..super::session_config()
                        },
                        None,
                    ) {
                        Ok(s) => {
                            attach(&hub, s, &connected);
                        }
                        Err(e) => {
                            eprintln!("[rejected incoming connection: {e}]");
                            dlog!("group", "incoming handshake failed: {e:?}");
                        }
                    }
                });
            }
        });
    }

    // ---- dialers: connect to peers with a LARGER fingerprint ----
    let ctx = Ctx {
        dialing: Arc::new(Mutex::new(HashSet::new())),
        persistence: persistence.clone(),
        hub: Arc::clone(&hub),
        identity: Arc::clone(&identity),
        connected: Arc::clone(&connected),
        own_fp,
    };
    for spec in flag_all(args, "--peer") {
        if let Err(e) = add_peer(&ctx, &spec) {
            die(&e);
        }
    }

    // ---- optional periodic catch-up ----
    // OFF by default. Members without a direct link to an author now learn of
    // new posts because whoever accepts one announces it (GroupMessage::Have)
    // and they ask that peer for it. A timer is only a safety net for people
    // who want one (e.g. very lossy links): --catchup S asks every S seconds.
    let catchup_secs: u64 = match flag(args, "--catchup") {
        Some(v) => v
            .parse()
            .unwrap_or_else(|_| die("--catchup takes a whole number of seconds (0 = off)")),
        None => 0,
    };
    if catchup_secs > 0 {
        let hub = Arc::clone(&hub);
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_secs(catchup_secs));
            let _ = hub.request_catchup();
        });
    }

    // ---- event printer ----
    let tsv = bot && flag(args, "--format").as_deref() == Some("tsv");
    {
        let hub = Arc::clone(&hub);
        std::thread::spawn(move || {
            while let Ok(ev) = hub.recv_event() {
                dlog!("group", "event: {ev:?}");
                if tsv {
                    show_event_tsv(ev);
                } else {
                    show_event(ev);
                }
            }
        });
    }

    if bot {
        bot_loop(args, &ctx);
    } else {
        println!("type a line to post; /help for commands; Ctrl-D to quit");
        // ---- keyboard loop ----
        for line in std::io::stdin().lock().lines() {
            let Ok(line) = line else { break };
            let line = line.trim_end().to_string();
            if line.is_empty() {
                continue;
            }
            if let Some(rest) = line.strip_prefix('/').filter(|_| !line.starts_with("//")) {
                handle_command(rest, &ctx);
            } else {
                let text = if line.starts_with("//") {
                    &line[1..]
                } else {
                    &line[..]
                };
                match hub.post(&identity, text.as_bytes()) {
                    Ok(seq) => dlog!("group", "posted #{seq}: {text:?}"),
                    Err(e) => eprintln!("[post failed: {e}]"),
                }
            }
        }
    }
    if !hub.persistence_healthy() {
        eprintln!("[warning: some history could NOT be saved to disk during this run]");
    }
}

/// One tab-separated line per event, for programs: `kind TAB who TAB seq TAB
/// text`. Tabs, newlines and backslashes inside text are escaped (`\t`, `\n`,
/// `\\`), so one event is always exactly one line and a message can never
/// forge a second record.
fn show_event_tsv(ev: GroupEvent) {
    fn esc(bytes: &[u8]) -> String {
        let mut out = String::new();
        for c in String::from_utf8_lossy(bytes).chars() {
            match c {
                '\\' => out.push_str("\\\\"),
                '\t' => out.push_str("\\t"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                c if c.is_control() => out.push('?'),
                c => out.push(c),
            }
        }
        out
    }
    match ev {
        GroupEvent::Message {
            sender,
            seq,
            payload,
        } => {
            println!("msg\t{sender}\t{seq}\t{}", esc(&payload))
        }
        GroupEvent::MessageEdited {
            author,
            seq,
            new_payload,
        } => {
            println!("edit\t{author}\t{seq}\t{}", esc(&new_payload))
        }
        GroupEvent::MessageDeleted {
            author,
            seq,
            deleted_by,
        } => {
            println!("del\t{author}\t{seq}\t{deleted_by}")
        }
        GroupEvent::MembershipChanged { members } => {
            println!("roster\t\t\t{}", members.len())
        }
        GroupEvent::Receipt { from, seq, kind } => {
            println!("receipt\t{from}\t{seq}\t{kind:?}")
        }
        GroupEvent::Existence { author, seq } => println!("exists\t{author}\t{seq}\t"),
        GroupEvent::FileOffered { sender, seq, offer } => {
            println!("file-offer\t{sender}\t{seq}\t{}", offer.size)
        }
        GroupEvent::FileProgress {
            author,
            seq,
            done,
            total,
        } => {
            println!("file-progress\t{author}\t{seq}\t{done}/{total}")
        }
        GroupEvent::FileComplete { author, seq } => println!("file-complete\t{author}\t{seq}\t"),
        GroupEvent::FileFailed {
            author,
            seq,
            reason,
        } => {
            println!("file-failed\t{author}\t{seq}\t{reason}")
        }
    }
}

/// The bot's foreground behaviour.
///
/// * LISTEN: events are already printing (plain or `--format tsv`).
/// * WRITE: each `--say TEXT` is posted once, as soon as a member is
///   connected (or after 15 s); then every line on stdin is posted VERBATIM
///   unless `--listen-only`. Lines are NOT parsed as commands (a program
///   feeding text must not be able to run `/remove`...); `--commands` turns
///   command parsing on for a human driving the bot by hand.
/// * `--seconds N` exits after N seconds. A one-shot alert bot is
///   `bot-run ... --say "disk full" --listen-only --seconds 20`; keep N long
///   enough for delivery (saved session state also retries on the next run).
fn bot_loop(args: &[String], ctx: &Ctx) {
    let listen_only = args.iter().any(|a| a == "--listen-only");
    let commands = args.iter().any(|a| a == "--commands");
    if let Some(n) = flag(args, "--seconds") {
        let secs: u64 = n
            .parse()
            .unwrap_or_else(|_| die("--seconds needs a whole number"));
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(secs));
            eprintln!("[--seconds {secs} elapsed; exiting]");
            std::process::exit(0);
        });
    }
    if ctx.hub.kind_of(&ctx.own_fp) != Some(MemberKind::Bot) {
        eprintln!("[warning: this identity is not (yet) a BOT member of the group; ask a sponsor to /addbot your public key. Posts will be rejected until then]");
    }
    let says = flag_all(args, "--say");
    if !says.is_empty() {
        let (hub, identity, connected) = (
            Arc::clone(&ctx.hub),
            Arc::clone(&ctx.identity),
            Arc::clone(&ctx.connected),
        );
        std::thread::spawn(move || {
            // Wait until we are connected AND have learned (by roster sync)
            // that we are a bot member; posting earlier is rejected.
            let t = Instant::now();
            let ready = |hub: &GroupHub| hub.kind_of(hub.own_id()) == Some(MemberKind::Bot);
            while (connected.lock().unwrap().is_empty() || !ready(&hub))
                && t.elapsed() < Duration::from_secs(60)
            {
                std::thread::sleep(Duration::from_millis(100));
            }
            if !ready(&hub) {
                eprintln!("[--say skipped: not a bot member of this group after 60 s; was /addbot run with this key?]");
                return;
            }
            for text in says {
                if let Err(e) = hub.post(&identity, text.as_bytes()) {
                    eprintln!("[--say failed: {e}]");
                }
            }
        });
    }
    if listen_only {
        // Nothing to read: just stay up (until --seconds or a signal).
        loop {
            std::thread::sleep(Duration::from_secs(3600));
        }
    }
    for line in std::io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        let line = line.trim_end().to_string();
        if line.is_empty() {
            continue;
        }
        if commands && line.starts_with('/') && !line.starts_with("//") {
            handle_command(&line[1..], ctx);
        } else {
            let text = if commands && line.starts_with("//") {
                &line[1..]
            } else {
                &line[..]
            };
            if let Err(e) = ctx.hub.post(&ctx.identity, text.as_bytes()) {
                eprintln!("[post failed: {e}]");
            }
        }
    }
}

/// Everything the dialers and the keyboard commands share.
struct Ctx {
    /// Peers we already have a dial loop for. A second loop for the same
    /// peer would attach a second session and replace the first.
    dialing: Arc<Mutex<HashSet<PeerId>>>,
    persistence: Option<Arc<symbolon::sessionstate::SessionPersistence>>,
    hub: Arc<GroupHub>,
    identity: Arc<Identity>,
    connected: Arc<Mutex<HashSet<PeerId>>>,
    own_fp: PeerId,
}

/// Start dialling `KEYHEX=HOST:PORT` if WE are the side that dials (smaller
/// fingerprint); otherwise explain that they will dial us.
fn add_peer(ctx: &Ctx, spec: &str) -> std::result::Result<(), String> {
    let (key_hex, addr) = spec
        .split_once('=')
        .ok_or_else(|| format!("peer must look like KEYHEX=HOST:PORT, got {spec:?}"))?;
    let key = decode_public_key(key_hex).map_err(|e| format!("bad peer key: {e}"))?;
    let peer_fp = fingerprint(&key);
    if peer_fp == ctx.own_fp {
        return Err("that is your own key".to_string());
    }
    if !ctx.hub.is_member(&peer_fp) {
        eprintln!("[note] {} is not in your roster yet; dialling anyway - the connection will succeed once the roster syncs]", peer_fp.short());
    }
    if peer_fp < ctx.own_fp {
        eprintln!("[note] {} has the smaller fingerprint, so THEY dial you; use --bind and give them your address]", peer_fp.short());
        return Ok(());
    }
    // One dial loop per peer. (Repeating --peer, or /peer twice, used to start
    // two loops that each attached a session, the second replacing the first.)
    if !ctx.dialing.lock().unwrap().insert(peer_fp) {
        eprintln!(
            "[note] already dialling {}; ignoring the repeat (restart to change its address)]",
            peer_fp.short()
        );
        return Ok(());
    }
    let (hub, identity, connected, _own, addr, persistence) = (
        Arc::clone(&ctx.hub),
        Arc::clone(&ctx.identity),
        Arc::clone(&ctx.connected),
        ctx.own_fp,
        addr.to_string(),
        ctx.persistence.clone(),
    );
    let expect_peer = peer_fp;
    std::thread::spawn(move || {
        let mut backoff = Duration::from_secs(1);
        loop {
            let t = Instant::now();
            eprintln!("[dialling {addr} ...]");
            match super::dial(&addr) {
                Ok(stream) => {
                    // Trust ONLY the peer we meant to dial. If this address
                    // actually belongs to someone else (a typo, 127.0.0.1 on
                    // the wrong machine) the handshake is refused BEFORE we
                    // answer it, so the other side never attaches a session
                    // that would replace a good one.
                    let mut registry = PeerRegistry::new();
                    registry.trust(key);
                    match Session::establish_with(
                        stream,
                        Role::Initiator,
                        &identity,
                        &registry,
                        SessionConfig {
                            persistence: persistence.clone(),
                            expect_peer: Some(expect_peer),
                            ..super::session_config()
                        },
                        None,
                    ) {
                        Ok(s) => {
                            backoff = Duration::from_secs(1);
                            let session = attach(&hub, s, &connected);
                            // Stay here while the link lives; when it dies, redial.
                            while session.link_alive() {
                                std::thread::sleep(Duration::from_millis(500));
                            }
                            eprintln!("[link to {} lost; redialling]", peer_fp.short());
                            connected.lock().unwrap().remove(&peer_fp);
                        }
                        Err(e) => {
                            eprintln!(
                                "[handshake with {addr} failed: {e}; retrying in {backoff:?}]"
                            );
                            dlog!(
                                "group",
                                "dial handshake failed after {:.1} ms: {e:?}",
                                super::ms_since(t)
                            );
                        }
                    }
                }
                Err(e) => {
                    dlog!("group", "dial {addr} failed: {e}");
                    eprintln!("[cannot reach {addr}: {e}; retrying in {backoff:?}]");
                }
            }
            std::thread::sleep(backoff);
            backoff = (backoff * 2).min(Duration::from_secs(15));
        }
    });
    Ok(())
}

fn handle_command(cmd: &str, ctx: &Ctx) {
    let (hub, identity, connected) = (&ctx.hub, &*ctx.identity, &ctx.connected);
    let mut parts = cmd.splitn(3, ' ');
    match parts.next().unwrap_or("") {
        "members" => {
            let up = connected.lock().unwrap().clone();
            for id in hub.member_ids() {
                let tier = hub.tier_of(&id).unwrap_or_default();
                let me = if &id == hub.own_id() { " (you)" } else { "" };
                let link = if up.contains(&id) { " [connected]" } else { "" };
                let bot = match hub.sponsor_of(&id) {
                    Some(s) if hub.kind_of(&id) == Some(MemberKind::Bot) => {
                        format!(" [bot, sponsor {}]", s.short())
                    }
                    _ if hub.kind_of(&id) == Some(MemberKind::Bot) => " [bot]".to_string(),
                    _ => String::new(),
                };
                println!("  {}  tier={tier}{bot}{me}{link}", &id.to_hex()[..16]);
            }
        }
        "bots" => {
            let bots: Vec<PeerId> = hub
                .member_ids()
                .into_iter()
                .filter(|id| hub.kind_of(id) == Some(MemberKind::Bot))
                .collect();
            if bots.is_empty() {
                println!("no bots in this group");
            }
            for id in bots {
                let sponsor = hub.sponsor_of(&id).map(|s| s.to_hex()).unwrap_or_default();
                println!(
                    "  {}  tier={}  sponsor={}",
                    &id.to_hex()[..16],
                    hub.tier_of(&id).unwrap_or_default(),
                    &sponsor[..sponsor.len().min(16)]
                );
            }
        }
        "addbot" => {
            let (Some(key_hex), tier) = (parts.next(), parts.next().unwrap_or("bot")) else {
                println!("usage: /addbot PUBLICKEY [tier]   (default tier \"bot\"; \"listener\" = read-only; you become its sponsor)");
                return;
            };
            match decode_public_key(key_hex) {
                Ok(key) => match hub.propose_add_bot(identity, key, tier.to_string()) {
                    Ok(()) => println!("[added bot {} as {tier}; it needs the invite and a connection to any member. It is removed automatically if you leave or are removed]", fingerprint(&key).short()),
                    Err(e) => println!("[addbot failed: {e}  (the tier must exist and grant neither add nor remove; see /deftier)]"),
                },
                Err(e) => println!("[bad public key: {e}]"),
            }
        }
        "tier" => {
            let (Some(prefix), Some(new_tier)) = (parts.next(), parts.next()) else {
                println!("usage: /tier FPR-PREFIX TIERNAME   (needs add+remove; a bot can only move to bot-safe tiers)");
                return;
            };
            let matches: Vec<PeerId> = hub.member_ids().into_iter().filter(|id| id.to_hex().starts_with(prefix)).collect();
            match matches.as_slice() {
                [one] => match hub.propose_change_tier(identity, *one, new_tier.to_string()) {
                    Ok(()) => println!("[{} is now {new_tier}]", one.short()),
                    Err(e) => println!("[tier change failed: {e}]"),
                },
                [] => println!("no member matches {prefix:?}"),
                _ => println!("{prefix:?} is ambiguous; give more characters"),
            }
        }
        "deftier" => {
            let (Some(name), Some(list)) = (parts.next(), parts.next()) else {
                println!("usage: /deftier NAME read,write,add,remove   (or 'none'; needs add+remove)");
                return;
            };
            let mut p = symbolon::group::Permissions::NONE;
            for w in list.split(',').map(str::trim).filter(|w| !w.is_empty() && *w != "none") {
                match w {
                    "read" => p.can_read = true,
                    "write" => p.can_write = true,
                    "add" => p.can_add = true,
                    "remove" => p.can_remove = true,
                    other => {
                        println!("[unknown permission {other:?}; use read,write,add,remove or none]");
                        return;
                    }
                }
            }
            match hub.propose_define_tier(identity, name.to_string(), p) {
                Ok(()) => println!("[tier {name} defined]"),
                Err(e) => println!("[deftier failed: {e}]"),
            }
        }
        "history" => {
            // Grouped by author, authors in fingerprint order (so the output is
            // stable between runs), each author's messages in their own seq
            // order. `#seq` counts THAT AUTHOR's messages only: there is no
            // group-wide sequence, because there is no server to number them.
            let mut ids = hub.member_ids();
            ids.sort();
            for id in ids {
                for (seq, payload, edited, deleted) in hub.history_for(&id) {
                    let flags = format!("{}{}", if edited { " edited" } else { "" }, if deleted { " DELETED" } else { "" });
                    println!("  [{} #{seq}{flags}] {}", id.short(), String::from_utf8_lossy(&payload));
                }
            }
        }
        "add" => {
            let (Some(key_hex), tier) = (parts.next(), parts.next().unwrap_or("member")) else {
                println!("usage: /add PUBLICKEY [tier]   (needs a tier with can_add; the new member joins with the group's invite)");
                return;
            };
            match decode_public_key(key_hex) {
                Ok(key) => match hub.propose_add(identity, key, tier.to_string()) {
                    Ok(()) => println!("[added {} as {tier}; give them the invite and tell them to connect to any member]", fingerprint(&key).short()),
                    Err(e) => println!("[add failed: {e}]"),
                },
                Err(e) => println!("[bad public key: {e}]"),
            }
        }
        "peer" => match parts.next() {
            Some(spec) => match add_peer(ctx, spec) {
                Ok(()) => {}
                Err(e) => println!("[{e}]"),
            },
            None => println!("usage: /peer PUBLICKEY=HOST:PORT"),
        },
        "catchup" => match hub.request_catchup() {
            Ok(()) => println!("[asked every connected member for anything we are missing]"),
            Err(e) => println!("[catch-up failed: {e}]"),
        },
        "edit" => {
            let (Some(seq), Some(text)) = (parts.next().and_then(|s| s.parse::<u64>().ok()), parts.next()) else {
                println!("usage: /edit SEQ new text");
                return;
            };
            match hub.edit(identity, seq, text.as_bytes()) {
                Ok(_) => {}
                Err(e) => println!("[edit failed: {e}]"),
            }
        }
        "delete" => {
            let Some(seq) = parts.next().and_then(|s| s.parse::<u64>().ok()) else {
                println!("usage: /delete SEQ   (your own message)");
                return;
            };
            if let Err(e) = hub.delete(identity, *hub.own_id(), seq) {
                println!("[delete failed: {e}]");
            }
        }
        "remove" => {
            let Some(prefix) = parts.next() else {
                println!("usage: /remove FINGERPRINT-PREFIX   (needs a tier with can_remove)");
                return;
            };
            let matches: Vec<PeerId> = hub.member_ids().into_iter().filter(|id| id.to_hex().starts_with(prefix)).collect();
            match matches.as_slice() {
                [one] => match hub.propose_remove(identity, *one) {
                    Ok(()) => println!("[removed {}]", one.short()),
                    Err(e) => println!("[remove failed: {e}]"),
                },
                [] => println!("no member matches {prefix:?}"),
                _ => println!("{prefix:?} is ambiguous; give more characters"),
            }
        }
        "fetch" => {
            let (Some(prefix), Some(seq)) = (parts.next(), parts.next().and_then(|s| s.parse::<u64>().ok())) else {
                println!("usage: /fetch AUTHOR-PREFIX SEQ   (ask the author; add 'any' to ask everyone)");
                return;
            };
            let any = parts.next() == Some("any");
            let matches: Vec<PeerId> = hub.member_ids().into_iter().filter(|id| id.to_hex().starts_with(prefix)).collect();
            match matches.as_slice() {
                [one] => {
                    let r = if any { hub.fetch_from_anyone(one, seq) } else { hub.fetch(one, seq) };
                    match r {
                        Ok(()) => println!("[asked for {} #{seq}]", one.short()),
                        Err(e) => println!("[fetch failed: {e}]"),
                    }
                }
                [] => println!("no member matches {prefix:?}"),
                _ => println!("{prefix:?} is ambiguous; give more characters"),
            }
        }
        "read" => {
            let (Some(prefix), Some(seq)) = (parts.next(), parts.next().and_then(|s| s.parse::<u64>().ok())) else {
                println!("usage: /read AUTHOR-PREFIX SEQ   (sends a read receipt; needs --read-receipts)");
                return;
            };
            let matches: Vec<PeerId> = hub.member_ids().into_iter().filter(|id| id.to_hex().starts_with(prefix)).collect();
            match matches.as_slice() {
                [one] => match hub.mark_read(one, seq) {
                    Ok(true) => println!("[read receipt sent]"),
                    Ok(false) => println!("[not sent: read receipts off, message not held, or author not connected]"),
                    Err(e) => println!("[failed: {e}]"),
                },
                [] => println!("no member matches {prefix:?}"),
                _ => println!("{prefix:?} is ambiguous; give more characters"),
            }
        }
        "receipts" => {
            let Some(seq) = parts.next().and_then(|s| s.parse::<u64>().ok()) else {
                println!("usage: /receipts SEQ   (who acknowledged your message)");
                return;
            };
            let r = hub.receipts_for(seq);
            if r.is_empty() {
                println!("no receipts for #{seq}");
            }
            for (who, kind) in r {
                println!("{}: {:?}", who.short(), kind);
            }
        }
        "pending" => {
            for m in hub.member_ids() {
                let p = hub.existence_only(&m);
                if !p.is_empty() {
                    println!("{}: content not held for #{:?}", m.short(), p);
                }
            }
        }
        "state" => {
            println!("group      : {}", hub.group_id());
            println!("you        : {}", &hub.own_id().to_hex()[..16]);
            println!("connected  : {:?}", connected.lock().unwrap().iter().map(|p| p.short()).collect::<Vec<_>>());
            println!("persistence: {}", if hub.persistence_healthy() { "ok" } else { "FAILING - history not being saved" });
        }
        _ => println!("commands: /members /bots /history /catchup /add KEY [tier] /addbot KEY [tier] /tier FPR TIER /deftier NAME perms /peer KEY=HOST:PORT /edit SEQ text /delete SEQ /remove FPR-PREFIX /fetch FPR-PREFIX SEQ [any] /pending /receipts SEQ /read FPR-PREFIX SEQ /state /help  (// sends a literal slash)"),
    }
}
