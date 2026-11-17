//! Group chat, built as a thin layer *on top of* the existing pairwise
//! [`crate::session::Session`] rather than a separate protocol.
//!
//! # Why full-mesh instead of a shared group key
//!
//! Every member keeps one ordinary, mutually-authenticated
//! [`crate::session::Session`] with every other member. A "group message"
//! is just that same payload sent out over every one of those links.
//! Nothing about pairwise security changes: each link still gets its own
//! mutual auth, forward secrecy, and gap-free delivery.
//!
//! # Sender authenticity is signed, not transport-implied
//!
//! An earlier version of this module authenticated the sender of a group
//! message purely by *which pairwise session it arrived on*. That works
//! fine as long as every message travels directly from its author - but it
//! breaks the moment you want relaying: if member Y wants to forward
//! something X said to Z (because Z was offline when X sent it, and X
//! isn't online right now either), Z has no way to check "did X really say
//! this" from the transport alone, since the bytes arrived over Y's link,
//! not X's.
//!
//! So every [`GroupContent`] a member originates - a post, an edit, or a
//! deletion - is wrapped in a [`GroupMessage::Application`] that carries an
//! Ed25519 **signature by the original author**, over the content plus a
//! per-author hash-chain header. Anyone who holds the author's pinned
//! public key (i.e. anyone in the group) can verify that signature
//! completely independently of who handed them the bytes. This is what
//! makes relaying safe: **any current member can relay any other member's
//! message to a reconnecting peer, and the recipient verifies authorship
//! against the original author's key, not the relayer's** - the relayer
//! never needs to be trusted with anything beyond "please pass this
//! along". See [`GroupHub::request_catchup`] and the relay cache below for
//! the mechanism, and the integration tests for a worked example of Y
//! relaying X's message to Z.
//!
//! This also directly answers "does X have to be the one to resend when Z
//! comes back online, or can Y do it instead": with signed content, it's
//! always Y (or anyone else online who has it cached) that *should* do it
//! when possible - it doesn't require X specifically to be reachable,
//! which is a real availability win for a full-mesh group where any given
//! member might be offline at any given time.
//!
//! # Tiered permissions
//!
//! Membership isn't flat. Every member has a named tier (e.g. `"owner"`,
//! `"moderator"`, `"member"`), and every tier has a [`Permissions`] bundle
//! along exactly four configurable dimensions: `can_add`, `can_remove`,
//! `can_read`, `can_write`. Tiers and their permission bundles are defined
//! by (and changeable via) signed roster operations, so the *rules of the
//! group* are just as tamper-evident and fork-resistant as its membership
//! list - see [`Roster::apply`].
//!
//! `can_read` is enforced by *exclusion*, not by hiding: [`GroupHub`] only
//! ever sends application content to sessions of members whose current
//! tier grants `can_read`. In a full-mesh model without per-subgroup
//! encryption keys, that's the only way "read" can be a real cryptographic
//! boundary rather than a polite fiction - a member who *does* receive the
//! ciphertext can always decrypt it, since it's just their own pairwise
//! session key.
//!
//! `can_remove` doubles as the moderation permission for deleting *someone
//! else's* message - conceptually "removing something from the group",
//! same as removing a member. Editing someone else's message is never
//! allowed, under any permission - that would be forgery, not moderation,
//! and no tier grants it.
//!
//! # On group "type" being immutable
//!
//! A [`Roster`] is created once, at [`Roster::genesis`], and only its
//! *membership and tier structure* change from then on - there is no
//! operation that converts a group into a 1:1 [`crate::session::Session`]
//! or vice versa, and no code path here branches on live member count.

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};

use crate::error::{ChatError, Result};
use crate::identity::{fingerprint, Identity, PeerId, PeerRegistry};
use crate::session::Session;
use crate::trace::TraceEvent;

/// Stable identifier for a group, fixed forever at creation time (see
/// [`Roster::genesis`]).
pub type GroupId = String;

/// The name of a permission tier (e.g. `"owner"`, `"member"`). Freely
/// chosen per group, not a fixed enum, so different groups can use
/// different tier structures.
pub type TierName = String;

/// The four configurable permission dimensions a tier can grant.
#[derive(Clone, Copy, Debug)]
pub struct Permissions {
    pub can_add: bool,
    pub can_remove: bool,
    pub can_read: bool,
    pub can_write: bool,
}

impl Permissions {
    pub const NONE: Permissions = Permissions {
        can_add: false,
        can_remove: false,
        can_read: false,
        can_write: false,
    };
    /// Read + write, but no membership-management rights - a typical
    /// baseline "member" tier.
    pub const READ_WRITE: Permissions = Permissions {
        can_add: false,
        can_remove: false,
        can_read: true,
        can_write: true,
    };
    /// Every permission - a typical "owner"/founder tier.
    pub const FULL: Permissions = Permissions {
        can_add: true,
        can_remove: true,
        can_read: true,
        can_write: true,
    };

    fn to_byte(self) -> u8 {
        (self.can_add as u8)
            | ((self.can_remove as u8) << 1)
            | ((self.can_read as u8) << 2)
            | ((self.can_write as u8) << 3)
    }
    fn from_byte(b: u8) -> Permissions {
        Permissions {
            can_add: b & 0b0001 != 0,
            can_remove: b & 0b0010 != 0,
            can_read: b & 0b0100 != 0,
            can_write: b & 0b1000 != 0,
        }
    }
}

/// Whether a member is a person or a bot. Fixed when the member is added
/// (there is no op that converts one into the other), so a bot can never be
/// quietly promoted into a "person" and clients can always label it honestly.
///
/// A bot is an ordinary member in every way that matters to the wire (own
/// Ed25519 key, own pairwise sessions, own author chain) EXCEPT governance:
/// * it may only hold tiers that grant neither `can_add` nor `can_remove`
///   (so it can never recruit or remove anyone, or re-tier anyone); and
/// * it has a SPONSOR (the member who added it) and lives only as long as
///   the sponsor is a member: removing or losing the sponsor removes their
///   bots in the same roster step, on every node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberKind {
    Person,
    Bot,
}

/// A member's public key plus their currently-assigned tier.
#[derive(Clone)]
struct MemberInfo {
    key: VerifyingKey,
    tier: TierName,
    kind: MemberKind,
    /// Who added this member as a bot (`None` for people). Used for the
    /// cascade removal described on [`MemberKind`].
    sponsor: Option<PeerId>,
}

/// True if a bundle of permissions is acceptable for a bot: it must not be
/// able to change who is in the group.
fn bot_safe(p: Permissions) -> bool {
    !p.can_add && !p.can_remove
}

/// How a group delivers messages. Fixed at creation (it lives only in the
/// genesis op, which can never be re-applied), so a group can never be
/// silently converted from one kind to another: switching means founding a
/// NEW group and pointing members at it.
///
/// Only the full-mesh kind exists today; the tag space is reserved so a
/// sender-key mode or MLS can be added later without a format change to
/// genesis. Unknown kinds are rejected on decode (fail closed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupKind {
    /// One pairwise session per member pair; each message sent to every
    /// reader individually (this module's current design).
    FullMesh,
}

impl GroupKind {
    fn to_byte(self) -> u8 {
        match self {
            GroupKind::FullMesh => 0,
        }
    }
    fn from_byte(b: u8) -> Result<GroupKind> {
        match b {
            0 => Ok(GroupKind::FullMesh),
            _ => Err(ChatError::MalformedMessage("unknown group kind")),
        }
    }
}

/// Who may serve a message's CONTENT to someone asking for it. Fixed at
/// creation (genesis), like [`GroupKind`]: changing it means a new group.
///
/// Either way, anyone holding a message may tell you THAT it exists: the
/// signed header (author, position, roster version, SHA-256 of the content)
/// proves it without revealing it. See [`GroupMessage::Existence`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RelayPolicy {
    /// Any member who has a message may serve its content (default).
    #[default]
    Open,
    /// Only the AUTHOR serves content. Everyone else who is asked answers
    /// with an existence notice instead. Better for privacy (a message only
    /// ever travels from the author), at the cost that content is
    /// unavailable while the author is offline.
    AuthorOnly,
}

impl RelayPolicy {
    fn to_byte(self) -> u8 {
        match self {
            RelayPolicy::Open => 0,
            RelayPolicy::AuthorOnly => 1,
        }
    }
    fn from_byte(b: u8) -> Result<RelayPolicy> {
        match b {
            0 => Ok(RelayPolicy::Open),
            1 => Ok(RelayPolicy::AuthorOnly),
            _ => Err(ChatError::MalformedMessage("unknown relay policy")),
        }
    }
}

/// What THIS device does with content that reaches it from someone other
/// than its author (a relay). A local choice, not a group rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RelayedContent {
    /// Accept it (it is verified against the author's key either way).
    /// A UI can still warn: see [`GroupHub::relayed_by`].
    #[default]
    Deliver,
    /// Do not accept relayed content: record only that the message exists,
    /// and fetch the content from its author ([`GroupHub::fetch`]).
    ExistenceOnly,
}

/// What a receipt says about a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ReceiptKind {
    /// "This message reached me" (sent automatically, on by default).
    Delivered,
    /// "I read it" (opt-in; only when the app calls [`GroupHub::mark_read`]).
    Read,
}

impl ReceiptKind {
    fn to_byte(self) -> u8 {
        match self {
            ReceiptKind::Delivered => 0,
            ReceiptKind::Read => 1,
        }
    }
    fn from_byte(b: u8) -> Result<ReceiptKind> {
        match b {
            0 => Ok(ReceiptKind::Delivered),
            1 => Ok(ReceiptKind::Read),
            _ => Err(ChatError::MalformedMessage("unknown receipt kind")),
        }
    }
}

/// Which receipts THIS device sends. Receipts tell the author something
/// about you (that you are online, and when you looked), which is why read
/// receipts are off unless you opt in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceiptSettings {
    /// Send a [`ReceiptKind::Delivered`] receipt for each post we accept
    /// (default `true`). Needs a signer: see [`GroupHub::enable_receipts`].
    pub delivery: bool,
    /// Allow [`GroupHub::mark_read`] to send [`ReceiptKind::Read`] receipts
    /// (default `false`).
    pub read: bool,
}

impl Default for ReceiptSettings {
    fn default() -> Self {
        ReceiptSettings {
            delivery: true,
            read: false,
        }
    }
}

/// Signs receipt bytes on our behalf (so the hub never needs to hold the
/// identity key itself; an app may back this with a keychain or HSM).
pub type ReceiptSigner = Arc<dyn Fn(&[u8]) -> [u8; 64] + Send + Sync>;

/// One proposed change to group membership or tier structure. Carries no
/// signature itself - see [`SignedRosterOp`] for the authenticated envelope
/// that actually gets applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RosterOp {
    /// Found a brand new group with this exact initial membership and tier
    /// structure. Only ever valid as the very first operation in a group's
    /// history.
    Genesis {
        kind: GroupKind,
        relay: RelayPolicy,
        tiers: Vec<(TierName, Permissions)>,
        members: Vec<(VerifyingKey, TierName)>,
    },
    /// Add a new member at a given tier. Requires the proposer's current
    /// tier to have `can_add`.
    Add {
        member: VerifyingKey,
        tier: TierName,
    },
    /// Add a BOT at a given tier. Needs `can_add` like [`RosterOp::Add`];
    /// the proposer becomes the bot's sponsor. The tier must be
    /// bot-safe (no `can_add`, no `can_remove`).
    AddBot {
        member: VerifyingKey,
        tier: TierName,
    },
    /// Remove a member. Requires `can_remove`, *unless* the proposer is
    /// removing themselves (leaving is always allowed).
    Remove { target: PeerId },
    /// Move a member to a different (already-defined) tier. Requires both
    /// `can_add` and `can_remove` - promoting/demoting is treated as more
    /// privileged than either alone.
    ChangeTier { target: PeerId, new_tier: TierName },
    /// Define or redefine a tier's permission bundle. Requires both
    /// `can_add` and `can_remove` - this is a governance action that
    /// affects everyone currently assigned to that tier.
    DefineTier {
        name: TierName,
        permissions: Permissions,
    },
}

impl PartialEq for Permissions {
    fn eq(&self, other: &Self) -> bool {
        self.to_byte() == other.to_byte()
    }
}
impl Eq for Permissions {}

impl RosterOp {
    fn encode(&self) -> Vec<u8> {
        match self {
            RosterOp::Genesis {
                kind,
                relay,
                tiers,
                members,
            } => {
                let mut out = vec![0u8];
                out.push(kind.to_byte());
                out.push(relay.to_byte());
                out.extend_from_slice(&(tiers.len() as u16).to_be_bytes());
                for (name, perms) in tiers {
                    let name_bytes = name.as_bytes();
                    out.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
                    out.extend_from_slice(name_bytes);
                    out.push(perms.to_byte());
                }
                out.extend_from_slice(&(members.len() as u16).to_be_bytes());
                for (key, tier) in members {
                    out.extend_from_slice(key.as_bytes());
                    let tier_bytes = tier.as_bytes();
                    out.extend_from_slice(&(tier_bytes.len() as u16).to_be_bytes());
                    out.extend_from_slice(tier_bytes);
                }
                out
            }
            RosterOp::Add { member, tier } => {
                let mut out = vec![1u8];
                out.extend_from_slice(member.as_bytes());
                let tier_bytes = tier.as_bytes();
                out.extend_from_slice(&(tier_bytes.len() as u16).to_be_bytes());
                out.extend_from_slice(tier_bytes);
                out
            }
            RosterOp::AddBot { member, tier } => {
                let mut out = vec![5u8];
                out.extend_from_slice(member.as_bytes());
                let tier_bytes = tier.as_bytes();
                out.extend_from_slice(&(tier_bytes.len() as u16).to_be_bytes());
                out.extend_from_slice(tier_bytes);
                out
            }
            RosterOp::Remove { target } => {
                let mut out = vec![2u8];
                let target_bytes = target.as_bytes();
                out.extend_from_slice(&(target_bytes.len() as u16).to_be_bytes());
                out.extend_from_slice(target_bytes);
                out
            }
            RosterOp::ChangeTier { target, new_tier } => {
                let mut out = vec![3u8];
                let target_bytes = target.as_bytes();
                out.extend_from_slice(&(target_bytes.len() as u16).to_be_bytes());
                out.extend_from_slice(target_bytes);
                let tier_bytes = new_tier.as_bytes();
                out.extend_from_slice(&(tier_bytes.len() as u16).to_be_bytes());
                out.extend_from_slice(tier_bytes);
                out
            }
            RosterOp::DefineTier { name, permissions } => {
                let mut out = vec![4u8];
                let name_bytes = name.as_bytes();
                out.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
                out.extend_from_slice(name_bytes);
                out.push(permissions.to_byte());
                out
            }
        }
    }

    fn decode(bytes: &[u8]) -> Result<RosterOp> {
        let mut cursor = bytes;
        let tag = take(&mut cursor, 1)?[0];
        match tag {
            0 => {
                let kind = GroupKind::from_byte(take(&mut cursor, 1)?[0])?;
                let relay = RelayPolicy::from_byte(take(&mut cursor, 1)?[0])?;
                let tier_count = read_u16(&mut cursor)? as usize;
                let mut tiers = Vec::with_capacity(tier_count);
                for _ in 0..tier_count {
                    let name_len = read_u16(&mut cursor)? as usize;
                    let name = String::from_utf8(take(&mut cursor, name_len)?)
                        .map_err(|_| ChatError::MalformedMessage("bad tier name"))?;
                    let perm_byte = take(&mut cursor, 1)?[0];
                    tiers.push((name, Permissions::from_byte(perm_byte)));
                }
                let member_count = read_u16(&mut cursor)? as usize;
                let mut members = Vec::with_capacity(member_count);
                for _ in 0..member_count {
                    let key_bytes: [u8; 32] = take(&mut cursor, 32)?.try_into().unwrap();
                    let key = VerifyingKey::from_bytes(&key_bytes)
                        .map_err(|_| ChatError::InvalidPublicKey)?;
                    let tier_len = read_u16(&mut cursor)? as usize;
                    let tier = String::from_utf8(take(&mut cursor, tier_len)?)
                        .map_err(|_| ChatError::MalformedMessage("bad member tier"))?;
                    members.push((key, tier));
                }
                Ok(RosterOp::Genesis {
                    kind,
                    relay,
                    tiers,
                    members,
                })
            }
            1 => {
                let key_bytes: [u8; 32] = take(&mut cursor, 32)?.try_into().unwrap();
                let member = VerifyingKey::from_bytes(&key_bytes)
                    .map_err(|_| ChatError::InvalidPublicKey)?;
                let tier_len = read_u16(&mut cursor)? as usize;
                let tier = String::from_utf8(take(&mut cursor, tier_len)?)
                    .map_err(|_| ChatError::MalformedMessage("bad tier"))?;
                Ok(RosterOp::Add { member, tier })
            }
            5 => {
                let key_bytes: [u8; 32] = take(&mut cursor, 32)?.try_into().unwrap();
                let member = VerifyingKey::from_bytes(&key_bytes)
                    .map_err(|_| ChatError::InvalidPublicKey)?;
                let tier_len = read_u16(&mut cursor)? as usize;
                let tier = String::from_utf8(take(&mut cursor, tier_len)?)
                    .map_err(|_| ChatError::MalformedMessage("bad tier"))?;
                Ok(RosterOp::AddBot { member, tier })
            }
            2 => {
                let target_len = read_u16(&mut cursor)? as usize;
                let target = String::from_utf8(take(&mut cursor, target_len)?)
                    .map_err(|_| ChatError::MalformedMessage("bad target"))?;
                Ok(RosterOp::Remove { target })
            }
            3 => {
                let target_len = read_u16(&mut cursor)? as usize;
                let target = String::from_utf8(take(&mut cursor, target_len)?)
                    .map_err(|_| ChatError::MalformedMessage("bad target"))?;
                let tier_len = read_u16(&mut cursor)? as usize;
                let new_tier = String::from_utf8(take(&mut cursor, tier_len)?)
                    .map_err(|_| ChatError::MalformedMessage("bad tier"))?;
                Ok(RosterOp::ChangeTier { target, new_tier })
            }
            4 => {
                let name_len = read_u16(&mut cursor)? as usize;
                let name = String::from_utf8(take(&mut cursor, name_len)?)
                    .map_err(|_| ChatError::MalformedMessage("bad tier name"))?;
                let perm_byte = take(&mut cursor, 1)?[0];
                Ok(RosterOp::DefineTier {
                    name,
                    permissions: Permissions::from_byte(perm_byte),
                })
            }
            _ => Err(ChatError::MalformedMessage("unknown roster op tag")),
        }
    }
}

/// A [`RosterOp`], signed by its proposer, positioned in the group's
/// history via `version` and `prev_hash`.
#[derive(Debug, Clone)]
pub struct SignedRosterOp {
    pub group_id: GroupId,
    pub version: u64,
    pub prev_hash: [u8; 32],
    pub op: RosterOp,
    pub proposer: PeerId,
    pub signature: Signature,
}

impl SignedRosterOp {
    fn signing_bytes(group_id: &str, version: u64, prev_hash: &[u8; 32], op: &RosterOp) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"symbolon/group/roster-op/v1");
        out.extend_from_slice(group_id.as_bytes());
        out.extend_from_slice(&version.to_be_bytes());
        out.extend_from_slice(prev_hash);
        out.extend_from_slice(&op.encode());
        out
    }
}

/// The group's membership, tier structure, and the signed, hash-chained
/// history that produced it.
pub struct Roster {
    pub group_id: GroupId,
    kind: GroupKind,
    relay: RelayPolicy,
    members: HashMap<PeerId, MemberInfo>,
    tiers: HashMap<TierName, Permissions>,
    version: u64,
    tip_hash: [u8; 32],
    /// `perm_history[v]` = every member's effective permissions as of roster
    /// version `v` (index 0 = genesis). Lets a receiver judge a message by
    /// the permissions its author held when they SENT it (the version they
    /// signed), not by whatever the roster says later. Grows by one small
    /// map per roster op.
    perm_history: Vec<HashMap<PeerId, Permissions>>,
    /// Keys of everyone who has EVER been a member, so a removed member's
    /// earlier, legitimately-signed messages remain verifiable.
    known_keys: HashMap<PeerId, VerifyingKey>,
    /// Every op applied after genesis, in order (`ops[i]` is version `i+1`).
    /// Kept so ANY member can bring a newcomer (or a member who was offline)
    /// up to date by replaying the ops; they are self-verifying (signed and
    /// hash-chained), so who relays them does not matter.
    ops: Vec<SignedRosterOp>,
}

impl Roster {
    /// Found a new group with an explicit tier structure and initial
    /// membership. `creator` signs the genesis operation, and must appear
    /// in `members`.
    pub fn genesis(
        creator: &Identity,
        tiers: Vec<(TierName, Permissions)>,
        members: Vec<(VerifyingKey, TierName)>,
    ) -> (Roster, SignedRosterOp) {
        Self::genesis_with_kind(creator, GroupKind::FullMesh, tiers, members)
    }

    /// Like [`Roster::genesis`] with an explicit, permanent [`GroupKind`].
    pub fn genesis_with_kind(
        creator: &Identity,
        kind: GroupKind,
        tiers: Vec<(TierName, Permissions)>,
        members: Vec<(VerifyingKey, TierName)>,
    ) -> (Roster, SignedRosterOp) {
        Self::genesis_with_policy(creator, kind, RelayPolicy::Open, tiers, members)
    }

    /// Like [`Roster::genesis_with_kind`] with an explicit, permanent
    /// [`RelayPolicy`] as well.
    pub fn genesis_with_policy(
        creator: &Identity,
        kind: GroupKind,
        relay: RelayPolicy,
        tiers: Vec<(TierName, Permissions)>,
        members: Vec<(VerifyingKey, TierName)>,
    ) -> (Roster, SignedRosterOp) {
        let mut hasher = Sha256::new();
        hasher.update(b"symbolon/group/id/v1");
        hasher.update([kind.to_byte(), relay.to_byte()]);
        hasher.update(creator.public_key().as_bytes());
        let mut fingerprints: Vec<PeerId> = members.iter().map(|(k, _)| fingerprint(k)).collect();
        fingerprints.sort();
        for fp in &fingerprints {
            hasher.update(fp.as_bytes());
        }
        let group_id: GroupId = hex_encode(&hasher.finalize());

        let op = RosterOp::Genesis {
            kind,
            relay,
            tiers: tiers.clone(),
            members: members.clone(),
        };
        let prev_hash = [0u8; 32];
        let signing_bytes = SignedRosterOp::signing_bytes(&group_id, 0, &prev_hash, &op);
        let signature = creator.sign(&signing_bytes);

        let signed = SignedRosterOp {
            group_id: group_id.clone(),
            version: 0,
            prev_hash,
            op,
            proposer: creator.fingerprint(),
            signature,
        };

        let mut roster = Roster::empty(group_id, kind, relay);
        for (name, perms) in tiers {
            roster.tiers.insert(name, perms);
        }
        for (key, tier) in members {
            roster.known_keys.insert(fingerprint(&key), key);
            roster.members.insert(
                fingerprint(&key),
                MemberInfo {
                    key,
                    tier,
                    kind: MemberKind::Person,
                    sponsor: None,
                },
            );
        }
        roster.tip_hash = tip_after(&prev_hash, &signed);
        roster.record_snapshot();

        (roster, signed)
    }

    /// Convenience genesis for the common two-tier case: the creator gets
    /// a `"owner"` tier with [`Permissions::FULL`], everyone else gets a
    /// `"member"` tier with [`Permissions::READ_WRITE`]. Equivalent to
    /// calling [`Roster::genesis`] directly with that tier structure - just
    /// saves callers from writing it out every time.
    pub fn genesis_default(
        creator: &Identity,
        other_members: Vec<VerifyingKey>,
    ) -> (Roster, SignedRosterOp) {
        let tiers = vec![
            ("owner".to_string(), Permissions::FULL),
            ("member".to_string(), Permissions::READ_WRITE),
        ];
        let mut members = vec![(creator.public_key(), "owner".to_string())];
        for m in other_members {
            members.push((m, "member".to_string()));
        }
        Roster::genesis(creator, tiers, members)
    }

    fn empty(group_id: GroupId, kind: GroupKind, relay: RelayPolicy) -> Roster {
        Roster {
            group_id,
            kind,
            relay,
            members: HashMap::new(),
            tiers: HashMap::new(),
            version: 0,
            tip_hash: [0u8; 32],
            perm_history: Vec::new(),
            known_keys: HashMap::new(),
            ops: Vec::new(),
        }
    }

    /// Record every member's effective permissions as of the current
    /// version. Called once per version (genesis, then after each applied op).
    fn record_snapshot(&mut self) {
        let snap: HashMap<PeerId, Permissions> = self
            .members
            .iter()
            .map(|(id, m)| {
                (
                    id.clone(),
                    self.tiers
                        .get(&m.tier)
                        .copied()
                        .unwrap_or(Permissions::NONE),
                )
            })
            .collect();
        debug_assert_eq!(self.perm_history.len() as u64, self.version);
        self.perm_history.push(snap);
    }

    /// Reconstruct a roster purely from a trusted genesis op.
    pub fn from_genesis(signed: &SignedRosterOp) -> Result<Roster> {
        let RosterOp::Genesis {
            kind,
            relay,
            tiers,
            members,
        } = &signed.op
        else {
            return Err(ChatError::MalformedMessage("expected a genesis roster op"));
        };
        if signed.version != 0 || signed.prev_hash != [0u8; 32] {
            return Err(ChatError::MalformedMessage(
                "genesis op must be version 0 with a zero prev_hash",
            ));
        }
        let creator_key = members
            .iter()
            .find(|(m, _)| fingerprint(m) == signed.proposer)
            .map(|(m, _)| m)
            .ok_or(ChatError::UnauthorizedRosterOp)?;
        let signing_bytes =
            SignedRosterOp::signing_bytes(&signed.group_id, 0, &signed.prev_hash, &signed.op);
        PeerRegistry::verify_signature(creator_key, &signing_bytes, &signed.signature)
            .map_err(|_| ChatError::RosterSignatureInvalid)?;

        let mut roster = Roster::empty(signed.group_id.clone(), *kind, *relay);
        for (name, perms) in tiers {
            roster.tiers.insert(name.clone(), *perms);
        }
        for (key, tier) in members {
            roster.known_keys.insert(fingerprint(key), *key);
            roster.members.insert(
                fingerprint(key),
                MemberInfo {
                    key: *key,
                    tier: tier.clone(),
                    kind: MemberKind::Person,
                    sponsor: None,
                },
            );
        }
        roster.tip_hash = tip_after(&[0u8; 32], signed);
        roster.record_snapshot();
        Ok(roster)
    }

    /// Apply a signed roster operation. Fails closed on: signature failure,
    /// history mismatch (stale or forked), unknown proposer, or the
    /// proposer's tier not granting the permission the operation requires.
    pub fn apply(&mut self, signed: &SignedRosterOp) -> Result<()> {
        if signed.group_id != self.group_id {
            return Err(ChatError::MalformedMessage(
                "roster op is for a different group",
            ));
        }
        if signed.version != self.version + 1 || signed.prev_hash != self.tip_hash {
            return Err(ChatError::RosterHistoryMismatch);
        }
        let proposer_info = self
            .members
            .get(&signed.proposer)
            .ok_or(ChatError::UnauthorizedRosterOp)?;
        let proposer_key = proposer_info.key;
        let proposer_perms = self
            .tiers
            .get(&proposer_info.tier)
            .copied()
            .unwrap_or(Permissions::NONE);

        let signing_bytes = SignedRosterOp::signing_bytes(
            &signed.group_id,
            signed.version,
            &signed.prev_hash,
            &signed.op,
        );
        PeerRegistry::verify_signature(&proposer_key, &signing_bytes, &signed.signature)
            .map_err(|_| ChatError::RosterSignatureInvalid)?;

        match &signed.op {
            RosterOp::Genesis { .. } => {
                return Err(ChatError::MalformedMessage(
                    "genesis op can't be applied twice",
                ))
            }
            RosterOp::Add { member, tier } => {
                if !proposer_perms.can_add {
                    return Err(ChatError::PermissionDenied);
                }
                if !self.tiers.contains_key(tier) {
                    return Err(ChatError::MalformedMessage(
                        "cannot add a member to an undefined tier",
                    ));
                }
                // Re-adding a CURRENT member would silently overwrite them, which
                // for a bot would turn it into a "person" (kind is permanent).
                if self.members.contains_key(&fingerprint(member)) {
                    return Err(ChatError::MalformedMessage("already a member"));
                }
                self.known_keys.insert(fingerprint(member), *member);
                self.members.insert(
                    fingerprint(member),
                    MemberInfo {
                        key: *member,
                        tier: tier.clone(),
                        kind: MemberKind::Person,
                        sponsor: None,
                    },
                );
            }
            RosterOp::AddBot { member, tier } => {
                if !proposer_perms.can_add {
                    return Err(ChatError::PermissionDenied);
                }
                let perms = self
                    .tiers
                    .get(tier)
                    .copied()
                    .ok_or(ChatError::MalformedMessage(
                        "cannot add a bot to an undefined tier",
                    ))?;
                if !bot_safe(perms) {
                    return Err(ChatError::PermissionDenied);
                }
                if self.members.contains_key(&fingerprint(member)) {
                    return Err(ChatError::MalformedMessage("already a member"));
                }
                self.known_keys.insert(fingerprint(member), *member);
                self.members.insert(
                    fingerprint(member),
                    MemberInfo {
                        key: *member,
                        tier: tier.clone(),
                        kind: MemberKind::Bot,
                        sponsor: Some(signed.proposer.clone()),
                    },
                );
            }
            RosterOp::Remove { target } => {
                let self_removal = *target == signed.proposer;
                if !self_removal && !proposer_perms.can_remove {
                    return Err(ChatError::PermissionDenied);
                }
                self.members.remove(target);
                // A bot lives only as long as its sponsor: drop theirs in the
                // same step. Deterministic, so every node agrees.
                self.members
                    .retain(|_, m| m.sponsor.as_deref() != Some(target.as_str()));
            }
            RosterOp::ChangeTier { target, new_tier } => {
                if !(proposer_perms.can_add && proposer_perms.can_remove) {
                    return Err(ChatError::PermissionDenied);
                }
                if !self.tiers.contains_key(new_tier) {
                    return Err(ChatError::MalformedMessage(
                        "cannot move a member to an undefined tier",
                    ));
                }
                let new_perms = self
                    .tiers
                    .get(new_tier)
                    .copied()
                    .unwrap_or(Permissions::NONE);
                let member = self
                    .members
                    .get_mut(target)
                    .ok_or(ChatError::MalformedMessage(
                        "change-tier target is not a member",
                    ))?;
                // A bot may never be given a tier that can change membership.
                if member.kind == MemberKind::Bot && !bot_safe(new_perms) {
                    return Err(ChatError::PermissionDenied);
                }
                member.tier = new_tier.clone();
            }
            RosterOp::DefineTier { name, permissions } => {
                if !(proposer_perms.can_add && proposer_perms.can_remove) {
                    return Err(ChatError::PermissionDenied);
                }
                // Redefining a tier must not hand membership powers to a bot
                // that already sits in it.
                if !bot_safe(*permissions)
                    && self
                        .members
                        .values()
                        .any(|m| m.kind == MemberKind::Bot && m.tier == *name)
                {
                    return Err(ChatError::PermissionDenied);
                }
                self.tiers.insert(name.clone(), *permissions);
            }
        }
        self.version += 1;
        self.tip_hash = tip_after(&signed.prev_hash, signed);
        self.ops.push(signed.clone());
        self.record_snapshot();
        Ok(())
    }

    fn propose(&self, proposer: &Identity, op: RosterOp) -> Result<SignedRosterOp> {
        let version = self.version + 1;
        let signing_bytes =
            SignedRosterOp::signing_bytes(&self.group_id, version, &self.tip_hash, &op);
        let signature = proposer.sign(&signing_bytes);
        Ok(SignedRosterOp {
            group_id: self.group_id.clone(),
            version,
            prev_hash: self.tip_hash,
            op,
            proposer: proposer.fingerprint(),
            signature,
        })
    }

    /// Build (but don't apply) a signed op proposing to add `member` at
    /// `tier`. `proposer` must currently have `can_add` - checked here so
    /// mistakes are caught immediately, and independently re-checked by
    /// every recipient's [`Roster::apply`].
    pub fn propose_add(
        &self,
        proposer: &Identity,
        member: VerifyingKey,
        tier: TierName,
    ) -> Result<SignedRosterOp> {
        if !self.permissions_of(&proposer.fingerprint()).can_add {
            return Err(ChatError::PermissionDenied);
        }
        self.propose(proposer, RosterOp::Add { member, tier })
    }

    /// Build (but don't apply) a signed op adding `member` as a BOT at
    /// `tier`. Checked here for fast feedback and re-checked by every
    /// recipient's [`Roster::apply`]: the proposer needs `can_add`, and the
    /// tier must exist and grant neither `can_add` nor `can_remove`.
    pub fn propose_add_bot(
        &self,
        proposer: &Identity,
        member: VerifyingKey,
        tier: TierName,
    ) -> Result<SignedRosterOp> {
        if !self.permissions_of(&proposer.fingerprint()).can_add {
            return Err(ChatError::PermissionDenied);
        }
        match self.tiers.get(&tier) {
            Some(p) if bot_safe(*p) => {}
            Some(_) => return Err(ChatError::PermissionDenied),
            None => {
                return Err(ChatError::MalformedMessage(
                    "cannot add a bot to an undefined tier",
                ))
            }
        }
        self.propose(proposer, RosterOp::AddBot { member, tier })
    }

    /// Build (but don't apply) a signed op proposing to remove `target`.
    pub fn propose_remove(&self, proposer: &Identity, target: PeerId) -> Result<SignedRosterOp> {
        let self_removal = target == proposer.fingerprint();
        if !self_removal && !self.permissions_of(&proposer.fingerprint()).can_remove {
            return Err(ChatError::PermissionDenied);
        }
        self.propose(proposer, RosterOp::Remove { target })
    }

    /// Build (but don't apply) a signed op moving `target` to `new_tier`.
    pub fn propose_change_tier(
        &self,
        proposer: &Identity,
        target: PeerId,
        new_tier: TierName,
    ) -> Result<SignedRosterOp> {
        let perms = self.permissions_of(&proposer.fingerprint());
        if !(perms.can_add && perms.can_remove) {
            return Err(ChatError::PermissionDenied);
        }
        self.propose(proposer, RosterOp::ChangeTier { target, new_tier })
    }

    /// Build (but don't apply) a signed op defining/redefining a tier.
    pub fn propose_define_tier(
        &self,
        proposer: &Identity,
        name: TierName,
        permissions: Permissions,
    ) -> Result<SignedRosterOp> {
        let perms = self.permissions_of(&proposer.fingerprint());
        if !(perms.can_add && perms.can_remove) {
            return Err(ChatError::PermissionDenied);
        }
        self.propose(proposer, RosterOp::DefineTier { name, permissions })
    }

    pub fn is_member(&self, id: &PeerId) -> bool {
        self.members.contains_key(id)
    }

    pub fn member_ids(&self) -> Vec<PeerId> {
        self.members.keys().cloned().collect()
    }

    pub fn tier_of(&self, id: &PeerId) -> Option<TierName> {
        self.members.get(id).map(|m| m.tier.clone())
    }

    /// Whether a current member is a person or a bot (`None` if not a member).
    pub fn kind_of(&self, id: &PeerId) -> Option<MemberKind> {
        self.members.get(id).map(|m| m.kind)
    }

    /// The member who added `id` as a bot (`None` for people / non-members).
    pub fn sponsor_of(&self, id: &PeerId) -> Option<PeerId> {
        self.members.get(id).and_then(|m| m.sponsor.clone())
    }

    /// The effective permissions for a given member right now. Members not
    /// in the roster (or - defensively - assigned to a since-undefined
    /// tier) get [`Permissions::NONE`]: fail closed, never fail open.
    pub fn permissions_of(&self, id: &PeerId) -> Permissions {
        self.members
            .get(id)
            .and_then(|m| self.tiers.get(&m.tier))
            .copied()
            .unwrap_or(Permissions::NONE)
    }

    pub fn version(&self) -> u64 {
        self.version
    }

    /// Public keys of all current members (what a transport layer needs to
    /// pin so it will accept exactly the members' connections).
    pub fn member_keys(&self) -> Vec<VerifyingKey> {
        self.members.values().map(|m| m.key).collect()
    }

    /// The ops that take a roster from `have_version` to the current one,
    /// oldest first (empty if `have_version` is current or ahead).
    pub fn ops_after(&self, have_version: u64) -> Vec<SignedRosterOp> {
        self.ops
            .iter()
            .skip(usize::try_from(have_version).unwrap_or(usize::MAX))
            .cloned()
            .collect()
    }

    /// The group's (permanent) kind.
    pub fn kind(&self) -> GroupKind {
        self.kind
    }

    /// The group's (permanent) relay policy.
    pub fn relay_policy(&self) -> RelayPolicy {
        self.relay
    }

    /// What `id` was allowed to do as of roster `version`: `None` if we have
    /// not reached that version yet (we cannot judge it), otherwise their
    /// permissions then ([`Permissions::NONE`] if they were not a member).
    pub fn permissions_at(&self, version: u64, id: &PeerId) -> Option<Permissions> {
        let snap = self.perm_history.get(usize::try_from(version).ok()?)?;
        Some(snap.get(id).copied().unwrap_or(Permissions::NONE))
    }

    /// The key of anyone who has ever been a member (current or removed).
    pub fn key_ever(&self, id: &PeerId) -> Option<VerifyingKey> {
        self.known_keys.get(id).copied()
    }
}

fn tip_after(prev_hash: &[u8; 32], signed: &SignedRosterOp) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(prev_hash);
    hasher.update(signed.group_id.as_bytes());
    hasher.update(signed.version.to_be_bytes());
    hasher.update(signed.op.encode());
    hasher.update(signed.proposer.as_bytes());
    hasher.finalize().into()
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Per-sender hash chain state, maintained by every recipient for every
/// other member, over the *encoded content* of their messages (posts,
/// edits, and deletes all share one chain per author). This is what makes
/// equivocation detectable: two recipients who each faithfully chain an
/// author's messages only agree on the resulting tip hash if they were
/// shown the exact same sequence of content.
#[derive(Clone)]
pub struct SenderChainState {
    next_seq: u64,
    tip_hash: [u8; 32],
    /// Highest roster version this author has claimed so far. An author's
    /// claimed version may never go DOWN along their chain, which limits
    /// how far back they can "backdate" a message to a time they still had
    /// permission.
    last_roster_version: u64,
}

impl Default for SenderChainState {
    fn default() -> Self {
        SenderChainState {
            next_seq: 1,
            tip_hash: [0u8; 32],
            last_roster_version: 0,
        }
    }
}

impl SenderChainState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Check that a message sits exactly next in its author's chain and
    /// advance. The chain hashes the signed HEADER (which commits to the
    /// content only by hash), so a recipient can extend the chain from a
    /// header alone, without holding the content.
    pub fn verify_and_advance(
        &mut self,
        seq: u64,
        claimed_prev_hash: [u8; 32],
        roster_version: u64,
        header_bytes: &[u8],
    ) -> Result<()> {
        if seq != self.next_seq
            || claimed_prev_hash != self.tip_hash
            || roster_version < self.last_roster_version
        {
            return Err(ChatError::SenderChainBroken);
        }
        self.last_roster_version = roster_version;
        let mut hasher = Sha256::new();
        hasher.update(self.tip_hash);
        hasher.update(header_bytes);
        self.tip_hash = hasher.finalize().into();
        self.next_seq += 1;
        Ok(())
    }

    pub fn tip_hash(&self) -> [u8; 32] {
        self.tip_hash
    }

    /// The next position this chain expects (everything below it is
    /// already accounted for, whether as content or as a notice).
    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }
}

/// The sending side of the same chain.
#[derive(Clone, Default)]
pub struct OwnChainState {
    next_seq: u64,
    tip_hash: [u8; 32],
}

impl OwnChainState {
    pub fn new() -> Self {
        OwnChainState {
            next_seq: 1,
            tip_hash: [0u8; 32],
        }
    }

    pub fn next_header(
        &mut self,
        sender: &str,
        roster_version: u64,
        content_bytes: &[u8],
    ) -> (u64, [u8; 32]) {
        let seq = self.next_seq;
        let prev_hash = self.tip_hash;
        let header =
            GroupMessage::header_bytes(sender, seq, &prev_hash, roster_version, content_bytes);
        let mut hasher = Sha256::new();
        hasher.update(self.tip_hash);
        hasher.update(&header);
        self.tip_hash = hasher.finalize().into();
        self.next_seq += 1;
        (seq, prev_hash)
    }
}

/// What a member's signed message actually says: a new post, an edit of
/// one of their own earlier posts, or a deletion (of their own post, or -
/// with `can_remove` - someone else's).
#[derive(Debug, Clone, PartialEq)]
pub enum GroupContent {
    Post {
        payload: Vec<u8>,
    },
    Edit {
        target_seq: u64,
        new_payload: Vec<u8>,
    },
    Delete {
        target_sender: PeerId,
        target_seq: u64,
    },
}

impl GroupContent {
    fn encode(&self) -> Vec<u8> {
        match self {
            GroupContent::Post { payload } => {
                let mut out = vec![0u8];
                out.extend_from_slice(payload);
                out
            }
            GroupContent::Edit {
                target_seq,
                new_payload,
            } => {
                let mut out = vec![1u8];
                out.extend_from_slice(&target_seq.to_be_bytes());
                out.extend_from_slice(new_payload);
                out
            }
            GroupContent::Delete {
                target_sender,
                target_seq,
            } => {
                let mut out = vec![2u8];
                let bytes = target_sender.as_bytes();
                out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
                out.extend_from_slice(bytes);
                out.extend_from_slice(&target_seq.to_be_bytes());
                out
            }
        }
    }

    fn decode(bytes: &[u8]) -> Result<GroupContent> {
        let mut cursor = bytes;
        let tag = take(&mut cursor, 1)?[0];
        match tag {
            0 => Ok(GroupContent::Post {
                payload: cursor.to_vec(),
            }),
            1 => {
                let target_seq = read_u64(&mut cursor)?;
                Ok(GroupContent::Edit {
                    target_seq,
                    new_payload: cursor.to_vec(),
                })
            }
            2 => {
                let len = read_u16(&mut cursor)? as usize;
                let target_sender = String::from_utf8(take(&mut cursor, len)?)
                    .map_err(|_| ChatError::MalformedMessage("bad target sender"))?;
                let target_seq = read_u64(&mut cursor)?;
                Ok(GroupContent::Delete {
                    target_sender,
                    target_seq,
                })
            }
            _ => Err(ChatError::MalformedMessage("unknown group content tag")),
        }
    }
}

/// Wire encoding for what travels over each pairwise [`Session`].
#[derive(Debug, Clone, PartialEq)]
pub enum GroupMessage {
    /// A signed message from `sender` (the *original author* - not
    /// necessarily whoever delivered these bytes to us, since relaying is
    /// supported - see module docs).
    Application {
        sender: PeerId,
        seq: u64,
        prev_hash: [u8; 32],
        roster_version: u64,
        content: GroupContent,
        signature: [u8; 64],
    },
    Roster(RosterOpWire),
    /// "Please resend anything you have cached from `sender` after
    /// `after_seq`." Broadcast by anyone who's just (re)connected and wants
    /// to catch up - answerable by *any* member who has it cached, not just
    /// `sender` themselves.
    RelayRequest {
        sender: PeerId,
        after_seq: u64,
    },
    /// "I am at roster version `have_version`; send me every roster op after
    /// it." Sent automatically when a connection is attached, which is how a
    /// member added AFTER the group was created (who only holds the genesis)
    /// learns the full membership, and how a member who was offline for a
    /// while catches up. Any member can answer; the ops verify themselves.
    RosterSyncRequest {
        have_version: u64,
    },
    /// "This message exists" WITHOUT its content: an [`GroupMessage::Application`]
    /// with the content replaced by its SHA-256. The author's signature
    /// covers exactly this header, so the notice is verifiable by anyone and
    /// advances the author's hash chain just like the full message. Sent when
    /// the group's [`RelayPolicy`] stops a non-author serving the content.
    Existence {
        sender: PeerId,
        seq: u64,
        prev_hash: [u8; 32],
        roster_version: u64,
        content_hash: [u8; 32],
        signature: [u8; 64],
    },
    /// "I now hold `sender`'s message number `seq`." A few bytes, sent after
    /// we ACCEPT a message to the other members who may read it, so that a
    /// member with no direct link to the author learns of it at once and can
    /// ask for it (a [`GroupMessage::RelayRequest`] to the announcer; the
    /// normal relay policy then decides what is served).
    ///
    /// Privacy: it names only this group's own author and seq, travels only
    /// over sessions attached to THIS group to members who currently have
    /// `can_read`, and says nothing about any other group, any 1:1 session
    /// or who is connected to whom. See [`GroupHub::announce_have`].
    Have {
        sender: PeerId,
        seq: u64,
    },
    /// "Send me message `seq` from `sender`" (one message, unlike
    /// [`GroupMessage::RelayRequest`], which asks for everything after a
    /// position). Ask the author first; see [`GroupHub::fetch`].
    FetchRequest {
        sender: PeerId,
        seq: u64,
    },
    /// A signed acknowledgement from `receiver` about `author`'s message
    /// `seq`. It names the content by hash, so it proves the receiver saw
    /// THAT content, and anyone can verify it. Receipts are not part of any
    /// author chain (they have no position of their own).
    Receipt {
        author: PeerId,
        seq: u64,
        content_hash: [u8; 32],
        kind: ReceiptKind,
        receiver: PeerId,
        signature: [u8; 64],
    },
}

/// Flattened, encodable form of [`SignedRosterOp`].
#[derive(Debug, Clone, PartialEq)]
pub struct RosterOpWire {
    pub group_id: GroupId,
    pub version: u64,
    pub prev_hash: [u8; 32],
    pub op_bytes: Vec<u8>,
    pub proposer: PeerId,
    pub signature_bytes: [u8; 64],
}

impl From<&SignedRosterOp> for RosterOpWire {
    fn from(s: &SignedRosterOp) -> Self {
        RosterOpWire {
            group_id: s.group_id.clone(),
            version: s.version,
            prev_hash: s.prev_hash,
            op_bytes: s.op.encode(),
            proposer: s.proposer.clone(),
            signature_bytes: s.signature.to_bytes(),
        }
    }
}

impl RosterOpWire {
    pub fn to_signed(&self) -> Result<SignedRosterOp> {
        let op = RosterOp::decode(&self.op_bytes)?;
        let signature = Signature::from_slice(&self.signature_bytes)
            .map_err(|_| ChatError::MalformedMessage("bad roster signature encoding"))?;
        Ok(SignedRosterOp {
            group_id: self.group_id.clone(),
            version: self.version,
            prev_hash: self.prev_hash,
            op,
            proposer: self.proposer.clone(),
            signature,
        })
    }
}

/// Upper bound on messages parked while waiting for a missing roster op (a
/// peer can otherwise make us hold unbounded data by claiming a far-future version).
const MAX_DEFERRED: usize = 1000;

const TAG_APPLICATION: u8 = 0x10;
const TAG_ROSTER: u8 = 0x11;
const TAG_RELAY_REQUEST: u8 = 0x12;
const TAG_ROSTER_SYNC_REQUEST: u8 = 0x13;
const TAG_EXISTENCE: u8 = 0x14;
const TAG_FETCH_REQUEST: u8 = 0x15;
const TAG_RECEIPT: u8 = 0x16;
const TAG_HAVE: u8 = 0x17;

impl GroupMessage {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            GroupMessage::Application {
                sender,
                seq,
                prev_hash,
                roster_version,
                content,
                signature,
            } => {
                let mut out = vec![TAG_APPLICATION];
                let sender_bytes = sender.as_bytes();
                out.extend_from_slice(&(sender_bytes.len() as u16).to_be_bytes());
                out.extend_from_slice(sender_bytes);
                out.extend_from_slice(&seq.to_be_bytes());
                out.extend_from_slice(prev_hash);
                out.extend_from_slice(&roster_version.to_be_bytes());
                let content_bytes = content.encode();
                out.extend_from_slice(&(content_bytes.len() as u32).to_be_bytes());
                out.extend_from_slice(&content_bytes);
                out.extend_from_slice(signature);
                out
            }
            GroupMessage::Roster(wire) => {
                let mut out = vec![TAG_ROSTER];
                let gid_bytes = wire.group_id.as_bytes();
                out.extend_from_slice(&(gid_bytes.len() as u16).to_be_bytes());
                out.extend_from_slice(gid_bytes);
                out.extend_from_slice(&wire.version.to_be_bytes());
                out.extend_from_slice(&wire.prev_hash);
                out.extend_from_slice(&(wire.op_bytes.len() as u32).to_be_bytes());
                out.extend_from_slice(&wire.op_bytes);
                let proposer_bytes = wire.proposer.as_bytes();
                out.extend_from_slice(&(proposer_bytes.len() as u16).to_be_bytes());
                out.extend_from_slice(proposer_bytes);
                out.extend_from_slice(&wire.signature_bytes);
                out
            }
            GroupMessage::RosterSyncRequest { have_version } => {
                let mut out = vec![TAG_ROSTER_SYNC_REQUEST];
                out.extend_from_slice(&have_version.to_be_bytes());
                out
            }
            GroupMessage::Existence {
                sender,
                seq,
                prev_hash,
                roster_version,
                content_hash,
                signature,
            } => {
                let mut out = vec![TAG_EXISTENCE];
                out.extend_from_slice(&(sender.len() as u16).to_be_bytes());
                out.extend_from_slice(sender.as_bytes());
                out.extend_from_slice(&seq.to_be_bytes());
                out.extend_from_slice(prev_hash);
                out.extend_from_slice(&roster_version.to_be_bytes());
                out.extend_from_slice(content_hash);
                out.extend_from_slice(signature);
                out
            }
            GroupMessage::Receipt {
                author,
                seq,
                content_hash,
                kind,
                receiver,
                signature,
            } => {
                let mut out = vec![TAG_RECEIPT];
                out.extend_from_slice(&(author.len() as u16).to_be_bytes());
                out.extend_from_slice(author.as_bytes());
                out.extend_from_slice(&seq.to_be_bytes());
                out.extend_from_slice(content_hash);
                out.push(kind.to_byte());
                out.extend_from_slice(&(receiver.len() as u16).to_be_bytes());
                out.extend_from_slice(receiver.as_bytes());
                out.extend_from_slice(signature);
                out
            }
            GroupMessage::FetchRequest { sender, seq } => {
                let mut out = vec![TAG_FETCH_REQUEST];
                out.extend_from_slice(&(sender.len() as u16).to_be_bytes());
                out.extend_from_slice(sender.as_bytes());
                out.extend_from_slice(&seq.to_be_bytes());
                out
            }
            GroupMessage::Have { sender, seq } => {
                let mut out = vec![TAG_HAVE];
                out.extend_from_slice(&(sender.len() as u16).to_be_bytes());
                out.extend_from_slice(sender.as_bytes());
                out.extend_from_slice(&seq.to_be_bytes());
                out
            }
            GroupMessage::RelayRequest { sender, after_seq } => {
                let mut out = vec![TAG_RELAY_REQUEST];
                let sender_bytes = sender.as_bytes();
                out.extend_from_slice(&(sender_bytes.len() as u16).to_be_bytes());
                out.extend_from_slice(sender_bytes);
                out.extend_from_slice(&after_seq.to_be_bytes());
                out
            }
        }
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut cursor = bytes;
        let tag = take(&mut cursor, 1)?[0];
        match tag {
            TAG_APPLICATION => {
                let sender_len = read_u16(&mut cursor)? as usize;
                let sender = String::from_utf8(take(&mut cursor, sender_len)?)
                    .map_err(|_| ChatError::MalformedMessage("bad sender id"))?;
                let seq = read_u64(&mut cursor)?;
                let prev_hash: [u8; 32] = take(&mut cursor, 32)?.try_into().unwrap();
                let roster_version = read_u64(&mut cursor)?;
                let content_len = read_u32(&mut cursor)? as usize;
                let content_bytes = take(&mut cursor, content_len)?;
                let content = GroupContent::decode(&content_bytes)?;
                let signature: [u8; 64] = take(&mut cursor, 64)?.try_into().unwrap();
                Ok(GroupMessage::Application {
                    sender,
                    seq,
                    prev_hash,
                    roster_version,
                    content,
                    signature,
                })
            }
            TAG_ROSTER => {
                let gid_len = read_u16(&mut cursor)? as usize;
                let group_id = String::from_utf8(take(&mut cursor, gid_len)?)
                    .map_err(|_| ChatError::MalformedMessage("bad group id"))?;
                let version = read_u64(&mut cursor)?;
                let prev_hash: [u8; 32] = take(&mut cursor, 32)?.try_into().unwrap();
                let op_len = read_u32(&mut cursor)? as usize;
                let op_bytes = take(&mut cursor, op_len)?;
                let proposer_len = read_u16(&mut cursor)? as usize;
                let proposer = String::from_utf8(take(&mut cursor, proposer_len)?)
                    .map_err(|_| ChatError::MalformedMessage("bad proposer id"))?;
                let signature_bytes: [u8; 64] = take(&mut cursor, 64)?.try_into().unwrap();
                Ok(GroupMessage::Roster(RosterOpWire {
                    group_id,
                    version,
                    prev_hash,
                    op_bytes,
                    proposer,
                    signature_bytes,
                }))
            }
            TAG_ROSTER_SYNC_REQUEST => Ok(GroupMessage::RosterSyncRequest {
                have_version: read_u64(&mut cursor)?,
            }),
            TAG_HAVE => {
                let sender_len = read_u16(&mut cursor)? as usize;
                let sender = String::from_utf8(take(&mut cursor, sender_len)?)
                    .map_err(|_| ChatError::MalformedMessage("bad sender id"))?;
                let seq = read_u64(&mut cursor)?;
                Ok(GroupMessage::Have { sender, seq })
            }
            TAG_RELAY_REQUEST => {
                let sender_len = read_u16(&mut cursor)? as usize;
                let sender = String::from_utf8(take(&mut cursor, sender_len)?)
                    .map_err(|_| ChatError::MalformedMessage("bad sender id"))?;
                let after_seq = read_u64(&mut cursor)?;
                Ok(GroupMessage::RelayRequest { sender, after_seq })
            }
            TAG_EXISTENCE => {
                let sender_len = read_u16(&mut cursor)? as usize;
                let sender = String::from_utf8(take(&mut cursor, sender_len)?)
                    .map_err(|_| ChatError::MalformedMessage("bad sender id"))?;
                let seq = read_u64(&mut cursor)?;
                let prev_hash: [u8; 32] = take(&mut cursor, 32)?.try_into().unwrap();
                let roster_version = read_u64(&mut cursor)?;
                let content_hash: [u8; 32] = take(&mut cursor, 32)?.try_into().unwrap();
                let signature: [u8; 64] = take(&mut cursor, 64)?.try_into().unwrap();
                Ok(GroupMessage::Existence {
                    sender,
                    seq,
                    prev_hash,
                    roster_version,
                    content_hash,
                    signature,
                })
            }
            TAG_RECEIPT => {
                let author_len = read_u16(&mut cursor)? as usize;
                let author = String::from_utf8(take(&mut cursor, author_len)?)
                    .map_err(|_| ChatError::MalformedMessage("bad author id"))?;
                let seq = read_u64(&mut cursor)?;
                let content_hash: [u8; 32] = take(&mut cursor, 32)?.try_into().unwrap();
                let kind = ReceiptKind::from_byte(take(&mut cursor, 1)?[0])?;
                let receiver_len = read_u16(&mut cursor)? as usize;
                let receiver = String::from_utf8(take(&mut cursor, receiver_len)?)
                    .map_err(|_| ChatError::MalformedMessage("bad receiver id"))?;
                let signature: [u8; 64] = take(&mut cursor, 64)?.try_into().unwrap();
                Ok(GroupMessage::Receipt {
                    author,
                    seq,
                    content_hash,
                    kind,
                    receiver,
                    signature,
                })
            }
            TAG_FETCH_REQUEST => {
                let sender_len = read_u16(&mut cursor)? as usize;
                let sender = String::from_utf8(take(&mut cursor, sender_len)?)
                    .map_err(|_| ChatError::MalformedMessage("bad sender id"))?;
                let seq = read_u64(&mut cursor)?;
                Ok(GroupMessage::FetchRequest { sender, seq })
            }
            _ => Err(ChatError::MalformedMessage("unknown group message tag")),
        }
    }

    /// The signed HEADER of an application message: everything about it
    /// except the content itself, which it commits to by SHA-256 hash.
    /// Signing and chaining both operate on this header, which is what lets
    /// a member prove "X said something at position N" (an existence notice)
    /// without disclosing the content.
    pub(crate) fn header_bytes(
        sender: &str,
        seq: u64,
        prev_hash: &[u8; 32],
        roster_version: u64,
        content_bytes: &[u8],
    ) -> Vec<u8> {
        Self::header_from_hash(
            sender,
            seq,
            prev_hash,
            roster_version,
            &Sha256::digest(content_bytes).into(),
        )
    }

    /// [`GroupMessage::header_bytes`] when only the content's hash is known
    /// (an existence notice).
    pub(crate) fn header_from_hash(
        sender: &str,
        seq: u64,
        prev_hash: &[u8; 32],
        roster_version: u64,
        content_hash: &[u8; 32],
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(sender.len() as u16).to_be_bytes());
        out.extend_from_slice(sender.as_bytes());
        out.extend_from_slice(&seq.to_be_bytes());
        out.extend_from_slice(prev_hash);
        out.extend_from_slice(&roster_version.to_be_bytes());
        out.extend_from_slice(content_hash);
        out
    }

    /// The exact bytes an author signs: a domain label, the group, and the header.
    pub(crate) fn signing_bytes(
        group_id: &str,
        sender: &str,
        seq: u64,
        prev_hash: &[u8; 32],
        roster_version: u64,
        content: &GroupContent,
    ) -> Vec<u8> {
        Self::signing_bytes_from_hash(
            group_id,
            sender,
            seq,
            prev_hash,
            roster_version,
            &Sha256::digest(content.encode()).into(),
        )
    }

    /// [`GroupMessage::signing_bytes`] from the content hash alone.
    pub(crate) fn signing_bytes_from_hash(
        group_id: &str,
        sender: &str,
        seq: u64,
        prev_hash: &[u8; 32],
        roster_version: u64,
        content_hash: &[u8; 32],
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"symbolon/group/application/v2");
        out.extend_from_slice(&(group_id.len() as u16).to_be_bytes());
        out.extend_from_slice(group_id.as_bytes());
        out.extend_from_slice(&Self::header_from_hash(
            sender,
            seq,
            prev_hash,
            roster_version,
            content_hash,
        ));
        out
    }

    /// What a receiver signs: label, group, who wrote the message, which
    /// message, the hash of its content, what kind of receipt, and who signs.
    pub(crate) fn receipt_signing_bytes(
        group_id: &str,
        author: &str,
        seq: u64,
        content_hash: &[u8; 32],
        kind: ReceiptKind,
        receiver: &str,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"symbolon/group/receipt/v1");
        for part in [group_id, author, receiver] {
            out.extend_from_slice(&(part.len() as u16).to_be_bytes());
            out.extend_from_slice(part.as_bytes());
        }
        out.extend_from_slice(&seq.to_be_bytes());
        out.extend_from_slice(content_hash);
        out.push(kind.to_byte());
        out
    }

    /// Turn a full application message into the matching existence notice
    /// (same signature, content replaced by its hash). `None` if `bytes` is
    /// not an application message.
    pub(crate) fn notice_from_application(bytes: &[u8]) -> Option<Vec<u8>> {
        match GroupMessage::decode(bytes).ok()? {
            GroupMessage::Application {
                sender,
                seq,
                prev_hash,
                roster_version,
                content,
                signature,
            } => Some(
                GroupMessage::Existence {
                    sender,
                    seq,
                    prev_hash,
                    roster_version,
                    content_hash: Sha256::digest(content.encode()).into(),
                    signature,
                }
                .encode(),
            ),
            _ => None,
        }
    }
}

fn read_u16(cursor: &mut &[u8]) -> Result<u16> {
    Ok(u16::from_be_bytes(take(cursor, 2)?.try_into().unwrap()))
}
fn read_u32(cursor: &mut &[u8]) -> Result<u32> {
    Ok(u32::from_be_bytes(take(cursor, 4)?.try_into().unwrap()))
}
fn read_u64(cursor: &mut &[u8]) -> Result<u64> {
    Ok(u64::from_be_bytes(take(cursor, 8)?.try_into().unwrap()))
}
fn take(cursor: &mut &[u8], n: usize) -> Result<Vec<u8>> {
    if cursor.len() < n {
        return Err(ChatError::MalformedMessage("truncated group message field"));
    }
    let (head, tail) = cursor.split_at(n);
    *cursor = tail;
    Ok(head.to_vec())
}

/// Something a group application should react to.
#[derive(Debug, Clone, PartialEq)]
pub enum GroupEvent {
    /// A new post from `sender`, at their per-sender position `seq` (useful
    /// for later referencing it in an edit/delete UI action).
    Message {
        sender: PeerId,
        seq: u64,
        payload: Vec<u8>,
    },
    /// `author`'s message at `seq` was edited (always by `author`
    /// themselves - see module docs on why edits are self-only).
    MessageEdited {
        author: PeerId,
        seq: u64,
        new_payload: Vec<u8>,
    },
    /// `author`'s message at `seq` was deleted, either by `author`
    /// themselves or by a moderator (`deleted_by` tells you which).
    MessageDeleted {
        author: PeerId,
        seq: u64,
        deleted_by: PeerId,
    },
    /// The roster (membership or tier structure) changed.
    MembershipChanged { members: Vec<PeerId> },
    /// `author`'s message `seq` EXISTS (its signed header verified and it
    /// took its place in the author's chain) but its content is not held
    /// here: the group's relay policy, or our own
    /// [`RelayedContent::ExistenceOnly`] setting, kept it from us. Ask for
    /// it with [`GroupHub::fetch`]; it arrives later as a normal
    /// [`GroupEvent::Message`] (or edit/delete event).
    Existence { author: PeerId, seq: u64 },
    /// `from` acknowledged OUR message `seq` (verified signature, and the
    /// receipt names exactly the content we sent).
    Receipt {
        from: PeerId,
        seq: u64,
        kind: ReceiptKind,
    },
}

struct StoredMessage {
    payload: Vec<u8>,
    edited: bool,
    deleted: bool,
}

/// Tunable knobs for a [`GroupHub`].
#[derive(Clone, Debug)]
pub struct GroupHubConfig {
    /// Which receipts we send. Default: delivery on, read off.
    pub receipts: ReceiptSettings,
    /// What to do with content that reaches us from someone other than its
    /// author. Default: [`RelayedContent::Deliver`].
    pub relayed_content: RelayedContent,
    /// Receiver for [`crate::trace::TraceEvent`]s (default: discards them).
    pub tracer: Arc<dyn crate::trace::Tracer>,
    /// How many recent messages to cache *per sender* for relaying to
    /// members who are catching up. Older entries are evicted first.
    pub relay_cache_capacity_per_sender: usize,
    /// If `true` (the default), `GroupHub` spawns and owns its own
    /// background thread that continuously drains and validates incoming
    /// messages, and [`GroupHub::attach_session`] spawns a per-session
    /// reader thread to feed it. This is the convenient, batteries-included
    /// mode most callers want.
    ///
    /// If `false`, `GroupHub` spawns *no threads at all* - it becomes a
    /// pure library component: [`GroupHub::attach_session`] only registers
    /// the session for sending, and the caller is responsible for pumping
    /// data in, one message at a time, via [`GroupHub::process_one`] (fed
    /// from wherever the caller reads bytes - their own thread, their own
    /// async runtime's task, whatever they're already using). Useful for
    /// embedding this crate into an application that already has its own
    /// concurrency model and doesn't want a second, competing one imposed
    /// on it - e.g. a single-threaded async executor, where spawning raw
    /// OS threads defeats the point.
    pub auto_pump: bool,
}

impl Default for GroupHubConfig {
    fn default() -> Self {
        GroupHubConfig {
            relay_cache_capacity_per_sender: 256,
            auto_pump: true,
            tracer: Arc::new(crate::trace::NoopTracer),
            relayed_content: RelayedContent::Deliver,
            receipts: ReceiptSettings::default(),
        }
    }
}

/// Ties a [`Roster`] together with one full-mesh [`Session`] per other
/// member, providing a `post`/`edit`/`delete`/`recv_event` API.
pub struct GroupHub {
    own_id: PeerId,
    roster: Mutex<Roster>,
    config: GroupHubConfig,
    sessions: Mutex<HashMap<PeerId, Arc<Session>>>,
    own_chain: Mutex<OwnChainState>,
    sender_chains: Mutex<HashMap<PeerId, SenderChainState>>,
    /// Every valid signed application message we've seen, cached so we can
    /// relay it to a member catching up later - see module docs.
    relay_cache: Mutex<HashMap<PeerId, BTreeMap<u64, Vec<u8>>>>,
    /// Messages we know EXIST (verified header, chain advanced) but whose
    /// content we do not hold: `(author, seq) -> expected SHA-256 of content`.
    /// Content that later arrives must match this hash to fill the entry.
    pending_existence: Mutex<HashMap<(PeerId, u64), [u8; 32]>>,
    /// Who handed us each message we accepted from a non-author, so a UI can
    /// warn "relayed by X". Absent = it came straight from its author.
    relayed_by: Mutex<HashMap<(PeerId, u64), PeerId>>,
    /// SHA-256 of the content of every message whose content we hold (ours
    /// and others'). Receipts are checked against, and built from, this.
    content_hashes: Mutex<HashMap<(PeerId, u64), [u8; 32]>>,
    /// Receipts received for OUR messages: seq -> receiver -> strongest kind.
    receipts: Mutex<HashMap<u64, HashMap<PeerId, ReceiptKind>>>,
    /// How we sign receipts (None = we send none). See `enable_receipts`.
    receipt_signer: Mutex<Option<ReceiptSigner>>,
    message_store: Mutex<HashMap<PeerId, BTreeMap<u64, StoredMessage>>>,
    merged_tx: Sender<(PeerId, Vec<u8>)>,
    /// Application-visible events end up here regardless of whether a
    /// background thread or a manual [`GroupHub::process_one`] call
    /// produced them - see [`GroupHubConfig::auto_pump`].
    event_tx: Sender<GroupEvent>,
    event_rx: Mutex<Receiver<GroupEvent>>,
    /// Optional durable, encrypted-at-rest log of every validated roster
    /// op and application message - see [`GroupHub::create_persisted`] /
    /// [`GroupHub::load_persisted`].
    log: Option<Arc<dyn crate::storage::EventStore>>,
    /// Set to true if any append to `log` ever failed (disk full, backend
    /// down...). Checked via [`GroupHub::persistence_healthy`].
    persist_failed: std::sync::atomic::AtomicBool,
    /// Application messages that claim a roster version we have not reached
    /// yet (we are missing a roster op). They cannot be judged until we
    /// catch up, so they wait here and are retried after each applied roster
    /// op. Bounded by [`MAX_DEFERRED`].
    pending_ahead: Mutex<Vec<(PeerId, Vec<u8>)>>,
    /// When we last asked anyone for each author's stream because of a
    /// [`GroupMessage::Have`]; limits how fast a chatty (or hostile) member
    /// can make us send requests.
    have_requested: Mutex<HashMap<PeerId, std::time::Instant>>,
    /// Set while replaying a persisted log at startup, so already-persisted
    /// records don't get appended to the log a second time.
    replaying: std::sync::atomic::AtomicBool,
}

/// Derive the key used to encrypt a member's own persisted group log at
/// rest, from their long-term identity's private key. Domain-separated
/// (via the HKDF `info` parameter) from every other use of that key - in
/// particular from signing - so this is cryptographically independent
/// derived material, not key reuse.
fn derive_storage_key(identity: &Identity) -> crate::crypto::AeadKey {
    use hkdf::Hkdf;
    let hk = Hkdf::<Sha256>::new(None, &identity.secret_bytes());
    let mut out = [0u8; 32];
    hk.expand(b"symbolon/group/storage-key/v1", &mut out)
        .expect("32 bytes is a valid HKDF output length");
    crate::crypto::AeadKey(out)
}

impl GroupHub {
    /// Create a hub with default [`GroupHubConfig`]. See
    /// [`GroupHub::with_config`] to customize it.
    pub fn new(own_identity: &Identity, roster: Roster) -> Arc<GroupHub> {
        Self::with_config(own_identity, roster, GroupHubConfig::default())
    }

    /// Build the hub and start its background processing thread.
    ///
    /// Unlike a naive design where incoming messages are only handled
    /// synchronously inside whatever call happens to be blocked in
    /// `recv_event`, `GroupHub` runs its validation/roster-application/
    /// relay-response logic on a dedicated background thread *continuously*
    /// - the same way `Session` already handles acks and resends in its own
    /// background thread regardless of whether the application is actively
    /// reading. This matters specifically for relaying: another member's
    /// `RelayRequest` needs to be answered whether or not *this* member's
    /// application happens to be mid-`recv_event` at that exact moment.
    pub fn with_config(
        own_identity: &Identity,
        roster: Roster,
        config: GroupHubConfig,
    ) -> Arc<GroupHub> {
        Self::build(own_identity, roster, config, None)
    }

    /// Found a brand-new group *and* persist it: writes the genesis
    /// operation as the first record of an encrypted-at-rest event log at
    /// `log_path`, then behaves like [`GroupHub::with_config`] from then
    /// on, appending every subsequently-validated roster op and
    /// application message to the same log. Use [`GroupHub::load_persisted`]
    /// to reopen it later (e.g. after a restart).
    ///
    /// The log is encrypted under a key derived from `own_identity` (see
    /// [`derive_storage_key`]) - group content never sits on disk in
    /// plaintext, matching the same "encrypted at rest" standard
    /// [`crate::persistence::EncryptedIdentity`] holds long-term identity
    /// keys to.
    pub fn create_persisted(
        own_identity: &Identity,
        roster: Roster,
        genesis: &SignedRosterOp,
        log_path: &std::path::Path,
        config: GroupHubConfig,
    ) -> Result<Arc<GroupHub>> {
        let store = Arc::new(crate::storage::FileEventStore::open(log_path)?);
        Self::create_with_store(own_identity, roster, genesis, store, config)
    }

    /// Like [`GroupHub::create_persisted`] but with ANY
    /// [`crate::storage::EventStore`] backend (database, cloud, memory...).
    /// The hub encrypts every record before the store sees it, so the
    /// backend only ever holds ciphertext.
    pub fn create_with_store(
        own_identity: &Identity,
        roster: Roster,
        genesis: &SignedRosterOp,
        store: Arc<dyn crate::storage::EventStore>,
        config: GroupHubConfig,
    ) -> Result<Arc<GroupHub>> {
        let sealed = Self::seal_store(own_identity, store);
        sealed.append(&GroupMessage::Roster(RosterOpWire::from(genesis)).encode())?;
        sealed.sync()?;
        Ok(Self::build(own_identity, roster, config, Some(sealed)))
    }

    /// Wrap a raw store so the hub's records are encrypted under the
    /// identity-derived storage key (see [`derive_storage_key`]).
    fn seal_store(
        own_identity: &Identity,
        store: Arc<dyn crate::storage::EventStore>,
    ) -> Arc<dyn crate::storage::EventStore> {
        /// Lets a shared `Arc<dyn EventStore>` be wrapped by `SealedEventStore`.
        struct Shared(Arc<dyn crate::storage::EventStore>);
        impl crate::storage::EventStore for Shared {
            fn append(&self, r: &[u8]) -> Result<()> {
                self.0.append(r)
            }
            fn sync(&self) -> Result<()> {
                self.0.sync()
            }
            fn read_all(&self) -> Result<Vec<Vec<u8>>> {
                self.0.read_all()
            }
        }
        Arc::new(crate::storage::SealedEventStore::new(
            Shared(store),
            derive_storage_key(own_identity),
        ))
    }

    /// Reopen a group previously created with [`GroupHub::create_persisted`],
    /// replaying its encrypted log (genesis, then every subsequent roster
    /// op and application message) through the exact same validation logic
    /// used for live traffic to fully reconstruct membership, tiers, sender
    /// chains, and message history - before any new sessions are attached.
    pub fn load_persisted(
        own_identity: &Identity,
        log_path: &std::path::Path,
        config: GroupHubConfig,
    ) -> Result<Arc<GroupHub>> {
        let store = Arc::new(crate::storage::FileEventStore::open(log_path)?);
        Self::load_with_store(own_identity, store, config)
    }

    /// Like [`GroupHub::load_persisted`] but from any
    /// [`crate::storage::EventStore`].
    pub fn load_with_store(
        own_identity: &Identity,
        store: Arc<dyn crate::storage::EventStore>,
        config: GroupHubConfig,
    ) -> Result<Arc<GroupHub>> {
        let sealed = Self::seal_store(own_identity, store);
        let records = sealed.read_all()?;
        let (first, rest) = records
            .split_first()
            .ok_or(ChatError::MalformedMessage("persisted group log is empty"))?;

        let GroupMessage::Roster(genesis_wire) = GroupMessage::decode(first)? else {
            return Err(ChatError::MalformedMessage(
                "persisted log does not start with a genesis roster op",
            ));
        };
        let genesis = genesis_wire.to_signed()?;
        let roster = Roster::from_genesis(&genesis)?;

        let hub = Self::build(own_identity, roster, config, Some(sealed));

        hub.replaying
            .store(true, std::sync::atomic::Ordering::SeqCst);
        for record in rest {
            // Replayed records were already validated once (that's how
            // they got persisted in the first place); re-running them
            // through `process_incoming` here reconstructs sender chains,
            // the message store, and roster state identically to how they
            // stood live, using one code path for both "just happened" and
            // "happened before I restarted".
            let _ = hub.process_incoming(hub.own_id.clone(), record.clone());
        }
        hub.replaying
            .store(false, std::sync::atomic::Ordering::SeqCst);

        // `process_incoming` tracks every sender - including our own past
        // messages, replayed above - in `sender_chains`, since that's the
        // structure used to validate *incoming* content. But *outgoing*
        // messages are tracked separately in `own_chain` (see `post`),
        // which replay never touches directly. Re-seed it from what replay
        // just reconstructed, so a `post()` right after reload continues
        // our own sequence rather than restarting it from 1 and immediately
        // colliding with our own already-persisted history.
        if let Some(chain) = hub.sender_chains.lock().unwrap().get(&hub.own_id) {
            let (next_seq, tip_hash) = chain.snapshot();
            hub.own_chain.lock().unwrap().seed_from(next_seq, tip_hash);
        }

        Ok(hub)
    }

    /// `false` once any write to the persistence backend has failed. History
    /// since that failure is NOT durable; the app should warn the user or
    /// stop. Always `true` for a hub with no persistence configured.
    pub fn persistence_healthy(&self) -> bool {
        !self
            .persist_failed
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    fn build(
        own_identity: &Identity,
        roster: Roster,
        config: GroupHubConfig,
        log: Option<Arc<dyn crate::storage::EventStore>>,
    ) -> Arc<GroupHub> {
        let (merged_tx, merged_rx) = mpsc::channel::<(PeerId, Vec<u8>)>();
        let (event_tx, event_rx) = mpsc::channel::<GroupEvent>();
        let auto_pump = config.auto_pump;
        let hub = Arc::new(GroupHub {
            own_id: own_identity.fingerprint(),
            roster: Mutex::new(roster),
            config,
            sessions: Mutex::new(HashMap::new()),
            own_chain: Mutex::new(OwnChainState::new()),
            sender_chains: Mutex::new(HashMap::new()),
            relay_cache: Mutex::new(HashMap::new()),
            pending_existence: Mutex::new(HashMap::new()),
            relayed_by: Mutex::new(HashMap::new()),
            content_hashes: Mutex::new(HashMap::new()),
            receipts: Mutex::new(HashMap::new()),
            receipt_signer: Mutex::new(None),
            message_store: Mutex::new(HashMap::new()),
            merged_tx,
            event_tx,
            event_rx: Mutex::new(event_rx),
            log,
            replaying: std::sync::atomic::AtomicBool::new(false),
            persist_failed: std::sync::atomic::AtomicBool::new(false),
            pending_ahead: Mutex::new(Vec::new()),
            have_requested: Mutex::new(HashMap::new()),
        });

        if auto_pump {
            let hub_for_thread = Arc::clone(&hub);
            std::thread::spawn(move || loop {
                let Ok((from, bytes)) = merged_rx.recv() else {
                    return;
                };
                hub_for_thread.process_one(from, bytes);
            });
        }
        // If `auto_pump` is false, `merged_rx` is simply dropped here -
        // nothing will ever send on `merged_tx` either, since
        // `attach_session` also checks `auto_pump` before spawning its own
        // feeder thread. The caller is expected to read from their
        // `Session`s themselves and call `process_one` directly.

        hub
    }

    /// Attach an already-established, mutually-authenticated pairwise
    /// session to another member. If [`GroupHubConfig::auto_pump`] is
    /// `true` (the default), this also spawns a thread that feeds incoming
    /// messages from `session` into the hub automatically; if `false`, it
    /// only registers the session for *sending* - reading and pumping
    /// (via [`GroupHub::process_one`]) is left entirely to the caller.
    pub fn attach_session(&self, peer_id: PeerId, session: Arc<Session>) {
        // Register FIRST. The reader thread below can receive and answer a
        // request (e.g. the peer's roster-sync request) immediately, and the
        // answer is sent through `self.sessions`; if we were not registered
        // yet the reply would be silently dropped.
        self.sessions
            .lock()
            .unwrap()
            .insert(peer_id.clone(), Arc::clone(&session));

        if self.config.auto_pump {
            let tx = self.merged_tx.clone();
            let session_for_thread = Arc::clone(&session);
            let peer_id_for_thread = peer_id.clone();
            std::thread::spawn(move || loop {
                match session_for_thread.recv() {
                    Ok(bytes) => {
                        if tx.send((peer_id_for_thread.clone(), bytes)).is_err() {
                            return;
                        }
                    }
                    Err(_) => return,
                }
            });
        }
        // Ask the new peer for any roster ops we are missing (a no-op if we
        // are current). Roster first, THEN content: messages that claim a
        // newer roster version wait in `pending_ahead` until it arrives.
        let have_version = self.roster.lock().unwrap().version();
        let _ = session.send(&GroupMessage::RosterSyncRequest { have_version }.encode());
    }

    /// Process exactly one raw `(from, bytes)` pair - the same validation
    /// (signature checks, tier permissions, sender-chain continuity, roster
    /// application, relay-request answering) the automatic background
    /// thread performs when [`GroupHubConfig::auto_pump`] is `true`. Call
    /// this yourself, in your own loop / task / async executor, when the
    /// hub was built with `auto_pump: false`. Any resulting
    /// application-visible event goes through the exact same queue
    /// [`GroupHub::recv_event`] reads from either way - `process_one` only
    /// changes *who* drives the pumping, never *how* events are delivered.
    pub fn process_one(&self, from: PeerId, bytes: Vec<u8>) {
        if let Some(event) = self.process_incoming(from, bytes) {
            let _ = self.event_tx.send(event);
        }
    }

    /// Post a new application payload, signed by `identity`, to every
    /// current member whose tier grants `can_read` (real enforcement: they
    /// simply never receive it, rather than receiving-then-hiding it).
    /// Requires our own current tier to grant `can_write`.
    pub fn post(&self, identity: &Identity, payload: &[u8]) -> Result<u64> {
        self.require_permission(|p| p.can_write)?;
        let content = GroupContent::Post {
            payload: payload.to_vec(),
        };
        self.sign_and_send(identity, content)
    }

    /// Backwards/forwards-compatible alias for [`GroupHub::post`].
    pub fn broadcast(&self, identity: &Identity, payload: &[u8]) -> Result<u64> {
        self.post(identity, payload)
    }

    /// Edit one of our own previous posts (identified by its per-sender
    /// `target_seq`). Requires `can_write` - you can only ever edit your
    /// own content, regardless of any other permission.
    pub fn edit(&self, identity: &Identity, target_seq: u64, new_payload: &[u8]) -> Result<u64> {
        self.require_permission(|p| p.can_write)?;
        let content = GroupContent::Edit {
            target_seq,
            new_payload: new_payload.to_vec(),
        };
        self.sign_and_send(identity, content)
    }

    /// Delete a message: your own (requires `can_write`, same as editing -
    /// deleting your own content is a normal part of authoring it), or - if
    /// `target_sender` is someone else - requires `can_remove` (moderation).
    pub fn delete(
        &self,
        identity: &Identity,
        target_sender: PeerId,
        target_seq: u64,
    ) -> Result<u64> {
        if target_sender == identity.fingerprint() {
            self.require_permission(|p| p.can_write)?;
        } else {
            self.require_permission(|p| p.can_remove)?;
        }
        let content = GroupContent::Delete {
            target_sender,
            target_seq,
        };
        self.sign_and_send(identity, content)
    }

    fn require_permission(&self, check: impl Fn(&Permissions) -> bool) -> Result<()> {
        let perms = self.roster.lock().unwrap().permissions_of(&self.own_id);
        if check(&perms) {
            Ok(())
        } else {
            Err(ChatError::PermissionDenied)
        }
    }

    fn sign_and_send(&self, identity: &Identity, content: GroupContent) -> Result<u64> {
        let content_bytes = content.encode();
        let sender = identity.fingerprint();
        let (group_id, roster_version) = {
            let r = self.roster.lock().unwrap();
            (r.group_id.clone(), r.version())
        };
        let (seq, prev_hash) =
            self.own_chain
                .lock()
                .unwrap()
                .next_header(&sender, roster_version, &content_bytes);
        let signing_bytes = GroupMessage::signing_bytes(
            &group_id,
            &sender,
            seq,
            &prev_hash,
            roster_version,
            &content,
        );
        let signature = identity.sign(&signing_bytes).to_bytes();
        let msg = GroupMessage::Application {
            sender: sender.clone(),
            seq,
            prev_hash,
            roster_version,
            content,
            signature,
        };
        let wire = msg.encode();

        // Cache our own message too, so we can relay it to someone else
        // even if we're the only one currently online who has it.
        self.cache_for_relay(&sender, seq, &wire);
        self.content_hashes
            .lock()
            .unwrap()
            .insert((sender.clone(), seq), Sha256::digest(&content_bytes).into());
        self.persist(&wire);
        self.apply_content_locally(&sender, seq, &self.get_content(&msg));

        self.fan_out_to_readers(&wire)?;
        Ok(seq)
    }

    /// Append `bytes` (an already-validated `GroupMessage::Application` or
    /// `GroupMessage::Roster` wire encoding) to the persisted log, if one is
    /// configured - unless we're currently replaying that same log at
    /// startup, in which case appending again would duplicate it.
    fn persist(&self, bytes: &[u8]) {
        if self.replaying.load(std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        if let Some(log) = &self.log {
            if log.append(bytes).is_err() {
                self.persist_failed
                    .store(true, std::sync::atomic::Ordering::SeqCst);
                self.trace(TraceEvent::PersistFailed);
            }
        }
    }

    fn trace(&self, e: TraceEvent) {
        self.config.tracer.event(&e);
    }

    /// Trace a dropped group message and return `None` (for `?`-style exits).
    fn reject(&self, author: &PeerId, reason: &'static str) -> Option<GroupEvent> {
        self.trace(TraceEvent::GroupMessageRejected {
            author: author.clone(),
            reason,
        });
        None
    }

    fn get_content(&self, msg: &GroupMessage) -> GroupContent {
        match msg {
            GroupMessage::Application { content, .. } => content.clone(),
            _ => unreachable!("get_content only ever called with an Application message"),
        }
    }

    /// Send `wire` to every attached session whose member currently has
    /// `can_read` - this is the actual enforcement point for the "read"
    /// permission dimension.
    fn fan_out_to_readers(&self, wire: &[u8]) -> Result<()> {
        let roster = self.roster.lock().unwrap();
        let sessions = self.sessions.lock().unwrap();
        for (peer_id, session) in sessions.iter() {
            if roster.permissions_of(peer_id).can_read {
                session.send(wire)?;
            }
        }
        Ok(())
    }

    fn cache_for_relay(&self, sender: &PeerId, seq: u64, wire: &[u8]) {
        let mut cache = self.relay_cache.lock().unwrap();
        let per_sender = cache.entry(sender.clone()).or_default();
        per_sender.insert(seq, wire.to_vec());
        while per_sender.len() > self.config.relay_cache_capacity_per_sender {
            if let Some(&oldest) = per_sender.keys().next() {
                per_sender.remove(&oldest);
            }
        }
    }

    /// Apply already-validated content to our local message store,
    /// returning the [`GroupEvent`] it produces, if any (an edit/delete
    /// targeting a message we never saw produces no event, but doesn't
    /// error - the underlying post may simply have been evicted or never
    /// relayed to us).
    fn apply_content_locally(
        &self,
        sender: &PeerId,
        seq: u64,
        content: &GroupContent,
    ) -> Option<GroupEvent> {
        let mut store = self.message_store.lock().unwrap();
        match content {
            GroupContent::Post { payload } => {
                store.entry(sender.clone()).or_default().insert(
                    seq,
                    StoredMessage {
                        payload: payload.clone(),
                        edited: false,
                        deleted: false,
                    },
                );
                Some(GroupEvent::Message {
                    sender: sender.clone(),
                    seq,
                    payload: payload.clone(),
                })
            }
            GroupContent::Edit {
                target_seq,
                new_payload,
            } => {
                let author_messages = store.entry(sender.clone()).or_default();
                if let Some(stored) = author_messages.get_mut(target_seq) {
                    if stored.deleted {
                        return None; // can't edit something already deleted
                    }
                    stored.payload = new_payload.clone();
                    stored.edited = true;
                    Some(GroupEvent::MessageEdited {
                        author: sender.clone(),
                        seq: *target_seq,
                        new_payload: new_payload.clone(),
                    })
                } else {
                    None
                }
            }
            GroupContent::Delete {
                target_sender,
                target_seq,
            } => {
                let author_messages = store.entry(target_sender.clone()).or_default();
                if let Some(stored) = author_messages.get_mut(target_seq) {
                    stored.deleted = true;
                    stored.payload.clear();
                    Some(GroupEvent::MessageDeleted {
                        author: target_sender.clone(),
                        seq: *target_seq,
                        deleted_by: sender.clone(),
                    })
                } else {
                    None
                }
            }
        }
    }

    /// Propose adding `member` at `tier`, applying locally and broadcasting
    /// to every attached session.
    pub fn propose_add(
        &self,
        own_identity: &Identity,
        member: VerifyingKey,
        tier: TierName,
    ) -> Result<()> {
        let signed = self
            .roster
            .lock()
            .unwrap()
            .propose_add(own_identity, member, tier)?;
        self.roster.lock().unwrap().apply(&signed)?;
        self.broadcast_roster_op(&signed)
    }

    /// Propose adding `member` as a BOT at `tier` (see [`MemberKind`]).
    pub fn propose_add_bot(
        &self,
        own_identity: &Identity,
        member: VerifyingKey,
        tier: TierName,
    ) -> Result<()> {
        let signed = self
            .roster
            .lock()
            .unwrap()
            .propose_add_bot(own_identity, member, tier)?;
        self.roster.lock().unwrap().apply(&signed)?;
        self.broadcast_roster_op(&signed)
    }

    /// Person or bot? `None` if `id` is not a current member. A UI should
    /// always show bots as bots.
    pub fn kind_of(&self, id: &PeerId) -> Option<MemberKind> {
        self.roster.lock().unwrap().kind_of(id)
    }

    /// Who sponsors this bot (its removal cascades from theirs).
    pub fn sponsor_of(&self, id: &PeerId) -> Option<PeerId> {
        self.roster.lock().unwrap().sponsor_of(id)
    }

    /// Propose removing `target`.
    pub fn propose_remove(&self, own_identity: &Identity, target: PeerId) -> Result<()> {
        let signed = self
            .roster
            .lock()
            .unwrap()
            .propose_remove(own_identity, target)?;
        self.roster.lock().unwrap().apply(&signed)?;
        self.broadcast_roster_op(&signed)
    }

    /// Propose moving `target` to `new_tier` (promotion/demotion).
    pub fn propose_change_tier(
        &self,
        own_identity: &Identity,
        target: PeerId,
        new_tier: TierName,
    ) -> Result<()> {
        let signed =
            self.roster
                .lock()
                .unwrap()
                .propose_change_tier(own_identity, target, new_tier)?;
        self.roster.lock().unwrap().apply(&signed)?;
        self.broadcast_roster_op(&signed)
    }

    /// Propose defining/redefining a tier's permission bundle.
    pub fn propose_define_tier(
        &self,
        own_identity: &Identity,
        name: TierName,
        permissions: Permissions,
    ) -> Result<()> {
        let signed =
            self.roster
                .lock()
                .unwrap()
                .propose_define_tier(own_identity, name, permissions)?;
        self.roster.lock().unwrap().apply(&signed)?;
        self.broadcast_roster_op(&signed)
    }

    fn broadcast_roster_op(&self, signed: &SignedRosterOp) -> Result<()> {
        let wire = GroupMessage::Roster(RosterOpWire::from(signed)).encode();
        self.persist(&wire);
        let sessions = self.sessions.lock().unwrap();
        for session in sessions.values() {
            session.send(&wire)?;
        }
        Ok(())
    }

    /// Ask the mesh to catch us up: for every other known member, send a
    /// [`GroupMessage::RelayRequest`] naming the highest position in their
    /// stream we've already seen. *Any* attached member who has newer
    /// entries of theirs cached will answer - not just that member
    /// themselves, which is what lets catch-up happen even if the original
    /// author is offline right now. Call this after (re)connecting.
    pub fn request_catchup(&self) -> Result<()> {
        let members = self.roster.lock().unwrap().member_ids();
        let chains = self.sender_chains.lock().unwrap();
        let sessions = self.sessions.lock().unwrap();
        for member in members {
            if member == self.own_id {
                continue;
            }
            let after_seq = chains.get(&member).map(|c| c.next_seq_hint()).unwrap_or(0);
            let request = GroupMessage::RelayRequest {
                sender: member,
                after_seq,
            }
            .encode();
            for session in sessions.values() {
                let _ = session.send(&request);
            }
        }
        Ok(())
    }

    /// Block until the next meaningful group event. Processing (signature
    /// verification, roster application, relay-request answering) already
    /// happens continuously on a background thread - this just waits for
    /// the next thing worth telling the application about.
    pub fn recv_event(&self) -> Result<GroupEvent> {
        self.event_rx
            .lock()
            .unwrap()
            .recv()
            .map_err(|_| ChatError::ConnectionClosed)
    }

    /// Like [`GroupHub::recv_event`], but gives up and returns `None` if
    /// nothing valid arrives within `timeout`.
    pub fn recv_event_timeout(&self, timeout: std::time::Duration) -> Option<GroupEvent> {
        self.event_rx.lock().unwrap().recv_timeout(timeout).ok()
    }

    /// Validate and process one raw `(arrival_peer, bytes)` pair. Note that
    /// `arrival_peer` - who physically handed us these bytes - is used only
    /// for routing [`GroupMessage::RelayRequest`] replies; it plays no role
    /// in authenticating [`GroupMessage::Application`] content, which is
    /// self-authenticating via its embedded signature (see module docs).
    fn process_incoming(&self, arrival_peer: PeerId, bytes: Vec<u8>) -> Option<GroupEvent> {
        let Ok(msg) = GroupMessage::decode(&bytes) else {
            return self.reject(&arrival_peer, "undecodable");
        };
        match msg {
            GroupMessage::Application {
                sender,
                seq,
                prev_hash,
                roster_version,
                content,
                signature,
            } => {
                // Look up the *original author's* key (anyone who was EVER a
                // member, so a since-removed member's earlier messages still
                // verify) and what they were allowed to do AS OF the roster
                // version they signed - not the arrival peer's, and not
                // whatever the roster says today.
                let (author_key, author_perms, group_id) = {
                    let roster = self.roster.lock().unwrap();
                    let Some(key) = roster.key_ever(&sender) else {
                        drop(roster);
                        return self.reject(&sender, "unknown author");
                    };
                    match roster.permissions_at(roster_version, &sender) {
                        Some(perms) => (key, perms, roster.group_id.clone()),
                        None => {
                            // The author's version is ahead of ours: we are
                            // missing a roster op and cannot judge yet. Park it.
                            drop(roster);
                            self.trace(TraceEvent::GroupMessageDeferred {
                                author: sender.clone(),
                            });
                            self.defer(arrival_peer, bytes);
                            return None;
                        }
                    }
                };

                let required_ok = match &content {
                    GroupContent::Post { .. } | GroupContent::Edit { .. } => author_perms.can_write,
                    GroupContent::Delete { target_sender, .. } => {
                        if *target_sender == sender {
                            author_perms.can_write
                        } else {
                            author_perms.can_remove
                        }
                    }
                };
                if !required_ok {
                    return self.reject(&sender, "not permitted at claimed roster version");
                }

                let signing_bytes = GroupMessage::signing_bytes(
                    &group_id,
                    &sender,
                    seq,
                    &prev_hash,
                    roster_version,
                    &content,
                );
                let sig_ok = Signature::from_slice(&signature)
                    .ok()
                    .map(|sig| {
                        PeerRegistry::verify_signature(&author_key, &signing_bytes, &sig).is_ok()
                    })
                    .unwrap_or(false);
                if !sig_ok {
                    return self.reject(&sender, "bad signature");
                }

                let content_hash: [u8; 32] = Sha256::digest(content.encode()).into();
                // Replay (arrival == us) is never "relayed"; neither is a
                // message straight from its author.
                let relayed = arrival_peer != sender && arrival_peer != self.own_id;
                let hide = relayed && self.config.relayed_content == RelayedContent::ExistenceOnly;

                // (1) Does this fill in a message we only knew existed? Its
                // content must hash to what the author's signed header said.
                let expected = self
                    .pending_existence
                    .lock()
                    .unwrap()
                    .get(&(sender.clone(), seq))
                    .copied();
                if let Some(expected) = expected {
                    if expected != content_hash {
                        return self.reject(&sender, "content does not match its existence notice");
                    }
                    if hide {
                        return None; // keep waiting for the author's own copy
                    }
                    self.pending_existence
                        .lock()
                        .unwrap()
                        .remove(&(sender.clone(), seq));
                    if relayed {
                        self.relayed_by
                            .lock()
                            .unwrap()
                            .insert((sender.clone(), seq), arrival_peer.clone());
                    }
                    self.cache_for_relay(&sender, seq, &bytes);
                    self.persist(&bytes);
                    self.trace(TraceEvent::ContentFilled {
                        author: sender.clone(),
                        seq,
                    });
                    self.note_held(&sender, seq, content_hash, &content, &arrival_peer);
                    return self.apply_content_locally(&sender, seq, &content);
                }

                let header = GroupMessage::header_from_hash(
                    &sender,
                    seq,
                    &prev_hash,
                    roster_version,
                    &content_hash,
                );

                // (2) Content from a relay, and we only want it from the
                // author: take the HEADER (it advances the chain and is
                // fully verified) but not the content.
                if hide {
                    {
                        let mut chains = self.sender_chains.lock().unwrap();
                        let chain = chains.entry(sender.clone()).or_default();
                        if chain
                            .verify_and_advance(seq, prev_hash, roster_version, &header)
                            .is_err()
                        {
                            drop(chains);
                            return self.reject(&sender, "chain violation");
                        }
                    }
                    self.pending_existence
                        .lock()
                        .unwrap()
                        .insert((sender.clone(), seq), content_hash);
                    let notice = GroupMessage::Existence {
                        sender: sender.clone(),
                        seq,
                        prev_hash,
                        roster_version,
                        content_hash,
                        signature,
                    }
                    .encode();
                    self.persist(&notice);
                    self.trace(TraceEvent::ExistenceRecorded {
                        author: sender.clone(),
                        seq,
                    });
                    return Some(GroupEvent::Existence {
                        author: sender,
                        seq,
                    });
                }

                // (3) Normal acceptance.
                {
                    let mut chains = self.sender_chains.lock().unwrap();
                    let chain = chains.entry(sender.clone()).or_default();
                    if chain
                        .verify_and_advance(seq, prev_hash, roster_version, &header)
                        .is_err()
                    {
                        drop(chains);
                        return self.reject(&sender, "chain violation");
                    }
                }

                // Cache it (regardless of who delivered it) so we can relay
                // it onward to someone else later - this is what makes any
                // member able to backfill any other member's history.
                self.cache_for_relay(&sender, seq, &bytes);
                self.persist(&bytes);
                if relayed {
                    self.relayed_by
                        .lock()
                        .unwrap()
                        .insert((sender.clone(), seq), arrival_peer.clone());
                }
                self.trace(TraceEvent::GroupMessageAccepted {
                    author: sender.clone(),
                    seq,
                });
                self.note_held(&sender, seq, content_hash, &content, &arrival_peer);
                self.announce_have(&sender, seq, &arrival_peer);

                self.apply_content_locally(&sender, seq, &content)
            }
            GroupMessage::Roster(wire) => {
                let Ok(signed) = wire.to_signed() else {
                    self.trace(TraceEvent::RosterRejected);
                    return None;
                };
                let applied = self.roster.lock().unwrap().apply(&signed).is_ok();
                if applied {
                    let version = self.roster.lock().unwrap().version;
                    self.trace(TraceEvent::RosterApplied { version });
                    self.persist(&bytes);
                    let members = self.roster.lock().unwrap().member_ids();
                    // Announce the membership change first, then retry any
                    // messages that were waiting on this very op.
                    let _ = self
                        .event_tx
                        .send(GroupEvent::MembershipChanged { members });
                    self.retry_deferred();
                    None
                } else {
                    self.trace(TraceEvent::RosterRejected);
                    None
                }
            }
            GroupMessage::RosterSyncRequest { have_version } => {
                // Send the ops they are missing, in order, over the same
                // session the request came in on. They verify each one.
                let ops = self.roster.lock().unwrap().ops_after(have_version);
                if let Some(session) = self.sessions.lock().unwrap().get(&arrival_peer) {
                    for op in ops {
                        let _ =
                            session.send(&GroupMessage::Roster(RosterOpWire::from(&op)).encode());
                    }
                }
                None
            }
            GroupMessage::Existence {
                sender,
                seq,
                prev_hash,
                roster_version,
                content_hash,
                signature,
            } => {
                let (author_key, author_perms, group_id) = {
                    let roster = self.roster.lock().unwrap();
                    let Some(key) = roster.key_ever(&sender) else {
                        drop(roster);
                        return self.reject(&sender, "unknown author");
                    };
                    match roster.permissions_at(roster_version, &sender) {
                        Some(perms) => (key, perms, roster.group_id.clone()),
                        None => {
                            drop(roster);
                            self.trace(TraceEvent::GroupMessageDeferred {
                                author: sender.clone(),
                            });
                            self.defer(arrival_peer, bytes);
                            return None;
                        }
                    }
                };
                // We cannot see the content kind, so we can only require
                // that the author held SOME posting power at that version.
                // The full per-kind check happens when the content arrives.
                if !(author_perms.can_write || author_perms.can_remove) {
                    return self.reject(&sender, "not permitted at claimed roster version");
                }
                let signing_bytes = GroupMessage::signing_bytes_from_hash(
                    &group_id,
                    &sender,
                    seq,
                    &prev_hash,
                    roster_version,
                    &content_hash,
                );
                let sig_ok = Signature::from_slice(&signature)
                    .ok()
                    .map(|sig| {
                        PeerRegistry::verify_signature(&author_key, &signing_bytes, &sig).is_ok()
                    })
                    .unwrap_or(false);
                if !sig_ok {
                    return self.reject(&sender, "bad signature");
                }
                let header = GroupMessage::header_from_hash(
                    &sender,
                    seq,
                    &prev_hash,
                    roster_version,
                    &content_hash,
                );
                {
                    let mut chains = self.sender_chains.lock().unwrap();
                    let chain = chains.entry(sender.clone()).or_default();
                    if chain.next_seq() > seq {
                        return None; // already accounted for (content or earlier notice)
                    }
                    if chain
                        .verify_and_advance(seq, prev_hash, roster_version, &header)
                        .is_err()
                    {
                        drop(chains);
                        return self.reject(&sender, "chain violation");
                    }
                }
                self.pending_existence
                    .lock()
                    .unwrap()
                    .insert((sender.clone(), seq), content_hash);
                self.persist(&bytes);
                self.trace(TraceEvent::ExistenceRecorded {
                    author: sender.clone(),
                    seq,
                });
                Some(GroupEvent::Existence {
                    author: sender,
                    seq,
                })
            }
            GroupMessage::Receipt {
                author,
                seq,
                content_hash,
                kind,
                receiver,
                signature,
            } => {
                if author != self.own_id {
                    return None; // about someone else's message: not ours to track
                }
                let (key, group_id) = {
                    let r = self.roster.lock().unwrap();
                    (r.key_ever(&receiver), r.group_id.clone())
                };
                let Some(key) = key else {
                    return self.reject(&receiver, "receipt from unknown member");
                };
                let signing = GroupMessage::receipt_signing_bytes(
                    &group_id,
                    &author,
                    seq,
                    &content_hash,
                    kind,
                    &receiver,
                );
                let ok = Signature::from_slice(&signature)
                    .ok()
                    .map(|sig| PeerRegistry::verify_signature(&key, &signing, &sig).is_ok())
                    .unwrap_or(false);
                if !ok {
                    return self.reject(&receiver, "bad receipt signature");
                }
                let ours = self
                    .content_hashes
                    .lock()
                    .unwrap()
                    .get(&(self.own_id.clone(), seq))
                    .copied();
                if ours != Some(content_hash) {
                    return self.reject(&receiver, "receipt for content we did not send");
                }
                {
                    let mut all = self.receipts.lock().unwrap();
                    let entry = all.entry(seq).or_default();
                    let best = entry.get(&receiver).copied();
                    if best.map_or(true, |b| kind > b) {
                        entry.insert(receiver.clone(), kind);
                    } else {
                        return None; // nothing new
                    }
                }
                self.persist(&bytes);
                Some(GroupEvent::Receipt {
                    from: receiver,
                    seq,
                    kind,
                })
            }
            GroupMessage::FetchRequest { sender, seq } => {
                // Serving content is where the `can_read` permission is
                // enforced for pulls (fan_out_to_readers does it for pushes):
                // someone who may not read must not get content by asking.
                if !self
                    .roster
                    .lock()
                    .unwrap()
                    .permissions_of(&arrival_peer)
                    .can_read
                {
                    return None;
                }
                let cached = self
                    .relay_cache
                    .lock()
                    .unwrap()
                    .get(&sender)
                    .and_then(|m| m.get(&seq))
                    .cloned();
                if let Some(wire) = cached {
                    let reply = self.wire_for_requester(&sender, wire);
                    if let Some(session) = self.sessions.lock().unwrap().get(&arrival_peer) {
                        let _ = session.send(&reply);
                    }
                }
                None
            }
            GroupMessage::Have { sender, seq } => {
                // Only a current reader of this group may tell us things, and
                // only about a member (past or present) of this group.
                let (reader, known_author) = {
                    let roster = self.roster.lock().unwrap();
                    (
                        roster.permissions_of(&arrival_peer).can_read,
                        roster.key_ever(&sender).is_some(),
                    )
                };
                if !reader || !known_author || sender == self.own_id {
                    return None;
                }
                // Do we already have it (or at least its header)?
                let have_up_to = self
                    .sender_chains
                    .lock()
                    .unwrap()
                    .get(&sender)
                    .map(|c| c.next_seq_hint())
                    .unwrap_or(0);
                if seq <= have_up_to {
                    return None;
                }
                // Debounce: one request per author per 300 ms, however many
                // announcements arrive.
                {
                    let mut last = self.have_requested.lock().unwrap();
                    let now = std::time::Instant::now();
                    if let Some(t) = last.get(&sender) {
                        if now.duration_since(*t) < std::time::Duration::from_millis(300) {
                            return None;
                        }
                    }
                    if last.len() > 1024 {
                        last.clear(); // bounded; worst case is one extra request
                    }
                    last.insert(sender.clone(), now);
                }
                let request = GroupMessage::RelayRequest {
                    sender,
                    after_seq: have_up_to,
                }
                .encode();
                if let Some(session) = self.sessions.lock().unwrap().get(&arrival_peer) {
                    let _ = session.send(&request);
                }
                None
            }
            GroupMessage::RelayRequest { sender, after_seq } => {
                // Same rule as FetchRequest: only current readers are served.
                if !self
                    .roster
                    .lock()
                    .unwrap()
                    .permissions_of(&arrival_peer)
                    .can_read
                {
                    return None;
                }
                // Answer using whatever we have cached from `sender` - we
                // don't need to *be* sender to help someone catch up.
                let cached: Vec<Vec<u8>> = {
                    let cache = self.relay_cache.lock().unwrap();
                    cache
                        .get(&sender)
                        .map(|per_sender| {
                            per_sender
                                .range((
                                    std::ops::Bound::Excluded(after_seq),
                                    std::ops::Bound::Unbounded,
                                ))
                                .map(|(_, v)| v.clone())
                                .collect()
                        })
                        .unwrap_or_default()
                };
                if let Some(session) = self.sessions.lock().unwrap().get(&arrival_peer) {
                    for wire in cached {
                        let _ = session.send(&self.wire_for_requester(&sender, wire));
                    }
                }
                None // a relay request itself is bookkeeping, not an app-visible event
            }
        }
    }

    /// Tell the other readers we now hold `author`'s message `seq`, so a member
    /// who is not linked to the author finds out immediately instead of on
    /// its next catch-up. Sent once per message (a duplicate is rejected before
    /// reaching here, so there are no loops), never for our own messages (those
    /// already go straight to every reader) and never for a log replay.
    ///
    /// Scope, on purpose: only sessions attached to THIS hub (so only members
    /// of this group), only members who currently have `can_read`, never the
    /// peer we got it from, never the author. It contains no link information
    /// and nothing about other groups or 1:1 chats; the worst a recipient
    /// learns is that we hold a message they are allowed to read anyway.
    fn announce_have(&self, author: &PeerId, seq: u64, came_from: &PeerId) {
        if *came_from == self.own_id || *author == self.own_id {
            return;
        }
        let wire = GroupMessage::Have {
            sender: author.clone(),
            seq,
        }
        .encode();
        let roster = self.roster.lock().unwrap();
        let sessions = self.sessions.lock().unwrap();
        for (peer_id, session) in sessions.iter() {
            if peer_id == came_from || peer_id == author {
                continue;
            }
            if roster.permissions_of(peer_id).can_read {
                let _ = session.send(&wire);
            }
        }
    }

    /// Bookkeeping when we have accepted content: remember its hash and, for
    /// a post from someone else that reached us live (not a log replay),
    /// send the author a delivery receipt if our settings allow it.
    fn note_held(
        &self,
        author: &PeerId,
        seq: u64,
        content_hash: [u8; 32],
        content: &GroupContent,
        arrival_peer: &PeerId,
    ) {
        self.content_hashes
            .lock()
            .unwrap()
            .insert((author.clone(), seq), content_hash);
        let live = *arrival_peer != self.own_id;
        if live
            && *author != self.own_id
            && self.config.receipts.delivery
            && matches!(content, GroupContent::Post { .. })
        {
            let _ = self.send_receipt(author, seq, ReceiptKind::Delivered);
        }
    }

    /// Build, sign and send a receipt to `author` over their session.
    /// `Ok(false)` if we cannot (no signer, content not held, author not
    /// connected); nothing is queued for later.
    fn send_receipt(&self, author: &PeerId, seq: u64, kind: ReceiptKind) -> Result<bool> {
        let Some(signer) = self.receipt_signer.lock().unwrap().clone() else {
            return Ok(false);
        };
        let Some(content_hash) = self
            .content_hashes
            .lock()
            .unwrap()
            .get(&(author.clone(), seq))
            .copied()
        else {
            return Ok(false);
        };
        let group_id = self.roster.lock().unwrap().group_id.clone();
        let signing = GroupMessage::receipt_signing_bytes(
            &group_id,
            author,
            seq,
            &content_hash,
            kind,
            &self.own_id,
        );
        let wire = GroupMessage::Receipt {
            author: author.clone(),
            seq,
            content_hash,
            kind,
            receiver: self.own_id.clone(),
            signature: signer(&signing),
        }
        .encode();
        match self.sessions.lock().unwrap().get(author) {
            Some(session) => session.send(&wire).map(|_| true),
            None => Ok(false),
        }
    }

    /// Give the hub a way to sign receipts. Without one, no receipts are
    /// sent (receiving and verifying them always works). The closure must
    /// sign with OUR identity key.
    pub fn set_receipt_signer(&self, signer: ReceiptSigner) {
        *self.receipt_signer.lock().unwrap() = Some(signer);
    }

    /// Convenience: sign receipts with `identity`.
    pub fn enable_receipts(&self, identity: Arc<Identity>) {
        self.set_receipt_signer(Arc::new(move |bytes| identity.sign(bytes).to_bytes()));
    }

    /// Tell `author` we READ their message `seq`. Does nothing (`Ok(false)`)
    /// unless read receipts are enabled in [`ReceiptSettings`], we hold the
    /// message, we have a signer, and the author is connected. Call it when
    /// your UI actually shows the message, not on arrival.
    pub fn mark_read(&self, author: &PeerId, seq: u64) -> Result<bool> {
        if !self.config.receipts.read || *author == self.own_id {
            return Ok(false);
        }
        self.send_receipt(author, seq, ReceiptKind::Read)
    }

    /// Receipts received for OUR message `seq`: who acknowledged it and how
    /// far (their strongest receipt), sorted by receiver id.
    pub fn receipts_for(&self, seq: u64) -> Vec<(PeerId, ReceiptKind)> {
        let mut v: Vec<_> = self
            .receipts
            .lock()
            .unwrap()
            .get(&seq)
            .map(|m| m.iter().map(|(p, k)| (p.clone(), *k)).collect())
            .unwrap_or_default();
        v.sort();
        v
    }

    /// What to send someone who asks us for a cached message by `author`:
    /// the full message, unless the group's policy is
    /// [`RelayPolicy::AuthorOnly`] and we are not the author, in which case
    /// only an existence notice (same signature, content replaced by hash).
    fn wire_for_requester(&self, author: &PeerId, cached: Vec<u8>) -> Vec<u8> {
        let author_only = self.roster.lock().unwrap().relay_policy() == RelayPolicy::AuthorOnly;
        if author_only && *author != self.own_id {
            GroupMessage::notice_from_application(&cached).unwrap_or(cached)
        } else {
            cached
        }
    }

    /// Ask for message `seq` from `author`, AUTHOR FIRST: sent over the
    /// author's session if we have one, otherwise to everyone attached
    /// (anyone holding it may answer, subject to the group's
    /// [`RelayPolicy`]). The answer arrives as a normal event. Errors if no
    /// session is attached at all.
    ///
    /// This never waits or retries (no timers in the library): if the author
    /// does not answer, the application decides when to give up and call
    /// [`GroupHub::fetch_from_anyone`].
    pub fn fetch(&self, author: &PeerId, seq: u64) -> Result<()> {
        let request = GroupMessage::FetchRequest {
            sender: author.clone(),
            seq,
        }
        .encode();
        let sessions = self.sessions.lock().unwrap();
        if let Some(s) = sessions.get(author) {
            return s.send(&request).map(|_| ());
        }
        if sessions.is_empty() {
            return Err(ChatError::ConnectionClosed);
        }
        for s in sessions.values() {
            let _ = s.send(&request);
        }
        Ok(())
    }

    /// The fallback half of [`GroupHub::fetch`]: ask EVERY attached peer,
    /// not just the author. Under [`RelayPolicy::AuthorOnly`] they will
    /// answer with notices only, so this helps only in open groups.
    pub fn fetch_from_anyone(&self, author: &PeerId, seq: u64) -> Result<()> {
        let request = GroupMessage::FetchRequest {
            sender: author.clone(),
            seq,
        }
        .encode();
        let sessions = self.sessions.lock().unwrap();
        if sessions.is_empty() {
            return Err(ChatError::ConnectionClosed);
        }
        for s in sessions.values() {
            let _ = s.send(&request);
        }
        Ok(())
    }

    /// Positions of `author`'s messages that we know exist but do not hold
    /// the content of, ascending. Pass each to [`GroupHub::fetch`].
    pub fn existence_only(&self, author: &PeerId) -> Vec<u64> {
        let mut v: Vec<u64> = self
            .pending_existence
            .lock()
            .unwrap()
            .keys()
            .filter(|(a, _)| a == author)
            .map(|(_, seq)| *seq)
            .collect();
        v.sort_unstable();
        v
    }

    /// If we accepted this message from someone other than its author, who
    /// handed it to us. `None` = it came straight from the author (or we
    /// do not hold it). Use it to warn "relayed by X".
    pub fn relayed_by(&self, author: &PeerId, seq: u64) -> Option<PeerId> {
        self.relayed_by
            .lock()
            .unwrap()
            .get(&(author.clone(), seq))
            .cloned()
    }

    /// The group's relay policy.
    pub fn relay_policy(&self) -> RelayPolicy {
        self.roster.lock().unwrap().relay_policy()
    }

    /// Park a message we cannot judge yet (see `pending_ahead`).
    fn defer(&self, from: PeerId, bytes: Vec<u8>) {
        let mut q = self.pending_ahead.lock().unwrap();
        if q.len() >= MAX_DEFERRED {
            q.remove(0); // drop the oldest rather than grow without bound
        }
        q.push((from, bytes));
    }

    /// Re-run every parked message; ones still ahead of us re-park themselves.
    fn retry_deferred(&self) {
        let parked = std::mem::take(&mut *self.pending_ahead.lock().unwrap());
        for (from, bytes) in parked {
            if let Some(event) = self.process_incoming(from, bytes) {
                let _ = self.event_tx.send(event);
            }
        }
    }

    /// The current, fully up-to-date message history from a given sender:
    /// `(seq, payload, was_edited, was_deleted)` tuples in order. A
    /// deleted message's payload is always empty (the content is dropped
    /// on deletion, not just hidden - see [`GroupHub::delete`]). This is
    /// what a UI would use to render a conversation, and what makes
    /// [`GroupHub::load_persisted`] actually useful: after replay, this
    /// reflects every post/edit/delete exactly as it stood before restart.
    pub fn history_for(&self, sender: &PeerId) -> Vec<(u64, Vec<u8>, bool, bool)> {
        self.message_store
            .lock()
            .unwrap()
            .get(sender)
            .map(|msgs| {
                msgs.iter()
                    .map(|(seq, m)| (*seq, m.payload.clone(), m.edited, m.deleted))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The group's permanent identifier.
    pub fn group_id(&self) -> GroupId {
        self.roster.lock().unwrap().group_id.clone()
    }

    /// Public keys of all current members.
    pub fn member_keys(&self) -> Vec<VerifyingKey> {
        self.roster.lock().unwrap().member_keys()
    }

    pub fn own_id(&self) -> &PeerId {
        &self.own_id
    }

    pub fn member_ids(&self) -> Vec<PeerId> {
        self.roster.lock().unwrap().member_ids()
    }

    pub fn is_member(&self, id: &PeerId) -> bool {
        self.roster.lock().unwrap().is_member(id)
    }

    /// The current tier assigned to `id`, if they're a member - useful for
    /// a UI to display alongside their fingerprint (e.g. "Alice - owner").
    pub fn tier_of(&self, id: &PeerId) -> Option<TierName> {
        self.roster.lock().unwrap().tier_of(id)
    }

    /// The current effective permissions for `id` (four booleans:
    /// add/remove/read/write) - what a UI would show as e.g. checkboxes or
    /// badges next to a member's name.
    pub fn permissions_of(&self, id: &PeerId) -> Permissions {
        self.roster.lock().unwrap().permissions_of(id)
    }

    /// Our own current effective permissions.
    pub fn my_permissions(&self) -> Permissions {
        self.permissions_of(&self.own_id)
    }

    /// The tip hash we've independently derived for a given sender's
    /// message history so far - compare across two `GroupHub`s on the same
    /// sender to detect equivocation.
    pub fn tip_hash_for(&self, sender: &PeerId) -> Option<[u8; 32]> {
        self.sender_chains
            .lock()
            .unwrap()
            .get(sender)
            .map(|c| c.tip_hash())
    }
}

impl SenderChainState {
    /// The seq we'd next expect from this sender, minus one - i.e. the
    /// highest position we've already validated. Used to build
    /// `RelayRequest.after_seq`.
    fn next_seq_hint(&self) -> u64 {
        self.next_seq.saturating_sub(1)
    }

    /// Snapshot the raw chain position - used to re-seed `OwnChainState`
    /// after replaying our own past messages during
    /// [`GroupHub::load_persisted`] (see there for why this is needed).
    fn snapshot(&self) -> (u64, [u8; 32]) {
        (self.next_seq, self.tip_hash)
    }
}

impl OwnChainState {
    /// Reset this chain to an exact prior position, e.g. reconstructed from
    /// replaying a persisted log. Only ever used at load time.
    fn seed_from(&mut self, next_seq: u64, tip_hash: [u8; 32]) {
        self.next_seq = next_seq;
        self.tip_hash = tip_hash;
    }
}

impl Roster {
    #[cfg(test)]
    fn member_key(&self, id: &PeerId) -> Option<VerifyingKey> {
        self.members.get(id).map(|m| m.key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Roster / tier genesis and mutation ----

    // ---- bots ----

    /// alice (owner) + bob (member), with an extra "bot" tier (read/write).
    fn bot_roster() -> (Roster, Identity, Identity) {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let (mut roster, _g) = Roster::genesis_default(&alice, vec![bob.public_key()]);
        let op = roster
            .propose_define_tier(&alice, "bot".into(), Permissions::READ_WRITE)
            .unwrap();
        roster.apply(&op).unwrap();
        (roster, alice, bob)
    }

    #[test]
    fn bot_is_marked_as_bot_with_its_sponsor() {
        let (mut roster, alice, _bob) = bot_roster();
        let bot = Identity::generate();
        let op = roster
            .propose_add_bot(&alice, bot.public_key(), "bot".into())
            .unwrap();
        roster.apply(&op).unwrap();
        let id = bot.fingerprint();
        assert!(roster.is_member(&id));
        assert_eq!(roster.kind_of(&id), Some(MemberKind::Bot));
        assert_eq!(roster.sponsor_of(&id), Some(alice.fingerprint()));
        assert_eq!(
            roster.kind_of(&alice.fingerprint()),
            Some(MemberKind::Person)
        );
    }

    #[test]
    fn bot_cannot_be_placed_in_a_tier_that_manages_membership() {
        let (roster, alice, _bob) = bot_roster();
        let bot = Identity::generate();
        // "owner" has can_add/can_remove: refused both when proposing...
        assert!(roster
            .propose_add_bot(&alice, bot.public_key(), "owner".into())
            .is_err());
        // ...and when a hostile proposer signs it by hand (apply re-checks).
        let forged = roster
            .propose(
                &alice,
                RosterOp::AddBot {
                    member: bot.public_key(),
                    tier: "owner".into(),
                },
            )
            .unwrap();
        let mut r2 = roster;
        assert!(matches!(
            r2.apply(&forged),
            Err(ChatError::PermissionDenied)
        ));
    }

    #[test]
    fn plain_member_cannot_add_a_bot() {
        let (roster, _alice, bob) = bot_roster();
        let bot = Identity::generate();
        assert!(roster
            .propose_add_bot(&bob, bot.public_key(), "bot".into())
            .is_err());
    }

    #[test]
    fn bot_can_never_be_promoted_to_a_managing_tier() {
        let (mut roster, alice, _bob) = bot_roster();
        let bot = Identity::generate();
        let op = roster
            .propose_add_bot(&alice, bot.public_key(), "bot".into())
            .unwrap();
        roster.apply(&op).unwrap();
        // Move to owner: denied.
        let promote = roster
            .propose_change_tier(&alice, bot.fingerprint(), "owner".into())
            .unwrap();
        assert!(matches!(
            roster.apply(&promote),
            Err(ChatError::PermissionDenied)
        ));
        // Redefine the bot tier to manage members: denied while a bot is in it.
        let widen = roster
            .propose_define_tier(&alice, "bot".into(), Permissions::FULL)
            .unwrap();
        assert!(matches!(
            roster.apply(&widen),
            Err(ChatError::PermissionDenied)
        ));
        assert_eq!(roster.kind_of(&bot.fingerprint()), Some(MemberKind::Bot));
    }

    #[test]
    fn re_adding_a_bot_as_a_person_is_refused() {
        let (mut roster, alice, _bob) = bot_roster();
        let bot = Identity::generate();
        let op = roster
            .propose_add_bot(&alice, bot.public_key(), "bot".into())
            .unwrap();
        roster.apply(&op).unwrap();
        let launder = roster
            .propose_add(&alice, bot.public_key(), "member".into())
            .unwrap();
        assert!(roster.apply(&launder).is_err());
        assert_eq!(roster.kind_of(&bot.fingerprint()), Some(MemberKind::Bot));
    }

    #[test]
    fn removing_the_sponsor_removes_their_bots_but_not_others() {
        let (mut roster, alice, bob) = bot_roster();
        // Bob needs can_add to sponsor: give him a tier for that.
        let t = roster
            .propose_define_tier(
                &alice,
                "mod".into(),
                Permissions {
                    can_add: true,
                    ..Permissions::READ_WRITE
                },
            )
            .unwrap();
        roster.apply(&t).unwrap();
        let c = roster
            .propose_change_tier(&alice, bob.fingerprint(), "mod".into())
            .unwrap();
        roster.apply(&c).unwrap();

        let (bob_bot, alice_bot) = (Identity::generate(), Identity::generate());
        let op = roster
            .propose_add_bot(&bob, bob_bot.public_key(), "bot".into())
            .unwrap();
        roster.apply(&op).unwrap();
        let op = roster
            .propose_add_bot(&alice, alice_bot.public_key(), "bot".into())
            .unwrap();
        roster.apply(&op).unwrap();

        let rm = roster.propose_remove(&alice, bob.fingerprint()).unwrap();
        roster.apply(&rm).unwrap();
        assert!(!roster.is_member(&bob.fingerprint()));
        assert!(
            !roster.is_member(&bob_bot.fingerprint()),
            "bob's bot goes with bob"
        );
        assert!(
            roster.is_member(&alice_bot.fingerprint()),
            "alice's bot stays"
        );
    }

    #[test]
    fn bot_op_survives_encode_decode() {
        let k = Identity::generate().public_key();
        let op = RosterOp::AddBot {
            member: k,
            tier: "bot".into(),
        };
        assert_eq!(RosterOp::decode(&op.encode()).unwrap(), op);
    }

    #[test]
    fn genesis_default_assigns_owner_to_creator_and_member_to_everyone_else() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let (roster, _genesis) = Roster::genesis_default(&alice, vec![bob.public_key()]);
        assert_eq!(
            roster.tier_of(&alice.fingerprint()),
            Some("owner".to_string())
        );
        assert_eq!(
            roster.tier_of(&bob.fingerprint()),
            Some("member".to_string())
        );
        assert_eq!(
            roster.permissions_of(&alice.fingerprint()),
            Permissions::FULL
        );
        assert_eq!(
            roster.permissions_of(&bob.fingerprint()),
            Permissions::READ_WRITE
        );
    }

    #[test]
    fn a_member_without_can_add_cannot_add_anyone() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let carol = Identity::generate();
        let (roster, _genesis) = Roster::genesis_default(&alice, vec![bob.public_key()]);
        // Bob is a plain "member" (READ_WRITE only, no can_add).
        let result = roster.propose_add(&bob, carol.public_key(), "member".to_string());
        assert!(matches!(result, Err(ChatError::PermissionDenied)));
    }

    #[test]
    fn owner_can_add_a_new_member_at_a_chosen_tier() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let carol = Identity::generate();
        let (mut roster, _genesis) = Roster::genesis_default(&alice, vec![bob.public_key()]);
        let add = roster
            .propose_add(&alice, carol.public_key(), "member".to_string())
            .unwrap();
        roster.apply(&add).unwrap();
        assert_eq!(
            roster.tier_of(&carol.fingerprint()),
            Some("member".to_string())
        );
    }

    #[test]
    fn a_member_can_always_remove_themselves_regardless_of_permissions() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let (mut roster, _genesis) = Roster::genesis_default(&alice, vec![bob.public_key()]);
        // Bob has no can_remove, but leaving is always allowed.
        let leave = roster.propose_remove(&bob, bob.fingerprint()).unwrap();
        roster.apply(&leave).unwrap();
        assert!(!roster.is_member(&bob.fingerprint()));
    }

    #[test]
    fn a_plain_member_cannot_remove_someone_else() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let carol = Identity::generate();
        let (roster, _genesis) =
            Roster::genesis_default(&alice, vec![bob.public_key(), carol.public_key()]);
        let result = roster.propose_remove(&bob, carol.fingerprint());
        assert!(matches!(result, Err(ChatError::PermissionDenied)));
    }

    #[test]
    fn owner_can_promote_a_member_to_a_new_tier() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let (mut roster, _genesis) = Roster::genesis_default(&alice, vec![bob.public_key()]);
        let promote = roster
            .propose_change_tier(&alice, bob.fingerprint(), "owner".to_string())
            .unwrap();
        roster.apply(&promote).unwrap();
        assert_eq!(roster.permissions_of(&bob.fingerprint()), Permissions::FULL);
    }

    #[test]
    fn a_plain_member_cannot_promote_anyone() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let carol = Identity::generate();
        let (roster, _genesis) =
            Roster::genesis_default(&alice, vec![bob.public_key(), carol.public_key()]);
        let result = roster.propose_change_tier(&bob, carol.fingerprint(), "owner".to_string());
        assert!(matches!(result, Err(ChatError::PermissionDenied)));
    }

    #[test]
    fn redefining_a_tier_immediately_changes_effective_permissions_for_everyone_in_it() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let (mut roster, _genesis) = Roster::genesis_default(&alice, vec![bob.public_key()]);
        assert!(roster.permissions_of(&bob.fingerprint()).can_write);

        // Owner revokes write access group-wide for the "member" tier -
        // e.g. switching the group to read-only announcements.
        let redefine = roster
            .propose_define_tier(
                &alice,
                "member".to_string(),
                Permissions {
                    can_add: false,
                    can_remove: false,
                    can_read: true,
                    can_write: false,
                },
            )
            .unwrap();
        roster.apply(&redefine).unwrap();

        assert!(!roster.permissions_of(&bob.fingerprint()).can_write);
        assert!(roster.permissions_of(&bob.fingerprint()).can_read);
    }

    #[test]
    fn cannot_add_a_member_to_an_undefined_tier() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let (mut roster, _genesis) = Roster::genesis_default(&alice, vec![]);
        let add = roster
            .propose_add(&alice, bob.public_key(), "nonexistent-tier".to_string())
            .unwrap();
        assert!(matches!(
            roster.apply(&add),
            Err(ChatError::MalformedMessage(_))
        ));
    }

    #[test]
    fn removed_member_permissions_drop_to_none() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let (mut roster, _genesis) = Roster::genesis_default(&alice, vec![bob.public_key()]);
        let remove = roster.propose_remove(&alice, bob.fingerprint()).unwrap();
        roster.apply(&remove).unwrap();
        assert_eq!(roster.permissions_of(&bob.fingerprint()), Permissions::NONE);
    }

    #[test]
    fn rejects_a_roster_op_that_forks_history() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let carol = Identity::generate();
        let (mut roster, _genesis) = Roster::genesis_default(&alice, vec![bob.public_key()]);
        let add = roster
            .propose_add(&alice, carol.public_key(), "member".to_string())
            .unwrap();
        roster.apply(&add).unwrap();
        // Replaying the same (now-stale) op fails: its prev_hash points at
        // a state the roster has already moved past.
        assert!(matches!(
            roster.apply(&add),
            Err(ChatError::RosterHistoryMismatch)
        ));
    }

    #[test]
    fn rejects_a_roster_op_with_a_tampered_signature() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let carol = Identity::generate();
        let (mut roster, _genesis) = Roster::genesis_default(&alice, vec![bob.public_key()]);
        let mut add = roster
            .propose_add(&alice, carol.public_key(), "member".to_string())
            .unwrap();
        add.op = RosterOp::Add {
            member: bob.public_key(),
            tier: "owner".to_string(),
        }; // tamper after signing
        assert!(matches!(
            roster.apply(&add),
            Err(ChatError::RosterSignatureInvalid)
        ));
    }

    #[test]
    fn a_non_member_cannot_even_build_a_valid_proposal() {
        // Non-members get `Permissions::NONE`, so `propose_add` fails via
        // the ordinary permission check - the same fail-closed path a
        // demoted member would hit, not a special case.
        let alice = Identity::generate();
        let mallory = Identity::generate();
        let (roster, _genesis) = Roster::genesis_default(&alice, vec![]);
        assert!(matches!(
            roster.propose_add(&mallory, alice.public_key(), "member".to_string()),
            Err(ChatError::PermissionDenied)
        ));
    }

    #[test]
    fn apply_independently_rejects_a_forged_op_from_a_non_member_even_if_injected_directly() {
        // This is the defense-in-depth check: even bypassing the safe
        // `propose_*` API entirely and hand-building a `SignedRosterOp`,
        // `apply` looks the proposer up in *its own* roster - a non-member
        // has no entry at all, which is `UnauthorizedRosterOp` specifically
        // (distinct from `PermissionDenied`, which is for members whose
        // tier just doesn't grant the permission).
        let alice = Identity::generate();
        let mallory = Identity::generate();
        let (mut roster, _genesis) = Roster::genesis_default(&alice, vec![]);
        let forged = SignedRosterOp {
            group_id: roster.group_id.clone(),
            version: roster.version() + 1,
            prev_hash: roster.tip_hash,
            op: RosterOp::Add {
                member: mallory.public_key(),
                tier: "member".to_string(),
            },
            proposer: mallory.fingerprint(),
            signature: mallory.sign(b"doesn't matter, rejected before signature check"),
        };
        assert!(matches!(
            roster.apply(&forged),
            Err(ChatError::UnauthorizedRosterOp)
        ));
    }

    // ---- GroupContent / GroupMessage wire encoding ----

    #[test]
    fn post_content_round_trips() {
        let content = GroupContent::Post {
            payload: b"hello".to_vec(),
        };
        assert_eq!(GroupContent::decode(&content.encode()).unwrap(), content);
    }

    #[test]
    fn edit_content_round_trips() {
        let content = GroupContent::Edit {
            target_seq: 3,
            new_payload: b"corrected".to_vec(),
        };
        assert_eq!(GroupContent::decode(&content.encode()).unwrap(), content);
    }

    #[test]
    fn delete_content_round_trips() {
        let content = GroupContent::Delete {
            target_sender: "abc123".to_string(),
            target_seq: 9,
        };
        assert_eq!(GroupContent::decode(&content.encode()).unwrap(), content);
    }

    #[test]
    fn application_message_round_trips() {
        let msg = GroupMessage::Application {
            sender: "deadbeef".to_string(),
            seq: 5,
            prev_hash: [7u8; 32],
            roster_version: 3,
            content: GroupContent::Post {
                payload: b"hi".to_vec(),
            },
            signature: [1u8; 64],
        };
        assert_eq!(GroupMessage::decode(&msg.encode()).unwrap(), msg);
    }

    #[test]
    fn relay_request_round_trips() {
        let msg = GroupMessage::RelayRequest {
            sender: "abc".to_string(),
            after_seq: 42,
        };
        assert_eq!(GroupMessage::decode(&msg.encode()).unwrap(), msg);
    }

    #[test]
    fn existence_and_fetch_messages_round_trip() {
        let n = GroupMessage::Existence {
            sender: "abc".into(),
            seq: 7,
            prev_hash: [1; 32],
            roster_version: 3,
            content_hash: [2; 32],
            signature: [3; 64],
        };
        assert_eq!(GroupMessage::decode(&n.encode()).unwrap(), n);
        let f = GroupMessage::FetchRequest {
            sender: "abc".into(),
            seq: 9,
        };
        assert_eq!(GroupMessage::decode(&f.encode()).unwrap(), f);
        for cut in 0..n.encode().len() {
            assert!(
                GroupMessage::decode(&n.encode()[..cut]).is_err(),
                "truncated at {cut}"
            );
        }
    }

    #[test]
    fn a_notice_made_from_a_message_verifies_but_a_tampered_one_does_not() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let (roster, _g) = Roster::genesis_default(&alice, vec![bob.public_key()]);
        let gid = roster.group_id.clone();
        let hub = GroupHub::with_config(
            &alice,
            roster,
            GroupHubConfig {
                auto_pump: false,
                ..Default::default()
            },
        );
        let full = signed_post(&bob, &gid, 1, [0u8; 32], 0, b"secret text");
        let notice = GroupMessage::notice_from_application(&full).unwrap();
        // The notice must not contain the content.
        assert!(!notice.windows(11).any(|w| w == b"secret text"));

        // Flip one bit of the content hash: the author's signature must fail.
        let mut bad = notice.clone();
        let idx = bad.len() - 64 - 1;
        bad[idx] ^= 1;
        hub.process_one(bob.fingerprint(), bad);
        assert!(hub.existence_only(&bob.fingerprint()).is_empty());

        hub.process_one(bob.fingerprint(), notice);
        assert_eq!(hub.existence_only(&bob.fingerprint()), vec![1]);
    }

    #[test]
    fn content_must_match_the_notice_it_fills() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let (roster, _g) = Roster::genesis_default(&alice, vec![bob.public_key()]);
        let gid = roster.group_id.clone();
        let hub = GroupHub::with_config(
            &alice,
            roster,
            GroupHubConfig {
                auto_pump: false,
                ..Default::default()
            },
        );
        let real = signed_post(&bob, &gid, 1, [0u8; 32], 0, b"what bob said");
        hub.process_one(
            bob.fingerprint(),
            GroupMessage::notice_from_application(&real).unwrap(),
        );
        assert_eq!(hub.existence_only(&bob.fingerprint()), vec![1]);

        // A different (even validly signed) message for the same position is refused.
        let other = signed_post(&bob, &gid, 1, [0u8; 32], 0, b"something else");
        hub.process_one(bob.fingerprint(), other);
        assert_eq!(hub.existence_only(&bob.fingerprint()), vec![1]);
        assert!(hub.history_for(&bob.fingerprint()).is_empty());

        // The real content fills it.
        hub.process_one(bob.fingerprint(), real);
        assert!(hub.existence_only(&bob.fingerprint()).is_empty());
        assert_eq!(hub.history_for(&bob.fingerprint())[0].1, b"what bob said");
    }

    #[test]
    fn a_notice_survives_restart_and_can_still_be_filled() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let (roster, genesis) = Roster::genesis_default(&alice, vec![bob.public_key()]);
        let gid = roster.group_id.clone();
        let store = Arc::new(crate::storage::MemoryEventStore::new());
        let cfg = || GroupHubConfig {
            auto_pump: false,
            ..Default::default()
        };
        let hub =
            GroupHub::create_with_store(&alice, roster, &genesis, store.clone(), cfg()).unwrap();
        let real = signed_post(&bob, &gid, 1, [0u8; 32], 0, b"later");
        hub.process_one(
            bob.fingerprint(),
            GroupMessage::notice_from_application(&real).unwrap(),
        );
        drop(hub);

        let hub = GroupHub::load_with_store(&alice, store, cfg()).unwrap();
        assert_eq!(
            hub.existence_only(&bob.fingerprint()),
            vec![1],
            "notice replayed"
        );
        hub.process_one(bob.fingerprint(), real);
        assert_eq!(hub.history_for(&bob.fingerprint())[0].1, b"later");
    }

    #[test]
    fn relay_policy_is_part_of_the_signed_genesis() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let mk = |p| {
            Roster::genesis_with_policy(
                &alice,
                GroupKind::FullMesh,
                p,
                vec![("owner".into(), Permissions::FULL)],
                vec![
                    (alice.public_key(), "owner".into()),
                    (bob.public_key(), "owner".into()),
                ],
            )
        };
        let (open, g_open) = mk(RelayPolicy::Open);
        let (only, g_only) = mk(RelayPolicy::AuthorOnly);
        assert_ne!(
            open.group_id, only.group_id,
            "policy is bound into the group id"
        );
        assert_eq!(
            Roster::from_genesis(&g_only).unwrap().relay_policy(),
            RelayPolicy::AuthorOnly
        );
        assert_eq!(
            Roster::from_genesis(&g_open).unwrap().relay_policy(),
            RelayPolicy::Open
        );
    }

    #[test]
    fn receipt_wire_round_trips() {
        let r = GroupMessage::Receipt {
            author: "a".into(),
            seq: 4,
            content_hash: [9; 32],
            kind: ReceiptKind::Read,
            receiver: "b".into(),
            signature: [7; 64],
        };
        assert_eq!(GroupMessage::decode(&r.encode()).unwrap(), r);
        for cut in 0..r.encode().len() {
            assert!(GroupMessage::decode(&r.encode()[..cut]).is_err());
        }
    }

    #[test]
    fn forged_or_mismatched_receipts_are_rejected() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let mallory = Identity::generate();
        let (roster, _g) = Roster::genesis_default(&alice, vec![bob.public_key()]);
        let gid = roster.group_id.clone();
        let hub = GroupHub::with_config(
            &alice,
            roster,
            GroupHubConfig {
                auto_pump: false,
                ..Default::default()
            },
        );
        let seq = hub.post(&alice, b"hello").unwrap();
        let hash: [u8; 32] = Sha256::digest(
            GroupContent::Post {
                payload: b"hello".to_vec(),
            }
            .encode(),
        )
        .into();
        let mk = |signer: &Identity, claimed: &Identity, h: [u8; 32]| {
            let sb = GroupMessage::receipt_signing_bytes(
                &gid,
                &alice.fingerprint(),
                seq,
                &h,
                ReceiptKind::Delivered,
                &claimed.fingerprint(),
            );
            GroupMessage::Receipt {
                author: alice.fingerprint(),
                seq,
                content_hash: h,
                kind: ReceiptKind::Delivered,
                receiver: claimed.fingerprint(),
                signature: signer.sign(&sb).to_bytes(),
            }
            .encode()
        };
        // Mallory signs but claims to be Bob.
        hub.process_one(bob.fingerprint(), mk(&mallory, &bob, hash));
        // Bob signs a receipt for different content than we sent.
        hub.process_one(bob.fingerprint(), mk(&bob, &bob, [1u8; 32]));
        assert!(hub.receipts_for(seq).is_empty());
        // A non-member (Mallory) acknowledging is also refused.
        hub.process_one(mallory.fingerprint(), mk(&mallory, &mallory, hash));
        assert!(hub.receipts_for(seq).is_empty());
        // The genuine one is accepted.
        hub.process_one(bob.fingerprint(), mk(&bob, &bob, hash));
        assert_eq!(
            hub.receipts_for(seq),
            vec![(bob.fingerprint(), ReceiptKind::Delivered)]
        );
    }

    #[test]
    fn receipts_survive_a_restart() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let (roster, genesis) = Roster::genesis_default(&alice, vec![bob.public_key()]);
        let gid = roster.group_id.clone();
        let store = Arc::new(crate::storage::MemoryEventStore::new());
        let cfg = || GroupHubConfig {
            auto_pump: false,
            ..Default::default()
        };
        let hub =
            GroupHub::create_with_store(&alice, roster, &genesis, store.clone(), cfg()).unwrap();
        let seq = hub.post(&alice, b"persist me").unwrap();
        let hash: [u8; 32] = Sha256::digest(
            GroupContent::Post {
                payload: b"persist me".to_vec(),
            }
            .encode(),
        )
        .into();
        let sb = GroupMessage::receipt_signing_bytes(
            &gid,
            &alice.fingerprint(),
            seq,
            &hash,
            ReceiptKind::Delivered,
            &bob.fingerprint(),
        );
        let wire = GroupMessage::Receipt {
            author: alice.fingerprint(),
            seq,
            content_hash: hash,
            kind: ReceiptKind::Delivered,
            receiver: bob.fingerprint(),
            signature: bob.sign(&sb).to_bytes(),
        }
        .encode();
        hub.process_one(bob.fingerprint(), wire);
        assert_eq!(hub.receipts_for(seq).len(), 1);
        drop(hub);
        let hub = GroupHub::load_with_store(&alice, store, cfg()).unwrap();
        assert_eq!(
            hub.receipts_for(seq),
            vec![(bob.fingerprint(), ReceiptKind::Delivered)]
        );
    }

    // ---- Sender chains ----

    /// Build the header bytes the chain hashes, for author "x" (tests only).
    fn hdr(seq: u64, prev: &[u8; 32], rv: u64, content: &[u8]) -> Vec<u8> {
        GroupMessage::header_bytes("x", seq, prev, rv, content)
    }

    #[test]
    fn sender_chain_accepts_a_consistent_sequence_of_content() {
        let mut chain = SenderChainState::new();
        let mut own = OwnChainState::new();
        let c1 = GroupContent::Post {
            payload: b"hello".to_vec(),
        }
        .encode();
        let (s1, p1) = own.next_header("x", 0, &c1);
        assert!(chain
            .verify_and_advance(s1, p1, 0, &hdr(s1, &p1, 0, &c1))
            .is_ok());
        let c2 = GroupContent::Post {
            payload: b"world".to_vec(),
        }
        .encode();
        let (s2, p2) = own.next_header("x", 0, &c2);
        assert!(chain
            .verify_and_advance(s2, p2, 0, &hdr(s2, &p2, 0, &c2))
            .is_ok());
    }

    #[test]
    fn sender_chain_rejects_reordered_or_mismatched_headers() {
        let mut own = OwnChainState::new();
        let c1 = GroupContent::Post {
            payload: b"hello".to_vec(),
        }
        .encode();
        let (_s1, _p1) = own.next_header("x", 0, &c1);
        let c2 = GroupContent::Post {
            payload: b"world".to_vec(),
        }
        .encode();
        let (s2, p2) = own.next_header("x", 0, &c2);

        let mut chain = SenderChainState::new();
        assert!(chain
            .verify_and_advance(s2, p2, 0, &hdr(s2, &p2, 0, &c2))
            .is_err()); // seq 2 before seq 1

        let mut chain2 = SenderChainState::new();
        let bogus = [0xAAu8; 32];
        assert!(chain2
            .verify_and_advance(1, bogus, 0, &hdr(1, &bogus, 0, &c1))
            .is_err()); // bogus prev_hash
    }

    #[test]
    fn sender_chain_rejects_a_roster_version_that_goes_backwards() {
        let mut own = OwnChainState::new();
        let mut chain = SenderChainState::new();
        let c = GroupContent::Post {
            payload: b"a".to_vec(),
        }
        .encode();
        let (s1, p1) = own.next_header("x", 5, &c);
        assert!(chain
            .verify_and_advance(s1, p1, 5, &hdr(s1, &p1, 5, &c))
            .is_ok());
        // Claiming an OLDER roster version later in the chain is backdating.
        let (s2, p2) = own.next_header("x", 3, &c);
        assert!(chain
            .verify_and_advance(s2, p2, 3, &hdr(s2, &p2, 3, &c))
            .is_err());
    }

    #[test]
    fn two_recipients_detect_equivocation_via_diverging_tip_hashes() {
        let mut own = OwnChainState::new();
        let c1 = GroupContent::Post {
            payload: b"meeting is at 5pm".to_vec(),
        }
        .encode();
        let (seq1, prev1) = own.next_header("x", 0, &c1);

        let mut alice_view = SenderChainState::new();
        let mut bob_view = SenderChainState::new();
        assert!(alice_view
            .verify_and_advance(seq1, prev1, 0, &hdr(seq1, &prev1, 0, &c1))
            .is_ok());
        // The sender shows Bob different content under the same position.
        let lie = GroupContent::Post {
            payload: b"meeting is at 6pm".to_vec(),
        }
        .encode();
        assert!(bob_view
            .verify_and_advance(seq1, prev1, 0, &hdr(seq1, &prev1, 0, &lie))
            .is_ok());

        assert_ne!(alice_view.tip_hash(), bob_view.tip_hash());
    }

    // ---- Group kind and roster history ----

    #[test]
    fn group_kind_is_part_of_genesis_and_survives_encoding() {
        let alice = Identity::generate();
        let (roster, genesis) = Roster::genesis_default(&alice, vec![]);
        assert_eq!(roster.kind(), GroupKind::FullMesh);
        let wire = RosterOpWire::from(&genesis);
        let rebuilt = Roster::from_genesis(&wire.to_signed().unwrap()).unwrap();
        assert_eq!(rebuilt.kind(), GroupKind::FullMesh);
        assert_eq!(rebuilt.group_id, roster.group_id);
    }

    #[test]
    fn an_unknown_group_kind_is_rejected() {
        let alice = Identity::generate();
        let (_r, genesis) = Roster::genesis_default(&alice, vec![]);
        let mut wire = RosterOpWire::from(&genesis);
        assert_eq!(wire.op_bytes[0], 0, "genesis tag");
        wire.op_bytes[1] = 0x7F; // kind byte
        assert!(wire.to_signed().is_err());
    }

    #[test]
    fn permissions_are_answerable_as_of_any_past_roster_version() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let (mut roster, _g) = Roster::genesis_default(&alice, vec![bob.public_key()]);
        let bob_id = bob.fingerprint();
        // v0: bob is a writer. v1: bob is removed.
        let remove = roster.propose_remove(&alice, bob_id.clone()).unwrap();
        roster.apply(&remove).unwrap();

        assert!(
            roster.permissions_at(0, &bob_id).unwrap().can_write,
            "bob could write at v0"
        );
        assert!(
            !roster.permissions_at(1, &bob_id).unwrap().can_write,
            "bob cannot at v1"
        );
        assert!(
            roster.permissions_at(2, &bob_id).is_none(),
            "v2 not reached: cannot judge"
        );
        // A removed member's key stays known so old messages still verify.
        assert!(roster.key_ever(&bob_id).is_some());
        assert!(!roster.is_member(&bob_id));
    }

    // ---- The core claim: authenticity survives relaying ----

    #[test]
    fn a_relayed_message_still_verifies_against_the_original_authors_key_not_the_relayers() {
        // This is the pure-data-structure proof of the mechanism
        // GroupHub relies on: X signs a message; the bytes get handed off
        // by some other party Y (simulated here by just... not involving Y
        // at all past "here are the bytes"); Z verifies purely against X's
        // pinned public key from the roster. Nothing about Y - who Y is,
        // whether Y is even a real session - factors into the check.
        let x = Identity::generate();
        let y = Identity::generate(); // the relayer - deliberately unused for verification
        let z_alice = Identity::generate();
        let _ = &y;

        let (roster, _genesis) =
            Roster::genesis_default(&x, vec![y.public_key(), z_alice.public_key()]);

        // X authors one message.
        let mut x_chain = OwnChainState::new();
        let content = GroupContent::Post {
            payload: b"the launch code is 4-8-15-16-23-42".to_vec(),
        };
        let content_bytes = content.encode();
        let sender = x.fingerprint();
        let (seq, prev_hash) = x_chain.next_header(&sender, 0, &content_bytes);
        let signing_bytes =
            GroupMessage::signing_bytes(&roster.group_id, &sender, seq, &prev_hash, 0, &content);
        let signature = x.sign(&signing_bytes).to_bytes();

        let wire = GroupMessage::Application {
            sender: sender.clone(),
            seq,
            prev_hash,
            roster_version: 0,
            content: content.clone(),
            signature,
        }
        .encode();

        // "Y relays it" is modeled as simply: these exact bytes arrive at Z
        // with no involvement from Y's identity whatsoever.
        let decoded = GroupMessage::decode(&wire).unwrap();
        let GroupMessage::Application {
            sender: decoded_sender,
            seq: decoded_seq,
            prev_hash: decoded_prev,
            roster_version: decoded_rv,
            content: decoded_content,
            signature: decoded_sig,
        } = decoded
        else {
            panic!("expected an application message");
        };

        // Z verifies using X's key, looked up from the (shared, signed)
        // roster - never touching anything belonging to Y.
        let author_key = roster
            .member_key(&decoded_sender)
            .expect("X is a roster member");
        let expected_signing_bytes = GroupMessage::signing_bytes(
            &roster.group_id,
            &decoded_sender,
            decoded_seq,
            &decoded_prev,
            decoded_rv,
            &decoded_content,
        );
        let sig = Signature::from_slice(&decoded_sig).unwrap();
        assert!(PeerRegistry::verify_signature(&author_key, &expected_signing_bytes, &sig).is_ok());
        assert_eq!(decoded_sender, x.fingerprint());
        assert_eq!(decoded_content, content);

        // And tampering with the relayed content (imagine a malicious Y
        // trying to alter what X said while forwarding it) is caught,
        // because the signature covers the content itself.
        let GroupContent::Post { payload } = &decoded_content else {
            unreachable!()
        };
        let tampered_content = GroupContent::Post {
            payload: [payload.as_slice(), b" (tampered by Y)"].concat(),
        };
        let tampered_signing_bytes = GroupMessage::signing_bytes(
            &roster.group_id,
            &decoded_sender,
            decoded_seq,
            &decoded_prev,
            decoded_rv,
            &tampered_content,
        );
        assert!(
            PeerRegistry::verify_signature(&author_key, &tampered_signing_bytes, &sig).is_err()
        );
    }

    // ---- Permission checks are "as of the author's signed roster version" ----

    /// Build the wire bytes for a signed post, exactly as an author's hub would.
    fn signed_post(
        author: &Identity,
        group_id: &str,
        seq: u64,
        prev: [u8; 32],
        rv: u64,
        text: &[u8],
    ) -> Vec<u8> {
        let content = GroupContent::Post {
            payload: text.to_vec(),
        };
        let sender = author.fingerprint();
        let sig = author
            .sign(&GroupMessage::signing_bytes(
                group_id, &sender, seq, &prev, rv, &content,
            ))
            .to_bytes();
        GroupMessage::Application {
            sender,
            seq,
            prev_hash: prev,
            roster_version: rv,
            content,
            signature: sig,
        }
        .encode()
    }

    fn manual_hub(me: &Identity, roster: Roster) -> Arc<GroupHub> {
        GroupHub::with_config(
            me,
            roster,
            GroupHubConfig {
                auto_pump: false,
                ..Default::default()
            },
        )
    }

    #[test]
    fn rejections_and_acceptances_are_traced() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let outsider = Identity::generate();
        let (roster, _g) = Roster::genesis_default(&alice, vec![bob.public_key()]);
        let gid = roster.group_id.clone();
        let tr = crate::trace::CollectingTracer::new();
        let hub = GroupHub::with_config(
            &alice,
            roster,
            GroupHubConfig {
                auto_pump: false,
                tracer: tr.clone(),
                ..Default::default()
            },
        );
        hub.process_one(bob.fingerprint(), vec![0xFF, 1, 2, 3]);
        assert!(tr.any(|e| matches!(
            e,
            TraceEvent::GroupMessageRejected {
                reason: "undecodable",
                ..
            }
        )));
        hub.process_one(
            bob.fingerprint(),
            signed_post(&outsider, &gid, 1, [0u8; 32], 0, b"x"),
        );
        assert!(tr.any(|e| matches!(
            e,
            TraceEvent::GroupMessageRejected {
                reason: "unknown author",
                ..
            }
        )));
        hub.process_one(
            bob.fingerprint(),
            signed_post(&bob, &gid, 1, [0u8; 32], 0, b"x"),
        );
        assert!(tr.any(|e| matches!(e, TraceEvent::GroupMessageAccepted { seq: 1, .. })));
    }

    #[test]
    fn a_message_signed_before_the_authors_removal_is_still_accepted_afterwards() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let (roster, genesis) = Roster::genesis_default(&alice, vec![bob.public_key()]);
        let gid = roster.group_id.clone();
        let hub = manual_hub(&alice, roster);
        hub.propose_remove(&alice, bob.fingerprint()).unwrap(); // hub is now at v1

        // Bob signed this while he was still a writer (roster v0). It reaches
        // us late, after his removal: judged as of v0, it is legitimate.
        let wire = signed_post(&bob, &gid, 1, [0u8; 32], 0, b"sent before removal");
        hub.process_one(alice.fingerprint(), wire);
        let h = hub.history_for(&bob.fingerprint());
        assert_eq!(h.len(), 1);
        assert_eq!(h[0].1, b"sent before removal");
        let _ = genesis;
    }

    #[test]
    fn a_message_claiming_a_version_after_the_authors_removal_is_rejected() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let (roster, _g) = Roster::genesis_default(&alice, vec![bob.public_key()]);
        let gid = roster.group_id.clone();
        let hub = manual_hub(&alice, roster);
        hub.propose_remove(&alice, bob.fingerprint()).unwrap(); // v1

        let wire = signed_post(&bob, &gid, 1, [0u8; 32], 1, b"posted after removal");
        hub.process_one(alice.fingerprint(), wire);
        assert!(hub.history_for(&bob.fingerprint()).is_empty());
    }

    #[test]
    fn a_message_from_a_version_we_have_not_reached_waits_then_is_delivered() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let carol = Identity::generate();
        let (mut roster_a, genesis) = Roster::genesis_default(&alice, vec![bob.public_key()]);
        let gid = roster_a.group_id.clone();
        // Our hub knows only genesis (v0); alice has since added carol (v1).
        let hub = manual_hub(&alice, Roster::from_genesis(&genesis).unwrap());
        let add = roster_a
            .propose_add(&alice, carol.public_key(), "member".to_string())
            .unwrap();
        roster_a.apply(&add).unwrap();

        // Bob (who has seen v1) posts claiming v1. We cannot judge it yet.
        let wire = signed_post(&bob, &gid, 1, [0u8; 32], 1, b"hello from the future");
        hub.process_one(bob.fingerprint(), wire);
        assert!(
            hub.history_for(&bob.fingerprint()).is_empty(),
            "must not be accepted before we reach v1"
        );

        // The missing roster op arrives; the parked message is now delivered.
        hub.process_one(
            alice.fingerprint(),
            GroupMessage::Roster(RosterOpWire::from(&add)).encode(),
        );
        let h = hub.history_for(&bob.fingerprint());
        assert_eq!(
            h.len(),
            1,
            "parked message must be retried after the op applies"
        );
        assert_eq!(h[0].1, b"hello from the future");
    }

    #[test]
    fn deferred_messages_are_bounded() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let (roster, _g) = Roster::genesis_default(&alice, vec![bob.public_key()]);
        let gid = roster.group_id.clone();
        let hub = manual_hub(&alice, roster);
        for i in 0..(MAX_DEFERRED as u64 + 50) {
            hub.process_one(
                bob.fingerprint(),
                signed_post(&bob, &gid, i + 1, [0u8; 32], 9_999, b"x"),
            );
        }
        assert!(hub.pending_ahead.lock().unwrap().len() <= MAX_DEFERRED);
    }
}
