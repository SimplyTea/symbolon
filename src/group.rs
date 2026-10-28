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
    pub const NONE: Permissions = Permissions { can_add: false, can_remove: false, can_read: false, can_write: false };
    /// Read + write, but no membership-management rights - a typical
    /// baseline "member" tier.
    pub const READ_WRITE: Permissions = Permissions { can_add: false, can_remove: false, can_read: true, can_write: true };
    /// Every permission - a typical "owner"/founder tier.
    pub const FULL: Permissions = Permissions { can_add: true, can_remove: true, can_read: true, can_write: true };

    fn to_byte(self) -> u8 {
        (self.can_add as u8) | ((self.can_remove as u8) << 1) | ((self.can_read as u8) << 2) | ((self.can_write as u8) << 3)
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

/// A member's public key plus their currently-assigned tier.
#[derive(Clone)]
struct MemberInfo {
    key: VerifyingKey,
    tier: TierName,
}

/// One proposed change to group membership or tier structure. Carries no
/// signature itself - see [`SignedRosterOp`] for the authenticated envelope
/// that actually gets applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RosterOp {
    /// Found a brand new group with this exact initial membership and tier
    /// structure. Only ever valid as the very first operation in a group's
    /// history.
    Genesis { tiers: Vec<(TierName, Permissions)>, members: Vec<(VerifyingKey, TierName)> },
    /// Add a new member at a given tier. Requires the proposer's current
    /// tier to have `can_add`.
    Add { member: VerifyingKey, tier: TierName },
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
    DefineTier { name: TierName, permissions: Permissions },
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
            RosterOp::Genesis { tiers, members } => {
                let mut out = vec![0u8];
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
                let tier_count = read_u16(&mut cursor)? as usize;
                let mut tiers = Vec::with_capacity(tier_count);
                for _ in 0..tier_count {
                    let name_len = read_u16(&mut cursor)? as usize;
                    let name = String::from_utf8(take(&mut cursor, name_len)?).map_err(|_| ChatError::MalformedMessage("bad tier name"))?;
                    let perm_byte = take(&mut cursor, 1)?[0];
                    tiers.push((name, Permissions::from_byte(perm_byte)));
                }
                let member_count = read_u16(&mut cursor)? as usize;
                let mut members = Vec::with_capacity(member_count);
                for _ in 0..member_count {
                    let key_bytes: [u8; 32] = take(&mut cursor, 32)?.try_into().unwrap();
                    let key = VerifyingKey::from_bytes(&key_bytes).map_err(|_| ChatError::InvalidPublicKey)?;
                    let tier_len = read_u16(&mut cursor)? as usize;
                    let tier = String::from_utf8(take(&mut cursor, tier_len)?).map_err(|_| ChatError::MalformedMessage("bad member tier"))?;
                    members.push((key, tier));
                }
                Ok(RosterOp::Genesis { tiers, members })
            }
            1 => {
                let key_bytes: [u8; 32] = take(&mut cursor, 32)?.try_into().unwrap();
                let member = VerifyingKey::from_bytes(&key_bytes).map_err(|_| ChatError::InvalidPublicKey)?;
                let tier_len = read_u16(&mut cursor)? as usize;
                let tier = String::from_utf8(take(&mut cursor, tier_len)?).map_err(|_| ChatError::MalformedMessage("bad tier"))?;
                Ok(RosterOp::Add { member, tier })
            }
            2 => {
                let target_len = read_u16(&mut cursor)? as usize;
                let target = String::from_utf8(take(&mut cursor, target_len)?).map_err(|_| ChatError::MalformedMessage("bad target"))?;
                Ok(RosterOp::Remove { target })
            }
            3 => {
                let target_len = read_u16(&mut cursor)? as usize;
                let target = String::from_utf8(take(&mut cursor, target_len)?).map_err(|_| ChatError::MalformedMessage("bad target"))?;
                let tier_len = read_u16(&mut cursor)? as usize;
                let new_tier = String::from_utf8(take(&mut cursor, tier_len)?).map_err(|_| ChatError::MalformedMessage("bad tier"))?;
                Ok(RosterOp::ChangeTier { target, new_tier })
            }
            4 => {
                let name_len = read_u16(&mut cursor)? as usize;
                let name = String::from_utf8(take(&mut cursor, name_len)?).map_err(|_| ChatError::MalformedMessage("bad tier name"))?;
                let perm_byte = take(&mut cursor, 1)?[0];
                Ok(RosterOp::DefineTier { name, permissions: Permissions::from_byte(perm_byte) })
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
        out.extend_from_slice(b"p2p-group-roster-op-v1");
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
    members: HashMap<PeerId, MemberInfo>,
    tiers: HashMap<TierName, Permissions>,
    version: u64,
    tip_hash: [u8; 32],
}

impl Roster {
    /// Found a new group with an explicit tier structure and initial
    /// membership. `creator` signs the genesis operation, and must appear
    /// in `members`.
    pub fn genesis(creator: &Identity, tiers: Vec<(TierName, Permissions)>, members: Vec<(VerifyingKey, TierName)>) -> (Roster, SignedRosterOp) {
        let mut hasher = Sha256::new();
        hasher.update(b"p2p-group-id-v1");
        hasher.update(creator.public_key().as_bytes());
        let mut fingerprints: Vec<PeerId> = members.iter().map(|(k, _)| fingerprint(k)).collect();
        fingerprints.sort();
        for fp in &fingerprints {
            hasher.update(fp.as_bytes());
        }
        let group_id: GroupId = hex_encode(&hasher.finalize());

        let op = RosterOp::Genesis { tiers: tiers.clone(), members: members.clone() };
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

        let mut roster = Roster { group_id, members: HashMap::new(), tiers: HashMap::new(), version: 0, tip_hash: prev_hash };
        for (name, perms) in tiers {
            roster.tiers.insert(name, perms);
        }
        for (key, tier) in members {
            roster.members.insert(fingerprint(&key), MemberInfo { key, tier });
        }
        roster.tip_hash = tip_after(&prev_hash, &signed);

        (roster, signed)
    }

    /// Convenience genesis for the common two-tier case: the creator gets
    /// a `"owner"` tier with [`Permissions::FULL`], everyone else gets a
    /// `"member"` tier with [`Permissions::READ_WRITE`]. Equivalent to
    /// calling [`Roster::genesis`] directly with that tier structure - just
    /// saves callers from writing it out every time.
    pub fn genesis_default(creator: &Identity, other_members: Vec<VerifyingKey>) -> (Roster, SignedRosterOp) {
        let tiers = vec![("owner".to_string(), Permissions::FULL), ("member".to_string(), Permissions::READ_WRITE)];
        let mut members = vec![(creator.public_key(), "owner".to_string())];
        for m in other_members {
            members.push((m, "member".to_string()));
        }
        Roster::genesis(creator, tiers, members)
    }

    /// Reconstruct a roster purely from a trusted genesis op.
    pub fn from_genesis(signed: &SignedRosterOp) -> Result<Roster> {
        let RosterOp::Genesis { tiers, members } = &signed.op else {
            return Err(ChatError::MalformedMessage("expected a genesis roster op"));
        };
        if signed.version != 0 || signed.prev_hash != [0u8; 32] {
            return Err(ChatError::MalformedMessage("genesis op must be version 0 with a zero prev_hash"));
        }
        let creator_key = members
            .iter()
            .find(|(m, _)| fingerprint(m) == signed.proposer)
            .map(|(m, _)| m)
            .ok_or(ChatError::UnauthorizedRosterOp)?;
        let signing_bytes = SignedRosterOp::signing_bytes(&signed.group_id, 0, &signed.prev_hash, &signed.op);
        PeerRegistry::verify_signature(creator_key, &signing_bytes, &signed.signature).map_err(|_| ChatError::RosterSignatureInvalid)?;

        let mut roster = Roster { group_id: signed.group_id.clone(), members: HashMap::new(), tiers: HashMap::new(), version: 0, tip_hash: [0u8; 32] };
        for (name, perms) in tiers {
            roster.tiers.insert(name.clone(), *perms);
        }
        for (key, tier) in members {
            roster.members.insert(fingerprint(key), MemberInfo { key: *key, tier: tier.clone() });
        }
        roster.tip_hash = tip_after(&[0u8; 32], signed);
        Ok(roster)
    }

    /// Apply a signed roster operation. Fails closed on: signature failure,
    /// history mismatch (stale or forked), unknown proposer, or the
    /// proposer's tier not granting the permission the operation requires.
    pub fn apply(&mut self, signed: &SignedRosterOp) -> Result<()> {
        if signed.group_id != self.group_id {
            return Err(ChatError::MalformedMessage("roster op is for a different group"));
        }
        if signed.version != self.version + 1 || signed.prev_hash != self.tip_hash {
            return Err(ChatError::RosterHistoryMismatch);
        }
        let proposer_info = self.members.get(&signed.proposer).ok_or(ChatError::UnauthorizedRosterOp)?;
        let proposer_key = proposer_info.key;
        let proposer_perms = self.tiers.get(&proposer_info.tier).copied().unwrap_or(Permissions::NONE);

        let signing_bytes = SignedRosterOp::signing_bytes(&signed.group_id, signed.version, &signed.prev_hash, &signed.op);
        PeerRegistry::verify_signature(&proposer_key, &signing_bytes, &signed.signature).map_err(|_| ChatError::RosterSignatureInvalid)?;

        match &signed.op {
            RosterOp::Genesis { .. } => return Err(ChatError::MalformedMessage("genesis op can't be applied twice")),
            RosterOp::Add { member, tier } => {
                if !proposer_perms.can_add {
                    return Err(ChatError::PermissionDenied);
                }
                if !self.tiers.contains_key(tier) {
                    return Err(ChatError::MalformedMessage("cannot add a member to an undefined tier"));
                }
                self.members.insert(fingerprint(member), MemberInfo { key: *member, tier: tier.clone() });
            }
            RosterOp::Remove { target } => {
                let self_removal = *target == signed.proposer;
                if !self_removal && !proposer_perms.can_remove {
                    return Err(ChatError::PermissionDenied);
                }
                self.members.remove(target);
            }
            RosterOp::ChangeTier { target, new_tier } => {
                if !(proposer_perms.can_add && proposer_perms.can_remove) {
                    return Err(ChatError::PermissionDenied);
                }
                if !self.tiers.contains_key(new_tier) {
                    return Err(ChatError::MalformedMessage("cannot move a member to an undefined tier"));
                }
                let member = self.members.get_mut(target).ok_or(ChatError::MalformedMessage("change-tier target is not a member"))?;
                member.tier = new_tier.clone();
            }
            RosterOp::DefineTier { name, permissions } => {
                if !(proposer_perms.can_add && proposer_perms.can_remove) {
                    return Err(ChatError::PermissionDenied);
                }
                self.tiers.insert(name.clone(), *permissions);
            }
        }
        self.version += 1;
        self.tip_hash = tip_after(&signed.prev_hash, signed);
        Ok(())
    }

    fn propose(&self, proposer: &Identity, op: RosterOp) -> Result<SignedRosterOp> {
        let version = self.version + 1;
        let signing_bytes = SignedRosterOp::signing_bytes(&self.group_id, version, &self.tip_hash, &op);
        let signature = proposer.sign(&signing_bytes);
        Ok(SignedRosterOp { group_id: self.group_id.clone(), version, prev_hash: self.tip_hash, op, proposer: proposer.fingerprint(), signature })
    }

    /// Build (but don't apply) a signed op proposing to add `member` at
    /// `tier`. `proposer` must currently have `can_add` - checked here so
    /// mistakes are caught immediately, and independently re-checked by
    /// every recipient's [`Roster::apply`].
    pub fn propose_add(&self, proposer: &Identity, member: VerifyingKey, tier: TierName) -> Result<SignedRosterOp> {
        if !self.permissions_of(&proposer.fingerprint()).can_add {
            return Err(ChatError::PermissionDenied);
        }
        self.propose(proposer, RosterOp::Add { member, tier })
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
    pub fn propose_change_tier(&self, proposer: &Identity, target: PeerId, new_tier: TierName) -> Result<SignedRosterOp> {
        let perms = self.permissions_of(&proposer.fingerprint());
        if !(perms.can_add && perms.can_remove) {
            return Err(ChatError::PermissionDenied);
        }
        self.propose(proposer, RosterOp::ChangeTier { target, new_tier })
    }

    /// Build (but don't apply) a signed op defining/redefining a tier.
    pub fn propose_define_tier(&self, proposer: &Identity, name: TierName, permissions: Permissions) -> Result<SignedRosterOp> {
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
}

impl Default for SenderChainState {
    fn default() -> Self {
        SenderChainState { next_seq: 1, tip_hash: [0u8; 32] }
    }
}

impl SenderChainState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn verify_and_advance(&mut self, seq: u64, claimed_prev_hash: [u8; 32], content_bytes: &[u8]) -> Result<()> {
        if seq != self.next_seq || claimed_prev_hash != self.tip_hash {
            return Err(ChatError::SenderChainBroken);
        }
        let mut hasher = Sha256::new();
        hasher.update(self.tip_hash);
        hasher.update(content_bytes);
        self.tip_hash = hasher.finalize().into();
        self.next_seq += 1;
        Ok(())
    }

    pub fn tip_hash(&self) -> [u8; 32] {
        self.tip_hash
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
        OwnChainState { next_seq: 1, tip_hash: [0u8; 32] }
    }

    pub fn next_header(&mut self, content_bytes: &[u8]) -> (u64, [u8; 32]) {
        let seq = self.next_seq;
        let prev_hash = self.tip_hash;
        let mut hasher = Sha256::new();
        hasher.update(self.tip_hash);
        hasher.update(content_bytes);
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
    Post { payload: Vec<u8> },
    Edit { target_seq: u64, new_payload: Vec<u8> },
    Delete { target_sender: PeerId, target_seq: u64 },
}

impl GroupContent {
    fn encode(&self) -> Vec<u8> {
        match self {
            GroupContent::Post { payload } => {
                let mut out = vec![0u8];
                out.extend_from_slice(payload);
                out
            }
            GroupContent::Edit { target_seq, new_payload } => {
                let mut out = vec![1u8];
                out.extend_from_slice(&target_seq.to_be_bytes());
                out.extend_from_slice(new_payload);
                out
            }
            GroupContent::Delete { target_sender, target_seq } => {
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
            0 => Ok(GroupContent::Post { payload: cursor.to_vec() }),
            1 => {
                let target_seq = read_u64(&mut cursor)?;
                Ok(GroupContent::Edit { target_seq, new_payload: cursor.to_vec() })
            }
            2 => {
                let len = read_u16(&mut cursor)? as usize;
                let target_sender = String::from_utf8(take(&mut cursor, len)?).map_err(|_| ChatError::MalformedMessage("bad target sender"))?;
                let target_seq = read_u64(&mut cursor)?;
                Ok(GroupContent::Delete { target_sender, target_seq })
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
    Application { sender: PeerId, seq: u64, prev_hash: [u8; 32], content: GroupContent, signature: [u8; 64] },
    Roster(RosterOpWire),
    /// "Please resend anything you have cached from `sender` after
    /// `after_seq`." Broadcast by anyone who's just (re)connected and wants
    /// to catch up - answerable by *any* member who has it cached, not just
    /// `sender` themselves.
    RelayRequest { sender: PeerId, after_seq: u64 },
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
        let signature = Signature::from_slice(&self.signature_bytes).map_err(|_| ChatError::MalformedMessage("bad roster signature encoding"))?;
        Ok(SignedRosterOp { group_id: self.group_id.clone(), version: self.version, prev_hash: self.prev_hash, op, proposer: self.proposer.clone(), signature })
    }
}

const TAG_APPLICATION: u8 = 0x10;
const TAG_ROSTER: u8 = 0x11;
const TAG_RELAY_REQUEST: u8 = 0x12;

impl GroupMessage {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            GroupMessage::Application { sender, seq, prev_hash, content, signature } => {
                let mut out = vec![TAG_APPLICATION];
                let sender_bytes = sender.as_bytes();
                out.extend_from_slice(&(sender_bytes.len() as u16).to_be_bytes());
                out.extend_from_slice(sender_bytes);
                out.extend_from_slice(&seq.to_be_bytes());
                out.extend_from_slice(prev_hash);
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
                let sender = String::from_utf8(take(&mut cursor, sender_len)?).map_err(|_| ChatError::MalformedMessage("bad sender id"))?;
                let seq = read_u64(&mut cursor)?;
                let prev_hash: [u8; 32] = take(&mut cursor, 32)?.try_into().unwrap();
                let content_len = read_u32(&mut cursor)? as usize;
                let content_bytes = take(&mut cursor, content_len)?;
                let content = GroupContent::decode(&content_bytes)?;
                let signature: [u8; 64] = take(&mut cursor, 64)?.try_into().unwrap();
                Ok(GroupMessage::Application { sender, seq, prev_hash, content, signature })
            }
            TAG_ROSTER => {
                let gid_len = read_u16(&mut cursor)? as usize;
                let group_id = String::from_utf8(take(&mut cursor, gid_len)?).map_err(|_| ChatError::MalformedMessage("bad group id"))?;
                let version = read_u64(&mut cursor)?;
                let prev_hash: [u8; 32] = take(&mut cursor, 32)?.try_into().unwrap();
                let op_len = read_u32(&mut cursor)? as usize;
                let op_bytes = take(&mut cursor, op_len)?;
                let proposer_len = read_u16(&mut cursor)? as usize;
                let proposer = String::from_utf8(take(&mut cursor, proposer_len)?).map_err(|_| ChatError::MalformedMessage("bad proposer id"))?;
                let signature_bytes: [u8; 64] = take(&mut cursor, 64)?.try_into().unwrap();
                Ok(GroupMessage::Roster(RosterOpWire { group_id, version, prev_hash, op_bytes, proposer, signature_bytes }))
            }
            TAG_RELAY_REQUEST => {
                let sender_len = read_u16(&mut cursor)? as usize;
                let sender = String::from_utf8(take(&mut cursor, sender_len)?).map_err(|_| ChatError::MalformedMessage("bad sender id"))?;
                let after_seq = read_u64(&mut cursor)?;
                Ok(GroupMessage::RelayRequest { sender, after_seq })
            }
            _ => Err(ChatError::MalformedMessage("unknown group message tag")),
        }
    }

    fn signing_bytes(group_id: &str, sender: &str, seq: u64, prev_hash: &[u8; 32], content: &GroupContent) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"p2p-group-application-v1");
        out.extend_from_slice(group_id.as_bytes());
        out.extend_from_slice(sender.as_bytes());
        out.extend_from_slice(&seq.to_be_bytes());
        out.extend_from_slice(prev_hash);
        out.extend_from_slice(&content.encode());
        out
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
    Message { sender: PeerId, seq: u64, payload: Vec<u8> },
    /// `author`'s message at `seq` was edited (always by `author`
    /// themselves - see module docs on why edits are self-only).
    MessageEdited { author: PeerId, seq: u64, new_payload: Vec<u8> },
    /// `author`'s message at `seq` was deleted, either by `author`
    /// themselves or by a moderator (`deleted_by` tells you which).
    MessageDeleted { author: PeerId, seq: u64, deleted_by: PeerId },
    /// The roster (membership or tier structure) changed.
    MembershipChanged { members: Vec<PeerId> },
}

struct StoredMessage {
    payload: Vec<u8>,
    edited: bool,
    deleted: bool,
}

/// Tunable knobs for a [`GroupHub`].
#[derive(Clone, Debug)]
pub struct GroupHubConfig {
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
        GroupHubConfig { relay_cache_capacity_per_sender: 256, auto_pump: true }
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
    log: Option<Arc<crate::persistence::EventLog>>,
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
    hk.expand(b"p2p-group-storage-key-v1", &mut out).expect("32 bytes is a valid HKDF output length");
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
    pub fn with_config(own_identity: &Identity, roster: Roster, config: GroupHubConfig) -> Arc<GroupHub> {
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
        let key = derive_storage_key(own_identity);
        let log = crate::persistence::EventLog::open_encrypted(log_path, key)?;
        log.append(&GroupMessage::Roster(RosterOpWire::from(genesis)).encode())?;
        log.sync()?;
        Ok(Self::build(own_identity, roster, config, Some(Arc::new(log))))
    }

    /// Reopen a group previously created with [`GroupHub::create_persisted`],
    /// replaying its encrypted log (genesis, then every subsequent roster
    /// op and application message) through the exact same validation logic
    /// used for live traffic to fully reconstruct membership, tiers, sender
    /// chains, and message history - before any new sessions are attached.
    pub fn load_persisted(own_identity: &Identity, log_path: &std::path::Path, config: GroupHubConfig) -> Result<Arc<GroupHub>> {
        let key = derive_storage_key(own_identity);
        let records = crate::persistence::EventLog::read_all(log_path, Some(&key))?;
        let (first, rest) = records.split_first().ok_or(ChatError::MalformedMessage("persisted group log is empty"))?;

        let GroupMessage::Roster(genesis_wire) = GroupMessage::decode(first)? else {
            return Err(ChatError::MalformedMessage("persisted log does not start with a genesis roster op"));
        };
        let genesis = genesis_wire.to_signed()?;
        let roster = Roster::from_genesis(&genesis)?;

        let log = crate::persistence::EventLog::open_encrypted(log_path, key)?;
        let hub = Self::build(own_identity, roster, config, Some(Arc::new(log)));

        hub.replaying.store(true, std::sync::atomic::Ordering::SeqCst);
        for record in rest {
            // Replayed records were already validated once (that's how
            // they got persisted in the first place); re-running them
            // through `process_incoming` here reconstructs sender chains,
            // the message store, and roster state identically to how they
            // stood live, using one code path for both "just happened" and
            // "happened before I restarted".
            let _ = hub.process_incoming(hub.own_id.clone(), record.clone());
        }
        hub.replaying.store(false, std::sync::atomic::Ordering::SeqCst);

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

    fn build(own_identity: &Identity, roster: Roster, config: GroupHubConfig, log: Option<Arc<crate::persistence::EventLog>>) -> Arc<GroupHub> {
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
            message_store: Mutex::new(HashMap::new()),
            merged_tx,
            event_tx,
            event_rx: Mutex::new(event_rx),
            log,
            replaying: std::sync::atomic::AtomicBool::new(false),
        });

        if auto_pump {
            let hub_for_thread = Arc::clone(&hub);
            std::thread::spawn(move || loop {
                let Ok((from, bytes)) = merged_rx.recv() else { return };
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
        self.sessions.lock().unwrap().insert(peer_id, session);
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
        let content = GroupContent::Post { payload: payload.to_vec() };
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
        let content = GroupContent::Edit { target_seq, new_payload: new_payload.to_vec() };
        self.sign_and_send(identity, content)
    }

    /// Delete a message: your own (requires `can_write`, same as editing -
    /// deleting your own content is a normal part of authoring it), or - if
    /// `target_sender` is someone else - requires `can_remove` (moderation).
    pub fn delete(&self, identity: &Identity, target_sender: PeerId, target_seq: u64) -> Result<u64> {
        if target_sender == identity.fingerprint() {
            self.require_permission(|p| p.can_write)?;
        } else {
            self.require_permission(|p| p.can_remove)?;
        }
        let content = GroupContent::Delete { target_sender, target_seq };
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
        let (seq, prev_hash) = self.own_chain.lock().unwrap().next_header(&content_bytes);
        let sender = identity.fingerprint();
        let signing_bytes = GroupMessage::signing_bytes(&self.roster_group_id(), &sender, seq, &prev_hash, &content);
        let signature = identity.sign(&signing_bytes).to_bytes();
        let msg = GroupMessage::Application { sender: sender.clone(), seq, prev_hash, content, signature };
        let wire = msg.encode();

        // Cache our own message too, so we can relay it to someone else
        // even if we're the only one currently online who has it.
        self.cache_for_relay(&sender, seq, &wire);
        self.persist(&wire);
        self.apply_content_locally(&sender, seq, &self.get_content(&msg));

        self.fan_out_to_readers(&wire)?;
        Ok(seq)
    }

    fn roster_group_id(&self) -> GroupId {
        self.roster.lock().unwrap().group_id.clone()
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
            let _ = log.append(bytes);
        }
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
    fn apply_content_locally(&self, sender: &PeerId, seq: u64, content: &GroupContent) -> Option<GroupEvent> {
        let mut store = self.message_store.lock().unwrap();
        match content {
            GroupContent::Post { payload } => {
                store.entry(sender.clone()).or_default().insert(seq, StoredMessage { payload: payload.clone(), edited: false, deleted: false });
                Some(GroupEvent::Message { sender: sender.clone(), seq, payload: payload.clone() })
            }
            GroupContent::Edit { target_seq, new_payload } => {
                let author_messages = store.entry(sender.clone()).or_default();
                if let Some(stored) = author_messages.get_mut(target_seq) {
                    if stored.deleted {
                        return None; // can't edit something already deleted
                    }
                    stored.payload = new_payload.clone();
                    stored.edited = true;
                    Some(GroupEvent::MessageEdited { author: sender.clone(), seq: *target_seq, new_payload: new_payload.clone() })
                } else {
                    None
                }
            }
            GroupContent::Delete { target_sender, target_seq } => {
                let author_messages = store.entry(target_sender.clone()).or_default();
                if let Some(stored) = author_messages.get_mut(target_seq) {
                    stored.deleted = true;
                    stored.payload.clear();
                    Some(GroupEvent::MessageDeleted { author: target_sender.clone(), seq: *target_seq, deleted_by: sender.clone() })
                } else {
                    None
                }
            }
        }
    }

    /// Propose adding `member` at `tier`, applying locally and broadcasting
    /// to every attached session.
    pub fn propose_add(&self, own_identity: &Identity, member: VerifyingKey, tier: TierName) -> Result<()> {
        let signed = self.roster.lock().unwrap().propose_add(own_identity, member, tier)?;
        self.roster.lock().unwrap().apply(&signed)?;
        self.broadcast_roster_op(&signed)
    }

    /// Propose removing `target`.
    pub fn propose_remove(&self, own_identity: &Identity, target: PeerId) -> Result<()> {
        let signed = self.roster.lock().unwrap().propose_remove(own_identity, target)?;
        self.roster.lock().unwrap().apply(&signed)?;
        self.broadcast_roster_op(&signed)
    }

    /// Propose moving `target` to `new_tier` (promotion/demotion).
    pub fn propose_change_tier(&self, own_identity: &Identity, target: PeerId, new_tier: TierName) -> Result<()> {
        let signed = self.roster.lock().unwrap().propose_change_tier(own_identity, target, new_tier)?;
        self.roster.lock().unwrap().apply(&signed)?;
        self.broadcast_roster_op(&signed)
    }

    /// Propose defining/redefining a tier's permission bundle.
    pub fn propose_define_tier(&self, own_identity: &Identity, name: TierName, permissions: Permissions) -> Result<()> {
        let signed = self.roster.lock().unwrap().propose_define_tier(own_identity, name, permissions)?;
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
            let request = GroupMessage::RelayRequest { sender: member, after_seq }.encode();
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
        self.event_rx.lock().unwrap().recv().map_err(|_| ChatError::ConnectionClosed)
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
        let msg = GroupMessage::decode(&bytes).ok()?;
        match msg {
            GroupMessage::Application { sender, seq, prev_hash, content, signature } => {
                // Look up the *original author's* pinned key and current
                // permissions from our roster - not the arrival peer's.
                let (author_key, author_perms) = {
                    let roster = self.roster.lock().unwrap();
                    if !roster.is_member(&sender) {
                        return None; // not a current member: reject regardless of who relayed it
                    }
                    let key = roster.member_key(&sender)?;
                    (key, roster.permissions_of(&sender))
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
                    return None;
                }

                let signing_bytes = GroupMessage::signing_bytes(&self.roster_group_id(), &sender, seq, &prev_hash, &content);
                let sig = Signature::from_slice(&signature).ok()?;
                PeerRegistry::verify_signature(&author_key, &signing_bytes, &sig).ok()?;

                let content_bytes = content.encode();
                {
                    let mut chains = self.sender_chains.lock().unwrap();
                    let chain = chains.entry(sender.clone()).or_default();
                    chain.verify_and_advance(seq, prev_hash, &content_bytes).ok()?;
                }

                // Cache it (regardless of who delivered it) so we can relay
                // it onward to someone else later - this is what makes any
                // member able to backfill any other member's history.
                self.cache_for_relay(&sender, seq, &bytes);
                self.persist(&bytes);

                self.apply_content_locally(&sender, seq, &content)
            }
            GroupMessage::Roster(wire) => {
                let signed = wire.to_signed().ok()?;
                if self.roster.lock().unwrap().apply(&signed).is_ok() {
                    self.persist(&bytes);
                    let members = self.roster.lock().unwrap().member_ids();
                    Some(GroupEvent::MembershipChanged { members })
                } else {
                    None
                }
            }
            GroupMessage::RelayRequest { sender, after_seq } => {
                // Answer using whatever we have cached from `sender` - we
                // don't need to *be* sender to help someone catch up.
                let cached: Vec<Vec<u8>> = {
                    let cache = self.relay_cache.lock().unwrap();
                    cache
                        .get(&sender)
                        .map(|per_sender| per_sender.range((std::ops::Bound::Excluded(after_seq), std::ops::Bound::Unbounded)).map(|(_, v)| v.clone()).collect())
                        .unwrap_or_default()
                };
                if let Some(session) = self.sessions.lock().unwrap().get(&arrival_peer) {
                    for wire in cached {
                        let _ = session.send(&wire);
                    }
                }
                None // a relay request itself is bookkeeping, not an app-visible event
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
            .map(|msgs| msgs.iter().map(|(seq, m)| (*seq, m.payload.clone(), m.edited, m.deleted)).collect())
            .unwrap_or_default()
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
        self.sender_chains.lock().unwrap().get(sender).map(|c| c.tip_hash())
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
    fn member_key(&self, id: &PeerId) -> Option<VerifyingKey> {
        self.members.get(id).map(|m| m.key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Roster / tier genesis and mutation ----

    #[test]
    fn genesis_default_assigns_owner_to_creator_and_member_to_everyone_else() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let (roster, _genesis) = Roster::genesis_default(&alice, vec![bob.public_key()]);
        assert_eq!(roster.tier_of(&alice.fingerprint()), Some("owner".to_string()));
        assert_eq!(roster.tier_of(&bob.fingerprint()), Some("member".to_string()));
        assert_eq!(roster.permissions_of(&alice.fingerprint()), Permissions::FULL);
        assert_eq!(roster.permissions_of(&bob.fingerprint()), Permissions::READ_WRITE);
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
        let add = roster.propose_add(&alice, carol.public_key(), "member".to_string()).unwrap();
        roster.apply(&add).unwrap();
        assert_eq!(roster.tier_of(&carol.fingerprint()), Some("member".to_string()));
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
        let (roster, _genesis) = Roster::genesis_default(&alice, vec![bob.public_key(), carol.public_key()]);
        let result = roster.propose_remove(&bob, carol.fingerprint());
        assert!(matches!(result, Err(ChatError::PermissionDenied)));
    }

    #[test]
    fn owner_can_promote_a_member_to_a_new_tier() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let (mut roster, _genesis) = Roster::genesis_default(&alice, vec![bob.public_key()]);
        let promote = roster.propose_change_tier(&alice, bob.fingerprint(), "owner".to_string()).unwrap();
        roster.apply(&promote).unwrap();
        assert_eq!(roster.permissions_of(&bob.fingerprint()), Permissions::FULL);
    }

    #[test]
    fn a_plain_member_cannot_promote_anyone() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let carol = Identity::generate();
        let (roster, _genesis) = Roster::genesis_default(&alice, vec![bob.public_key(), carol.public_key()]);
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
            .propose_define_tier(&alice, "member".to_string(), Permissions { can_add: false, can_remove: false, can_read: true, can_write: false })
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
        let add = roster.propose_add(&alice, bob.public_key(), "nonexistent-tier".to_string()).unwrap();
        assert!(matches!(roster.apply(&add), Err(ChatError::MalformedMessage(_))));
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
        let add = roster.propose_add(&alice, carol.public_key(), "member".to_string()).unwrap();
        roster.apply(&add).unwrap();
        // Replaying the same (now-stale) op fails: its prev_hash points at
        // a state the roster has already moved past.
        assert!(matches!(roster.apply(&add), Err(ChatError::RosterHistoryMismatch)));
    }

    #[test]
    fn rejects_a_roster_op_with_a_tampered_signature() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let carol = Identity::generate();
        let (mut roster, _genesis) = Roster::genesis_default(&alice, vec![bob.public_key()]);
        let mut add = roster.propose_add(&alice, carol.public_key(), "member".to_string()).unwrap();
        add.op = RosterOp::Add { member: bob.public_key(), tier: "owner".to_string() }; // tamper after signing
        assert!(matches!(roster.apply(&add), Err(ChatError::RosterSignatureInvalid)));
    }

    #[test]
    fn a_non_member_cannot_even_build_a_valid_proposal() {
        // Non-members get `Permissions::NONE`, so `propose_add` fails via
        // the ordinary permission check - the same fail-closed path a
        // demoted member would hit, not a special case.
        let alice = Identity::generate();
        let mallory = Identity::generate();
        let (roster, _genesis) = Roster::genesis_default(&alice, vec![]);
        assert!(matches!(roster.propose_add(&mallory, alice.public_key(), "member".to_string()), Err(ChatError::PermissionDenied)));
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
            op: RosterOp::Add { member: mallory.public_key(), tier: "member".to_string() },
            proposer: mallory.fingerprint(),
            signature: mallory.sign(b"doesn't matter, rejected before signature check"),
        };
        assert!(matches!(roster.apply(&forged), Err(ChatError::UnauthorizedRosterOp)));
    }

    // ---- GroupContent / GroupMessage wire encoding ----

    #[test]
    fn post_content_round_trips() {
        let content = GroupContent::Post { payload: b"hello".to_vec() };
        assert_eq!(GroupContent::decode(&content.encode()).unwrap(), content);
    }

    #[test]
    fn edit_content_round_trips() {
        let content = GroupContent::Edit { target_seq: 3, new_payload: b"corrected".to_vec() };
        assert_eq!(GroupContent::decode(&content.encode()).unwrap(), content);
    }

    #[test]
    fn delete_content_round_trips() {
        let content = GroupContent::Delete { target_sender: "abc123".to_string(), target_seq: 9 };
        assert_eq!(GroupContent::decode(&content.encode()).unwrap(), content);
    }

    #[test]
    fn application_message_round_trips() {
        let msg = GroupMessage::Application {
            sender: "deadbeef".to_string(),
            seq: 5,
            prev_hash: [7u8; 32],
            content: GroupContent::Post { payload: b"hi".to_vec() },
            signature: [1u8; 64],
        };
        assert_eq!(GroupMessage::decode(&msg.encode()).unwrap(), msg);
    }

    #[test]
    fn relay_request_round_trips() {
        let msg = GroupMessage::RelayRequest { sender: "abc".to_string(), after_seq: 42 };
        assert_eq!(GroupMessage::decode(&msg.encode()).unwrap(), msg);
    }

    // ---- Sender chains ----

    #[test]
    fn sender_chain_accepts_a_consistent_sequence_of_content() {
        let mut chain = SenderChainState::new();
        let mut own = OwnChainState::new();
        let c1 = GroupContent::Post { payload: b"hello".to_vec() }.encode();
        let (s1, p1) = own.next_header(&c1);
        assert!(chain.verify_and_advance(s1, p1, &c1).is_ok());
        let c2 = GroupContent::Post { payload: b"world".to_vec() }.encode();
        let (s2, p2) = own.next_header(&c2);
        assert!(chain.verify_and_advance(s2, p2, &c2).is_ok());
    }

    #[test]
    fn sender_chain_rejects_reordered_or_mismatched_headers() {
        let mut own = OwnChainState::new();
        let c1 = GroupContent::Post { payload: b"hello".to_vec() }.encode();
        let (_s1, _p1) = own.next_header(&c1);
        let c2 = GroupContent::Post { payload: b"world".to_vec() }.encode();
        let (s2, p2) = own.next_header(&c2);

        let mut chain = SenderChainState::new();
        assert!(chain.verify_and_advance(s2, p2, &c2).is_err()); // seq 2 before seq 1

        let mut chain2 = SenderChainState::new();
        assert!(chain2.verify_and_advance(1, [0xAAu8; 32], &c1).is_err()); // bogus prev_hash
    }

    #[test]
    fn two_recipients_detect_equivocation_via_diverging_tip_hashes() {
        let mut own = OwnChainState::new();
        let c1 = GroupContent::Post { payload: b"meeting is at 5pm".to_vec() }.encode();
        let (seq1, prev1) = own.next_header(&c1);

        let mut alice_view = SenderChainState::new();
        let mut bob_view = SenderChainState::new();
        assert!(alice_view.verify_and_advance(seq1, prev1, &c1).is_ok());
        // The sender shows Bob different content under the same header.
        let lie = GroupContent::Post { payload: b"meeting is at 6pm".to_vec() }.encode();
        assert!(bob_view.verify_and_advance(seq1, prev1, &lie).is_ok());

        assert_ne!(alice_view.tip_hash(), bob_view.tip_hash());
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

        let (roster, _genesis) = Roster::genesis_default(&x, vec![y.public_key(), z_alice.public_key()]);

        // X authors one message.
        let mut x_chain = OwnChainState::new();
        let content = GroupContent::Post { payload: b"the launch code is 4-8-15-16-23-42".to_vec() };
        let content_bytes = content.encode();
        let (seq, prev_hash) = x_chain.next_header(&content_bytes);
        let sender = x.fingerprint();
        let signing_bytes = GroupMessage::signing_bytes(&roster.group_id, &sender, seq, &prev_hash, &content);
        let signature = x.sign(&signing_bytes).to_bytes();

        let wire = GroupMessage::Application { sender: sender.clone(), seq, prev_hash, content: content.clone(), signature }.encode();

        // "Y relays it" is modeled as simply: these exact bytes arrive at Z
        // with no involvement from Y's identity whatsoever.
        let decoded = GroupMessage::decode(&wire).unwrap();
        let GroupMessage::Application { sender: decoded_sender, seq: decoded_seq, prev_hash: decoded_prev, content: decoded_content, signature: decoded_sig } = decoded else {
            panic!("expected an application message");
        };

        // Z verifies using X's key, looked up from the (shared, signed)
        // roster - never touching anything belonging to Y.
        let author_key = roster.member_key(&decoded_sender).expect("X is a roster member");
        let expected_signing_bytes = GroupMessage::signing_bytes(&roster.group_id, &decoded_sender, decoded_seq, &decoded_prev, &decoded_content);
        let sig = Signature::from_slice(&decoded_sig).unwrap();
        assert!(PeerRegistry::verify_signature(&author_key, &expected_signing_bytes, &sig).is_ok());
        assert_eq!(decoded_sender, x.fingerprint());
        assert_eq!(decoded_content, content);

        // And tampering with the relayed content (imagine a malicious Y
        // trying to alter what X said while forwarding it) is caught,
        // because the signature covers the content itself.
        let GroupContent::Post { payload } = &decoded_content else { unreachable!() };
        let tampered_content = GroupContent::Post { payload: [payload.as_slice(), b" (tampered by Y)"].concat() };
        let tampered_signing_bytes = GroupMessage::signing_bytes(&roster.group_id, &decoded_sender, decoded_seq, &decoded_prev, &tampered_content);
        assert!(PeerRegistry::verify_signature(&author_key, &tampered_signing_bytes, &sig).is_err());
    }
}

