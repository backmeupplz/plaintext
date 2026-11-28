//! Wire types shared by the server and every client. Ids are hex, blobs base64.
//! Anything signed travels as `Signed { body, signer, sig }`: the exact bytes that
//! were signed, so nobody has to agree on a JSON canonical form.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::crypto::Id;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Hex(pub Id);

impl Serialize for Hex {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(self.0))
    }
}
impl<'de> Deserialize<'de> for Hex {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        let mut id = [0u8; 16];
        hex::decode_to_slice(&s, &mut id).map_err(serde::de::Error::custom)?;
        Ok(Hex(id))
    }
}
impl std::fmt::Display for Hex {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}
impl std::str::FromStr for Hex {
    type Err = hex::FromHexError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut id = [0u8; 16];
        hex::decode_to_slice(s, &mut id)?;
        Ok(Hex(id))
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct B64(pub Vec<u8>);

impl Serialize for B64 {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(&self.0))
    }
}
impl<'de> Deserialize<'de> for B64 {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        STANDARD.decode(s).map(B64).map_err(serde::de::Error::custom)
    }
}

/// A signed document: `sig` signs `plaintext/v1/<domain> ‖ body` with `signer`'s identity key.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Signed {
    pub body: B64,
    pub signer: String,
    pub sig: B64,
}

// ---------- Identity ----------

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Human,
    Agent,
}

/// A user's public identity, self-signed (domain `identity`).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Identity {
    pub username: String,
    pub kind: Kind,
    /// For agents: the human who created and controls it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    pub sign_pk: B64,
    pub enc_pk: B64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct InviteProof {
    pub id: Hex,
    /// HMAC(invite secret, identity body): lets the inviter's devices verify the
    /// new user's keys without trusting the server.
    pub proof: B64,
}

// ---------- Vaults ----------

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Reader,
    Writer,
    Owner,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Member {
    pub username: String,
    pub sign_pk: B64,
    pub enc_pk: B64,
    pub role: Role,
    /// Unix seconds; after this the member is treated as removed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<u64>,
}

/// Who may use a vault (domain `roster`). Each version is signed by an owner of
/// the previous version and links to it by hash.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Roster {
    pub vault_id: Hex,
    pub version: u64,
    /// SHA-256 of the previous version's signed body; empty for version 0.
    pub prev: B64,
    /// Bumped whenever the vault key is replaced (a member was removed).
    pub epoch: u64,
    /// HMAC(vault key, "plaintext/v1/key-check" ‖ vault_id ‖ epoch): proves a
    /// wrapped key handed out by the server is the owner's real key.
    pub key_check: B64,
    pub members: Vec<Member>,
}

/// The public part of a manifest (domain `manifest`): the chain links stay
/// verifiable after a key change because they're outside the encryption.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ManifestEnvelope {
    pub vault_id: Hex,
    pub counter: u64,
    pub epoch: u64,
    /// The roster version the writer acted under: their role is checked there.
    pub roster: u64,
    /// SHA-256 of the previous manifest's signed body; empty for the first.
    pub prev: B64,
    /// Sealed `{meta, items: {id → hash}}` with the vault key.
    pub sealed: B64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct WrappedKey {
    pub username: String,
    pub epoch: u64,
    pub key: B64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct NewVault {
    pub roster: Signed,
    pub keys: Vec<WrappedKey>,
    pub manifest: Signed,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ItemBlob {
    pub id: Hex,
    pub blob: B64,
}

/// `GET /v1/vaults/{id}?since=N&roster=V`
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct VaultResponse {
    pub counter: u64,
    /// Every manifest after `since`, oldest first.
    pub manifests: Vec<Signed>,
    /// Every roster version after `roster` (all of them when `roster` is absent).
    pub rosters: Vec<Signed>,
    /// This user's wrapped key for the current epoch.
    pub key: Option<B64>,
    /// Items written after `since` (all items when the epoch changed since then).
    pub items: Vec<ItemBlob>,
    /// Members of the current roster whose accounts were deleted. The server no
    /// longer serves them; an owner's device removes them for real (new key).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub gone: Vec<String>,
}

/// `PUT /v1/vaults/{id}`: applied only if the server is still at `expected_counter`.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VaultPut {
    pub expected_counter: u64,
    pub manifest: Signed,
    pub upserts: Vec<ItemBlob>,
    pub deletes: Vec<Hex>,
    /// Item blobs sent ahead with `POST /v1/vaults/{id}/stage`, committed with this push.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub staged: Option<Staged>,
}

/// The `count` item blobs this member staged under `id`; the push fails (409) if
/// the server doesn't hold exactly that many.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Staged {
    pub id: Hex,
    pub count: u64,
}

/// Most item bytes one push (or key rotation) may write. Every member's next pull
/// brings them in one response, which clients take up to 128 MiB of, in base64
/// and with a manifest of up to 16 MiB (twice base64).
pub const MAX_PUSH: usize = 64 << 20;

/// `POST /v1/vaults/{id}/leave`, signed (domain `leave`) by the member leaving.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct LeaveVault {
    pub vault_id: Hex,
    /// Unix milliseconds; the server takes it within ±120 s.
    pub ts: u64,
}

/// `POST /v1/vaults/{id}/stage`: part of the items of a push (or a key rotation)
/// too big for one request. The server holds them, uncommitted, until the push
/// that names `stage`, or a day after the first part. Staging under a new id drops
/// what the member staged before in that vault, and so does a refused part or push.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct StageRequest {
    pub stage: Hex,
    pub upserts: Vec<ItemBlob>,
}

/// `POST /v1/vaults/{id}/roster`: a new roster version, plus keys for new members.
/// With `rotation`, the vault key changes and every item is re-sealed.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RosterUpdate {
    pub roster: Signed,
    pub keys: Vec<WrappedKey>,
    pub rotation: Option<VaultPut>,
}

// ---------- Account ----------

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SignupRequest {
    pub account_id: Hex,
    /// Ed25519 login public key derived from (password, Secret Key) or the agent key.
    pub auth_key: B64,
    /// Account Key sealed with the Account Unlock Key.
    pub account_key: B64,
    pub identity: Signed,
    /// Private keys and pinned contacts, sealed with the Account Key.
    pub keyring: B64,
    /// Humans get a personal vault at signup; agents get none.
    pub vault: Option<NewVault>,
    pub invite: Option<InviteProof>,
    /// For the first account on a server started with PLAINTEXT_SETUP_CODE.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setup: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct LoginRequest {
    pub account_id: Hex,
    /// Unix milliseconds. Must be newer than the account's last login (no replay).
    pub ts: u64,
    pub sig: B64,
    pub device: String,
    /// Seconds the session should last, at most the server's limit (30 days).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u64>,
    /// The client can finish a sign-in with a security key (`LoginResponse::key`).
    /// Without it, an account that needs one is refused with a message saying so.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub keys: bool,
    /// This device's `LoginResponse::trust` from an earlier sign-in with a security
    /// key: it isn't asked for one again.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct LoginResponse {
    /// Empty when `key` is set.
    #[serde(default)]
    pub token: String,
    /// The account needs a security key: finish with `POST /v1/login/finish`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<KeyNeeded>,
    /// After a sign-in with a security key or a recovery code: send it with later
    /// logins from this device (`LoginRequest::trust`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust: Option<String>,
}

// ---------- Security keys for sign-in (DESIGN "Signing in with a security key") ----------

/// A login whose account needs a security key, waiting to be finished.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct KeyNeeded {
    /// Finishes the sign-in. Only the client that signed the login gets it.
    pub pending: String,
    /// The WebAuthn challenge. Its hex names the approval page, `/v1/login/key#<hex>`.
    pub challenge: B64,
    pub keys: Vec<KeyCred>,
}

/// A security key's credential and the relying party (a host of the server) it was made for.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct KeyCred {
    pub id: B64,
    pub rp_id: String,
}

/// A WebAuthn assertion, as a browser or a CTAP client returns it.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Assertion {
    /// The credential id.
    pub id: B64,
    /// clientDataJSON
    pub client_data: B64,
    pub auth_data: B64,
    pub signature: B64,
}

/// `POST /v1/login/finish`: an assertion, a recovery code, or neither once the
/// approval page has taken the assertion.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct LoginFinish {
    pub pending: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assertion: Option<Assertion>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery: Option<String>,
}

/// `GET /v1/login/approve/{challenge}`: what the approval page shows and asks the key for.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Approval {
    pub username: String,
    pub device: String,
    pub keys: Vec<KeyCred>,
}

/// `POST /v1/account/signin-keys`, signed by the login key over
/// `crypto::signin_keys_message`, so only the password changes them.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SigninKeysChange {
    pub ts: u64,
    /// A `SigninKeyAction` as JSON: the exact bytes signed.
    pub action: B64,
    pub sig: B64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "do", rename_all = "snake_case")]
pub enum SigninKeyAction {
    /// `registration` is the new credential's authenticatorData; `proof` an
    /// assertion by it over `crypto::signin_key_add_challenge`.
    Add { name: String, rp_id: String, registration: B64, proof: Assertion },
    Remove { id: B64 },
    /// New recovery codes, replacing the old ones.
    Codes,
}

/// `GET /v1/account/signin-keys`. Any key listed means sign-in needs one.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct SigninKeys {
    pub keys: Vec<SigninKey>,
    pub codes_left: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SigninKey {
    pub id: B64,
    pub name: String,
    pub rp_id: String,
    pub added: u64,
}

/// The answer to a `SigninKeysChange`: new recovery codes (adding the first key,
/// or `Codes`), shown once; otherwise none.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct RecoveryCodes {
    pub codes: Vec<String>,
    /// Adding a key: a token that spares the device that added it the key at
    /// sign-in, as after a sign-in with it (`LoginResponse::trust`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AccountResponse {
    pub username: String,
    pub admin: bool,
    pub account_key: B64,
    pub keyring: B64,
    pub keyring_counter: u64,
    pub vaults: Vec<Hex>,
    /// Storage this account may use, in bytes (`None`: unlimited).
    #[serde(default)]
    pub quota: Option<u64>,
    /// Bytes counted against the quota: the vaults in `paid` and the share links and
    /// messages this account and its agents sent (DESIGN "Servers and accounts").
    #[serde(default)]
    pub usage: u64,
    /// Every vault that counts against this account (`usage`): the ones it created,
    /// and ones that moved to it from someone else (DESIGN "Servers and accounts"),
    /// including ones it isn't a current member of (only an agent of its is, or its
    /// membership expired).
    /// `POST /v1/vaults/{id}/leave` takes it and its agents out of any of them.
    #[serde(default)]
    pub paid: Vec<Hex>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct KeyringPut {
    pub expected_counter: u64,
    pub keyring: B64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PasswordChange {
    pub ts: u64,
    pub auth_key: B64,
    pub account_key: B64,
    /// Signed by the current login key over `password_change_message`.
    pub sig: B64,
}

/// `DELETE /v1/account`, signed by the login key over `account_delete_message`.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AccountDelete {
    pub ts: u64,
    pub sig: B64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DeviceSession {
    pub id: String,
    pub device: String,
    pub created: u64,
    pub current: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct UserInfo {
    pub identity: Signed,
    pub admin: bool,
    pub disabled: bool,
    pub invite: Option<InviteProof>,
}

/// `GET /v1/info`, unauthenticated: what an app needs before showing the signup form.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ServerInfo {
    pub version: String,
    /// Anyone may sign up (`true`), or only with an invite.
    pub open: bool,
    /// No accounts yet and the first one needs the setup code.
    pub setup: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct NewInvite {
    pub id: Hex,
}

// ---------- Inbox, links, audit ----------

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum MessageKind {
    /// An item someone shared with you.
    Item,
    /// An agent asking its owner for access.
    Request,
}

/// A message to one user (domain `message`), sealed to their encryption key.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Message {
    pub id: Hex,
    pub to: String,
    pub kind: MessageKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<u64>,
    pub sealed: B64,
}

/// A link anyone can open (no account): the item is sealed with a random key
/// that travels only in the link's `#fragment`.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct NewLink {
    pub id: Hex,
    pub blob: B64,
    /// Unix seconds.
    pub expires: u64,
    pub max_views: Option<u32>,
}

/// `GET /v1/vaults/{id}/files`: every uploaded file, and the server's clock
/// (unix seconds), which times collection so a device's own clock can't.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FileList {
    pub now: u64,
    pub files: Vec<FileInfo>,
}

/// An uploaded file; `size` is the sealed blob's.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FileInfo {
    pub id: Hex,
    pub size: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AuditEntry {
    pub ts: u64,
    pub username: String,
    pub action: String,
}
