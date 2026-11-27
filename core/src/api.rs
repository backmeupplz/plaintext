//! Wire types shared by the server and every client. Ids are hex, blobs base64.

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

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct NewVault {
    pub id: Hex,
    /// Vault Key sealed with the Account Key.
    pub vault_key: B64,
    pub manifest: B64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SignupRequest {
    pub account_id: Hex,
    /// Ed25519 public key derived from (password, Secret Key).
    pub auth_key: B64,
    /// Account Key sealed with the Account Unlock Key.
    pub account_key: B64,
    pub vault: NewVault,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct LoginRequest {
    pub account_id: Hex,
    /// Unix seconds. Must be newer than the account's last login (no replay).
    pub ts: u64,
    pub sig: B64,
    pub device: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct LoginResponse {
    pub token: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VaultInfo {
    pub id: Hex,
    pub vault_key: B64,
    pub counter: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AccountResponse {
    pub account_key: B64,
    pub vaults: Vec<VaultInfo>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ItemBlob {
    pub id: Hex,
    pub blob: B64,
}

/// `GET /v1/vaults/{id}?since=N`: the manifest plus every item written after N.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct VaultResponse {
    pub counter: u64,
    pub manifest: B64,
    pub items: Vec<ItemBlob>,
}

/// `PUT /v1/vaults/{id}`: applied only if the server is still at `expected_counter`,
/// otherwise 409 and the client pulls, merges and retries.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VaultPut {
    pub expected_counter: u64,
    pub manifest: B64,
    pub upserts: Vec<ItemBlob>,
    pub deletes: Vec<Hex>,
}
