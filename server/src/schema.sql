PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS accounts(
  id BLOB PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  kind TEXT NOT NULL,                -- human | agent
  owner TEXT,                        -- for agents: the human who controls it
  identity TEXT NOT NULL,            -- self-signed Identity (Signed JSON)
  auth_key BLOB NOT NULL,            -- Ed25519 login public key
  account_key BLOB NOT NULL,         -- sealed with the Account Unlock Key
  keyring BLOB NOT NULL,             -- sealed with the Account Key
  keyring_counter INTEGER NOT NULL DEFAULT 0,
  admin INTEGER NOT NULL DEFAULT 0,
  disabled INTEGER NOT NULL DEFAULT 0,
  invite_id BLOB,
  invite_proof BLOB,
  last_login INTEGER NOT NULL DEFAULT 0,
  created INTEGER NOT NULL);

CREATE TABLE IF NOT EXISTS sessions(
  token_hash BLOB PRIMARY KEY,
  account_id BLOB NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  device TEXT NOT NULL,
  created INTEGER NOT NULL);

CREATE TABLE IF NOT EXISTS invites(
  id BLOB PRIMARY KEY,
  created_by TEXT NOT NULL,
  expires INTEGER NOT NULL,
  used INTEGER NOT NULL DEFAULT 0);

CREATE TABLE IF NOT EXISTS vaults(
  id BLOB PRIMARY KEY,
  counter INTEGER NOT NULL,
  epoch INTEGER NOT NULL,
  roster_version INTEGER NOT NULL,
  roster_hash BLOB,
  manifest_hash BLOB);

CREATE TABLE IF NOT EXISTS rosters(
  vault_id BLOB NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
  version INTEGER NOT NULL,
  signed TEXT NOT NULL,
  PRIMARY KEY(vault_id, version));

-- Derived from the current roster, for access checks.
CREATE TABLE IF NOT EXISTS members(
  vault_id BLOB NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
  username TEXT NOT NULL,
  role TEXT NOT NULL,
  expires INTEGER,
  PRIMARY KEY(vault_id, username));
CREATE INDEX IF NOT EXISTS members_user ON members(username);

CREATE TABLE IF NOT EXISTS vault_keys(
  vault_id BLOB NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
  username TEXT NOT NULL,
  epoch INTEGER NOT NULL,
  key BLOB NOT NULL,
  PRIMARY KEY(vault_id, username, epoch));

-- ponytail: every manifest is kept so any device can verify the chain from where
-- it left off; add signed checkpoints if this ever gets large.
CREATE TABLE IF NOT EXISTS manifests(
  vault_id BLOB NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
  counter INTEGER NOT NULL,
  signed TEXT NOT NULL,
  PRIMARY KEY(vault_id, counter));

CREATE TABLE IF NOT EXISTS items(
  vault_id BLOB NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
  id BLOB NOT NULL,
  blob BLOB NOT NULL,
  counter INTEGER NOT NULL,
  PRIMARY KEY(vault_id, id));
CREATE INDEX IF NOT EXISTS items_since ON items(vault_id, counter);

CREATE TABLE IF NOT EXISTS files(
  vault_id BLOB NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
  id BLOB NOT NULL,
  blob BLOB NOT NULL,
  PRIMARY KEY(vault_id, id));

CREATE TABLE IF NOT EXISTS messages(
  id BLOB PRIMARY KEY,
  to_user TEXT NOT NULL,
  signed TEXT NOT NULL,
  expires INTEGER,
  created INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS messages_to ON messages(to_user);
CREATE INDEX IF NOT EXISTS messages_expires ON messages(expires);

CREATE TABLE IF NOT EXISTS links(
  id BLOB PRIMARY KEY,
  creator TEXT NOT NULL,
  blob BLOB NOT NULL,
  expires INTEGER NOT NULL,
  views_left INTEGER);
CREATE INDEX IF NOT EXISTS links_expires ON links(expires);
CREATE INDEX IF NOT EXISTS links_creator ON links(creator);

CREATE TABLE IF NOT EXISTS audit(
  vault_id BLOB NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
  ts INTEGER NOT NULL,
  username TEXT NOT NULL,
  action TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS audit_vault ON audit(vault_id, ts);

-- Item blobs of a push too big for one request, until the push that names the
-- stage commits them. One stage per member and vault; deleted a day after its first part.
CREATE TABLE IF NOT EXISTS staged(
  vault_id BLOB NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
  username TEXT NOT NULL,
  stage BLOB NOT NULL,
  id BLOB NOT NULL,
  blob BLOB NOT NULL,
  created INTEGER NOT NULL,
  PRIMARY KEY(vault_id, username, id));
CREATE INDEX IF NOT EXISTS staged_created ON staged(created);

-- Security keys that signing in needs (DESIGN "Signing in with a security key").
-- An account with any needs one, its recovery codes or a device it trusts.
CREATE TABLE IF NOT EXISTS signin_keys(
  account_id BLOB NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  cred_id BLOB NOT NULL,
  name TEXT NOT NULL,
  rp_id TEXT NOT NULL,
  public_key BLOB NOT NULL,          -- COSE
  sign_count INTEGER NOT NULL DEFAULT 0,
  added INTEGER NOT NULL,
  PRIMARY KEY(account_id, cred_id));

CREATE TABLE IF NOT EXISTS recovery_codes(
  account_id BLOB NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  code_hash BLOB NOT NULL,
  PRIMARY KEY(account_id, code_hash));

-- Devices that signed in with a key or a recovery code once; only the hash of their token.
CREATE TABLE IF NOT EXISTS trusted_devices(
  token_hash BLOB PRIMARY KEY,
  account_id BLOB NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  created INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS trusted_account ON trusted_devices(account_id);

-- Signed logins waiting for a security key, for a few minutes.
CREATE TABLE IF NOT EXISTS pending_logins(
  pending_hash BLOB PRIMARY KEY,
  challenge BLOB NOT NULL UNIQUE,
  account_id BLOB NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  device TEXT NOT NULL,
  ttl INTEGER NOT NULL,
  approved INTEGER NOT NULL DEFAULT 0,
  expires INTEGER NOT NULL);
