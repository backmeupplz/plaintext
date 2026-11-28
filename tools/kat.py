# Independent re-implementation of plaintext v1 derivation and blob format, to cross-check the Rust vectors.
# Needs: pip install argon2-cffi cryptography pynacl
import hashlib, unicodedata
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
A = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
sk = b"0123456789abcdef"; pw = "correct horse battery staple"
n = int.from_bytes(sk, "big") << 2
data = "".join(A[(n >> (5 * i)) & 31] for i in reversed(range(26)))
h = hashlib.sha256(sk).digest(); data += A[h[0] >> 3] + A[h[1] >> 3]
print("sk", "A1-" + "-".join(data[i:i+7] for i in range(0, 28, 7)))
def hk(salt, ikm, info, n): return HKDF(hashes.SHA256(), n, salt, info).derive(ikm)
print("account_id", hk(None, sk, b"plaintext/v1/account-id", 16).hex())
salt = hashlib.sha256(b"plaintext/v1/argon-salt" + sk).digest()
st = hash_secret_raw(unicodedata.normalize("NFKD", pw).encode(), salt, 3, 65536, 1, 32, Type.ID, 19)
print("unlock", hk(sk, st, b"plaintext/v1/unlock", 32).hex())
seed = hk(sk, st, b"plaintext/v1/auth", 32)
print("auth_pub", Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex())

# Blob vector: XChaCha20-Poly1305 with key 07*32, nonce 03*24, AD = 0x01 ‖ "plaintext/v1/item" ‖ 01*16 ‖ 02*16.
from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_encrypt as xc
aad = b"\x01" + b"plaintext/v1/item" + b"\x01" * 16 + b"\x02" * 16
print("blob", (b"\x01" + b"\x03" * 24 + xc(b"plaintext", aad, b"\x03" * 24, b"\x07" * 32)).hex())

# Agent key (32 bytes of 0x05): HKDF(salt="plaintext/v1/agent", ikm=key).
ak = b"\x05" * 32
print("agent_id", hk(b"plaintext/v1/agent", ak, b"plaintext/v1/account-id", 16).hex())
aseed = hk(b"plaintext/v1/agent", ak, b"plaintext/v1/auth", 32)
print("agent_auth_pub", Ed25519PrivateKey.from_private_bytes(aseed).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex())

# Fingerprint of ("alice", sign_pk = 01*32, enc_pk = 02*32, kem_pk = 03*1184): SHA-256, first 15 bytes, Crockford base32, groups of 6.
fh = hashlib.sha256(b"plaintext/v1/fingerprint" + b"alice" + b"\x00" + b"\x01" * 32 + b"\x02" * 32 + b"\x03" * 1184).digest()[:15]
fn = int.from_bytes(fh, "big")
fs = "".join(A[(fn >> (5 * i)) & 31] for i in reversed(range(24)))
print("fingerprint", " ".join(fs[i:i+6] for i in range(0, 24, 6)))
