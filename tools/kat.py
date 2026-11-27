# Independent re-implementation of plaintext v1 derivation, to cross-check Rust vectors.
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
