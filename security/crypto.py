"""Chiffrement AES-256-GCM, enveloppement de clés, partage hybride ECDH+HKDF.

Correspond aux Flux A, B, C du cahier des charges.
"""
import os
import base64

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

KEY_SIZE = 32        # AES-256
NONCE_SIZE = 12      # 96 bits (recommandation NIST pour GCM)
PBKDF2_ITERATIONS = 200_000
SALT_SIZE = 16


class IntegrityError(Exception):
    """Levée quand le tag GCM est invalide (chiffré altéré ou mauvaise clé)."""


# ---------------------------------------------------------------- fichiers --
def generate_file_key() -> bytes:
    """Clé AES-256 aléatoire, unique par fichier."""
    return AESGCM.generate_key(bit_length=256)


def encrypt_bytes(key: bytes, plaintext: bytes, aad: bytes | None = None):
    """Chiffre avec AES-256-GCM. Retourne (nonce, chiffré||tag).

    Le nonce est tiré aléatoirement à CHAQUE appel : ne jamais le réutiliser
    avec la même clé. `aad` (ex. id du fichier) est authentifié mais non chiffré.
    """
    nonce = os.urandom(NONCE_SIZE)
    return nonce, AESGCM(key).encrypt(nonce, plaintext, aad)


def decrypt_bytes(key: bytes, nonce: bytes, ciphertext: bytes,
                  aad: bytes | None = None) -> bytes:
    """Déchiffre et vérifie le tag GCM. Lève IntegrityError si altéré."""
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise IntegrityError("Tag GCM invalide : fichier altéré ou clé incorrecte") from exc


def encrypt_file_to_disk(key: bytes, plaintext: bytes, storage_dir: str,
                         aad: bytes | None = None):
    """Chiffre et écrit dans storage_dir sous un nom aléatoire (UUID .bin).

    Retourne (stored_name, nonce). `storage_dir` doit être hors racine Web.
    """
    import uuid
    os.makedirs(storage_dir, exist_ok=True)
    stored_name = f"{uuid.uuid4()}.bin"
    nonce, ct = encrypt_bytes(key, plaintext, aad)
    path = os.path.join(storage_dir, stored_name)
    with open(path, "wb") as f:
        f.write(ct)
    os.chmod(path, 0o600)
    return stored_name, nonce


def decrypt_file_from_disk(key: bytes, nonce: bytes, storage_dir: str,
                           stored_name: str, aad: bytes | None = None) -> bytes:
    # Protection path traversal : on n'accepte qu'un nom de fichier simple
    if os.path.basename(stored_name) != stored_name:
        raise ValueError("Nom de fichier stocké invalide")
    with open(os.path.join(storage_dir, stored_name), "rb") as f:
        ct = f.read()
    return decrypt_bytes(key, nonce, ct, aad)


# ------------------------------------------------ clé maître (propriétaire) --
def load_master_key(env_var: str = "MASTER_KEY") -> bytes:
    """Lit la clé maître (base64, 32 octets) depuis une variable d'environnement."""
    raw = os.environ.get(env_var)
    if not raw:
        raise RuntimeError(f"Variable d'environnement {env_var} absente")
    key = base64.b64decode(raw)
    if len(key) != KEY_SIZE:
        raise ValueError("La clé maître doit faire 32 octets")
    return key


def generate_master_key_b64() -> str:
    """Utilitaire : à exécuter une fois, puis stocker dans l'env (jamais dans Git)."""
    return base64.b64encode(os.urandom(KEY_SIZE)).decode()


def wrap_key(master_key: bytes, file_key: bytes) -> bytes:
    """Enveloppe la clé du fichier avec la clé maître. Retourne nonce||chiffré."""
    nonce, ct = encrypt_bytes(master_key, file_key, aad=b"file-key-master-wrap")
    return nonce + ct


def unwrap_key(master_key: bytes, wrapped: bytes) -> bytes:
    nonce, ct = wrapped[:NONCE_SIZE], wrapped[NONCE_SIZE:]
    return decrypt_bytes(master_key, nonce, ct, aad=b"file-key-master-wrap")


# ----------------------------------------- partage hybride ECDH → HKDF → GCM --
def _derive_wrap_key(private_key: ec.EllipticCurvePrivateKey,
                     peer_public_key: ec.EllipticCurvePublicKey) -> bytes:
    shared = private_key.exchange(ec.ECDH(), peer_public_key)
    return HKDF(algorithm=hashes.SHA256(), length=KEY_SIZE, salt=None,
                info=b"file-key-wrap").derive(shared)


def wrap_key_for_recipient(owner_private_key: ec.EllipticCurvePrivateKey,
                           recipient_public_key: ec.EllipticCurvePublicKey,
                           file_key: bytes) -> bytes:
    """Flux C : réenveloppe la clé du fichier pour un destinataire."""
    wrap_key_ = _derive_wrap_key(owner_private_key, recipient_public_key)
    nonce, ct = encrypt_bytes(wrap_key_, file_key, aad=b"file-key-share")
    return nonce + ct


def unwrap_key_as_recipient(recipient_private_key: ec.EllipticCurvePrivateKey,
                            owner_public_key: ec.EllipticCurvePublicKey,
                            wrapped: bytes) -> bytes:
    """Flux B : le destinataire retrouve la clé du fichier (ECDH symétrique)."""
    wrap_key_ = _derive_wrap_key(recipient_private_key, owner_public_key)
    nonce, ct = wrapped[:NONCE_SIZE], wrapped[NONCE_SIZE:]
    return decrypt_bytes(wrap_key_, nonce, ct, aad=b"file-key-share")


# ------------------------------- clé privée utilisateur (PBKDF2 + AES-GCM) --
def _derive_from_password(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=KEY_SIZE, salt=salt,
                     iterations=PBKDF2_ITERATIONS)
    return kdf.derive(password.encode("utf-8"))


def encrypt_private_key(private_key: ec.EllipticCurvePrivateKey, password: str) -> bytes:
    """Chiffre la clé privée (PEM PKCS8) : salt || nonce || chiffré."""
    pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())
    salt = os.urandom(SALT_SIZE)
    nonce, ct = encrypt_bytes(_derive_from_password(password, salt), pem,
                              aad=b"user-private-key")
    return salt + nonce + ct


def decrypt_private_key(blob: bytes, password: str) -> ec.EllipticCurvePrivateKey:
    """Déchiffre la clé privée en mémoire à la connexion."""
    salt = blob[:SALT_SIZE]
    nonce = blob[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    ct = blob[SALT_SIZE + NONCE_SIZE:]
    pem = decrypt_bytes(_derive_from_password(password, salt), nonce, ct,
                        aad=b"user-private-key")
    return serialization.load_pem_private_key(pem, password=None)