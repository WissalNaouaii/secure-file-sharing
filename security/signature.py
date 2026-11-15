"""Signature numérique ECDSA P-256 sur le SHA-256 du clair."""
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed


def generate_keypair() -> ec.EllipticCurvePrivateKey:
    """Paire de clés ECDSA / ECDH sur la courbe P-256 (SECP256R1)."""
    return ec.generate_private_key(ec.SECP256R1())


def public_key_pem(private_key: ec.EllipticCurvePrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo)


def load_public_key(pem: bytes) -> ec.EllipticCurvePublicKey:
    return serialization.load_pem_public_key(pem)


def sign_hash(private_key: ec.EllipticCurvePrivateKey, sha256_hex: str) -> bytes:
    """Signe le condensat SHA-256 (hex) du clair. Signature DER."""
    digest = bytes.fromhex(sha256_hex)
    if len(digest) != 32:
        raise ValueError("Condensat SHA-256 invalide")
    return private_key.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256())))


def verify_signature(public_key: ec.EllipticCurvePublicKey, signature: bytes,
                     sha256_hex: str) -> bool:
    """Vérifie la signature ; retourne True/False (ne lève jamais pour une signature fausse)."""
    try:
        digest = bytes.fromhex(sha256_hex)
        public_key.verify(signature, digest, ec.ECDSA(Prehashed(hashes.SHA256())))
        return True
    except (InvalidSignature, ValueError):
        return False