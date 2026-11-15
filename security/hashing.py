"""Hachage SHA-256 et comparaison en temps constant (R2, Choix crypto: Intégrité)."""
import hashlib
import hmac

CHUNK = 64 * 1024


def sha256_bytes(data: bytes) -> str:
    """SHA-256 d'un contenu en mémoire, retourné en hexadécimal."""
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str) -> str:
    """SHA-256 d'un fichier lu par blocs (pas de chargement complet en RAM)."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(CHUNK):
            h.update(chunk)
    return h.hexdigest()


def verify_hash(data: bytes, expected_hex: str) -> bool:
    """Recalcule le SHA-256 et compare en temps constant (anti-timing)."""
    return hmac.compare_digest(sha256_bytes(data), expected_hex.lower())


def verify_file_hash(path: str, expected_hex: str) -> bool:
    """Comparaison d'un fichier local avec la référence de la plateforme."""
    return hmac.compare_digest(sha256_file(path), expected_hex.lower())