"""Tests unitaires + scénario d'attaque Alice/Bob (modules crypto, hash, signature, PKI)."""
import datetime as dt
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from security import crypto, hashing, signature, certificates as pki  # noqa: E402


# ---------------------------------------------------------------- AES-GCM --
def test_aes_gcm_roundtrip():
    key = crypto.generate_file_key()
    nonce, ct = crypto.encrypt_bytes(key, b"contrat confidentiel")
    assert crypto.decrypt_bytes(key, nonce, ct) == b"contrat confidentiel"


def test_nonce_unique_a_chaque_chiffrement():
    key = crypto.generate_file_key()
    nonces = {crypto.encrypt_bytes(key, b"x")[0] for _ in range(1000)}
    assert len(nonces) == 1000


def test_altération_du_chiffre_detectee():
    key = crypto.generate_file_key()
    nonce, ct = crypto.encrypt_bytes(key, b"facture")
    tampered = bytes([ct[0] ^ 1]) + ct[1:]
    with pytest.raises(crypto.IntegrityError):
        crypto.decrypt_bytes(key, nonce, tampered)


def test_mauvaise_cle_refusee():
    nonce, ct = crypto.encrypt_bytes(crypto.generate_file_key(), b"data")
    with pytest.raises(crypto.IntegrityError):
        crypto.decrypt_bytes(crypto.generate_file_key(), nonce, ct)


def test_stockage_disque_nom_aleatoire_et_path_traversal(tmp_path):
    key = crypto.generate_file_key()
    name, nonce = crypto.encrypt_file_to_disk(key, b"PDF", str(tmp_path))
    assert name.endswith(".bin")
    assert b"PDF" not in (tmp_path / name).read_bytes()
    assert crypto.decrypt_file_from_disk(key, nonce, str(tmp_path), name) == b"PDF"
    with pytest.raises(ValueError):
        crypto.decrypt_file_from_disk(key, nonce, str(tmp_path), "../../etc/passwd")


def test_wrap_cle_maitre():
    master, fk = os.urandom(32), crypto.generate_file_key()
    assert crypto.unwrap_key(master, crypto.wrap_key(master, fk)) == fk
    with pytest.raises(crypto.IntegrityError):
        crypto.unwrap_key(os.urandom(32), crypto.wrap_key(master, fk))


def test_cle_privee_chiffree_par_mot_de_passe():
    k = signature.generate_keypair()
    blob = crypto.encrypt_private_key(k, "Mot-de-passe-Fort-12!")
    assert b"PRIVATE KEY" not in blob
    k2 = crypto.decrypt_private_key(blob, "Mot-de-passe-Fort-12!")
    assert k2.private_numbers() == k.private_numbers()
    with pytest.raises(crypto.IntegrityError):
        crypto.decrypt_private_key(blob, "mauvais")


# ---------------------------------------------------------------- SHA-256 --
def test_sha256_valeur_connue():
    assert hashing.sha256_bytes(b"abc") == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")


def test_sha256_fichier_et_comparaison(tmp_path):
    p = tmp_path / "f.bin"
    p.write_bytes(b"A" * 200_000)
    ref = hashing.sha256_bytes(b"A" * 200_000)
    assert hashing.sha256_file(str(p)) == ref
    assert hashing.verify_file_hash(str(p), ref)
    p.write_bytes(b"A" * 199_999 + b"B")
    assert not hashing.verify_file_hash(str(p), ref)


# -------------------------------------------------------------- Signature --
def test_signature_valide_et_invalide():
    k = signature.generate_keypair()
    h = hashing.sha256_bytes(b"document")
    sig = signature.sign_hash(k, h)
    assert signature.verify_signature(k.public_key(), sig, h)
    assert not signature.verify_signature(k.public_key(), sig, hashing.sha256_bytes(b"autre"))
    assert not signature.verify_signature(signature.generate_keypair().public_key(), sig, h)
    assert not signature.verify_signature(k.public_key(), sig[:-1] + b"\x00", h)


# -------------------------------------------------------------- Certificats --
@pytest.fixture(scope="module")
def ca(tmp_path_factory):
    d = str(tmp_path_factory.mktemp("ca"))
    return pki.create_ca(ca_dir=d, passphrase=b"ca-pass"), d


def _user(ca_key, ca_cert, email, days=365):
    k = signature.generate_keypair()
    return k, pki.issue_user_certificate(k.public_key(), email, ca_key, ca_cert, days)


def test_certificat_valide(ca):
    (ca_key, ca_cert), _ = ca
    _, pem = _user(ca_key, ca_cert, "alice@example.com")
    cert = pki.verify_certificate(pem, ca_cert, expected_email="alice@example.com")
    assert "alice@example.com" in pki.certificate_info(cert)["subject"]


def test_certificat_expire_refuse(ca):
    (ca_key, ca_cert), _ = ca
    _, pem = _user(ca_key, ca_cert, "bob@example.com", days=1)
    futur = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=3)
    with pytest.raises(pki.CertificateError, match="expiré"):
        pki.verify_certificate(pem, ca_cert, at=futur)


def test_certificat_forge_par_fausse_ac_refuse(ca):
    (_, ca_cert), _ = ca
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        fake_key, fake_cert = pki.create_ca("SecureShare Local CA", ca_dir=d)
    _, pem = _user(fake_key, fake_cert, "mallory@example.com")
    with pytest.raises(pki.CertificateError, match="forgé"):
        pki.verify_certificate(pem, ca_cert)   # même nom d'AC, mauvaise clé


def test_certificat_mauvaise_identite_refuse(ca):
    (ca_key, ca_cert), _ = ca
    _, pem = _user(ca_key, ca_cert, "alice@example.com")
    with pytest.raises(pki.CertificateError, match="correspond"):
        pki.verify_certificate(pem, ca_cert, expected_email="bob@example.com")


def test_certificat_ac_refuse_comme_utilisateur(ca):
    (_, ca_cert), _ = ca
    from cryptography.hazmat.primitives import serialization
    pem = ca_cert.public_bytes(serialization.Encoding.PEM)
    with pytest.raises(pki.CertificateError):
        pki.verify_certificate(pem, ca_cert)


def test_rechargement_ac(ca):
    (_, ca_cert), d = ca
    _, cert2 = pki.load_ca(d, passphrase=b"ca-pass")
    assert cert2.serial_number == ca_cert.serial_number


# --------------------------------------------- Scénario complet Alice → Bob --
def test_scenario_alice_bob(ca, tmp_path):
    (ca_key, ca_cert), _ = ca
    master = os.urandom(32)
    storage = str(tmp_path / "storage")

    alice_k, alice_pem = _user(ca_key, ca_cert, "alice@example.com")
    bob_k, bob_pem = _user(ca_key, ca_cert, "bob@example.com")
    eve_k, _ = _user(ca_key, ca_cert, "eve@example.com")

    # Flux A : Alice dépose
    pdf = b"%PDF-1.7 contrat tres confidentiel"
    fk = crypto.generate_file_key()
    stored, nonce = crypto.encrypt_file_to_disk(fk, pdf, storage)
    digest = hashing.sha256_bytes(pdf)
    sig = signature.sign_hash(alice_k, digest)
    wrapped_owner = crypto.wrap_key(master, fk)

    # Flux C : Alice partage avec Bob (certificat de Bob validé d'abord)
    bob_cert = pki.verify_certificate(bob_pem, ca_cert, "bob@example.com")
    wrapped_bob = crypto.wrap_key_for_recipient(
        alice_k, pki.certificate_public_key(bob_cert),
        crypto.unwrap_key(master, wrapped_owner))

    # Flux B : Bob télécharge et vérifie
    alice_cert = pki.verify_certificate(alice_pem, ca_cert, "alice@example.com")
    fk_bob = crypto.unwrap_key_as_recipient(
        bob_k, pki.certificate_public_key(alice_cert), wrapped_bob)
    clair = crypto.decrypt_file_from_disk(fk_bob, nonce, storage, stored)
    assert clair == pdf
    assert hashing.verify_hash(clair, digest)
    assert signature.verify_signature(pki.certificate_public_key(alice_cert), sig, digest)

    # Eve ne peut pas déchiffrer la clé de Bob
    with pytest.raises(crypto.IntegrityError):
        crypto.unwrap_key_as_recipient(
            eve_k, pki.certificate_public_key(alice_cert), wrapped_bob)

    # Attaque : fichier modifié sur le disque -> tag GCM invalide
    path = os.path.join(storage, stored)
    data = bytearray(open(path, "rb").read())
    data[5] ^= 0xFF
    open(path, "wb").write(bytes(data))
    with pytest.raises(crypto.IntegrityError):
        crypto.decrypt_file_from_disk(fk_bob, nonce, storage, stored)