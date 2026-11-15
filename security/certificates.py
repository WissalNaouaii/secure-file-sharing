"""Gestion des certificats X.509 : AC locale, émission, validation de chaîne.

Équivalent Python des scripts OpenSSL de pki/ (voir pki/init_ca.sh).
Contre-mesure R11 : certificat forgé ou expiré accepté.
"""
import datetime as dt
import os

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

CA_VALIDITY_DAYS = 3650
USER_VALIDITY_DAYS = 365


class CertificateError(Exception):
    """Certificat invalide, expiré, forgé ou à usage incorrect."""


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


# ------------------------------------------------------------------- AC ----
def create_ca(common_name: str = "SecureShare Local CA", ca_dir: str = "pki/ca",
              passphrase: bytes | None = None):
    """Crée l'AC locale (clé + certificat auto-signé). Retourne (clé, cert)."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "TN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureShare"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_now() - dt.timedelta(minutes=1))
            .not_valid_after(_now() + dt.timedelta(days=CA_VALIDITY_DAYS))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                           critical=False)
            .sign(key, hashes.SHA256()))

    os.makedirs(ca_dir, exist_ok=True)
    enc = (serialization.BestAvailableEncryption(passphrase) if passphrase
           else serialization.NoEncryption())
    key_path = os.path.join(ca_dir, "ca.key.pem")
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.PKCS8, enc))
    os.chmod(key_path, 0o600)      # la clé de l'AC ne va JAMAIS dans Git
    with open(os.path.join(ca_dir, "ca.cert.pem"), "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    return key, cert


def load_ca(ca_dir: str = "pki/ca", passphrase: bytes | None = None):
    with open(os.path.join(ca_dir, "ca.key.pem"), "rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=passphrase)
    with open(os.path.join(ca_dir, "ca.cert.pem"), "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    return key, cert


# ------------------------------------------------------------- émission ----
def issue_user_certificate(user_public_key: ec.EllipticCurvePublicKey, email: str,
                           ca_key: ec.EllipticCurvePrivateKey,
                           ca_cert: x509.Certificate,
                           days: int = USER_VALIDITY_DAYS) -> bytes:
    """Émet un certificat utilisateur signé par l'AC. Retourne le PEM."""
    subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureShare"),
        x509.NameAttribute(NameOID.COMMON_NAME, email),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, email),
    ])
    cert = (x509.CertificateBuilder()
            .subject_name(subject).issuer_name(ca_cert.subject)
            .public_key(user_public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(_now() - dt.timedelta(minutes=1))
            .not_valid_after(_now() + dt.timedelta(days=days))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            # Usage de clé : signature (ECDSA) + accord de clé (ECDH pour le partage)
            .add_extension(x509.KeyUsage(
                digital_signature=True, key_agreement=True,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.EMAIL_PROTECTION]),
                           critical=False)
            .add_extension(x509.SubjectAlternativeName([x509.RFC822Name(email)]),
                           critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
                ca_cert.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM)


# ----------------------------------------------------------- validation ----
def load_certificate(pem: bytes) -> x509.Certificate:
    return x509.load_pem_x509_certificate(pem)


def verify_certificate(cert_pem: bytes, ca_cert: x509.Certificate,
                       expected_email: str | None = None,
                       at: dt.datetime | None = None) -> x509.Certificate:
    """Valide : chaîne (signature de l'AC), dates, usage de clé, identité.

    Retourne le certificat si valide, lève CertificateError sinon.
    """
    cert = load_certificate(cert_pem)
    at = at or _now()

    # 1. Émetteur attendu + signature de l'AC (empêche un certificat forgé)
    if cert.issuer != ca_cert.subject:
        raise CertificateError("Émetteur inconnu : certificat non émis par l'AC locale")
    try:
        ca_cert.public_key().verify(cert.signature, cert.tbs_certificate_bytes,
                                    ec.ECDSA(cert.signature_hash_algorithm))
    except InvalidSignature as exc:
        raise CertificateError("Signature de l'AC invalide (certificat forgé)") from exc

    # 2. Période de validité notBefore / notAfter
    if at < cert.not_valid_before_utc:
        raise CertificateError("Certificat pas encore valide")
    if at > cert.not_valid_after_utc:
        raise CertificateError("Certificat expiré")

    # 3. Usage de clé et contraintes de base
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound as exc:
        raise CertificateError("Extensions obligatoires absentes") from exc
    if bc.ca:
        raise CertificateError("Un certificat utilisateur ne doit pas être une AC")
    if not ku.digital_signature:
        raise CertificateError("Usage de clé : signature numérique non autorisée")

    # 4. Identité (le certificat appartient bien à l'utilisateur attendu)
    if expected_email is not None:
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if not cn or cn[0].value != expected_email:
            raise CertificateError("Le certificat ne correspond pas à l'utilisateur attendu")
    return cert


def certificate_public_key(cert: x509.Certificate) -> ec.EllipticCurvePublicKey:
    return cert.public_key()


def certificate_info(cert: x509.Certificate) -> dict:
    """Infos affichables dans l'UI de vérification."""
    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial": format(cert.serial_number, "x"),
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
    }