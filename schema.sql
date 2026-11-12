-- Schema for secure file-sharing app
-- VULNERABLE version: some columns store secrets in clear (documented in docs/vulnerabilities_known.md)

DROP TABLE IF EXISTS shares;
DROP TABLE IF EXISTS files;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    email               TEXT UNIQUE NOT NULL,
    password_hash       TEXT NOT NULL,              -- bcrypt
    public_key_pem      TEXT,                       -- ECDSA P-256 public key (filled by Ines's code)
    private_key_pem     TEXT,                       -- VULN: stored in clear (to be fixed in Livrable 3)
    certificate_pem     TEXT,                       -- X.509 cert signed by local CA
    created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE files (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id            INTEGER NOT NULL,
    original_name       TEXT NOT NULL,
    stored_name         TEXT NOT NULL,              -- UUID filename in /storage
    nonce               BLOB NOT NULL,              -- 12-byte AES-GCM nonce
    aes_key             BLOB NOT NULL,              -- VULN: stored in clear (to be wrapped in Livrable 3)
    sha256_hash         TEXT NOT NULL,              -- hex digest of plaintext
    signature           BLOB NOT NULL,              -- ECDSA signature over sha256_hash
    created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (owner_id) REFERENCES users(id)
);

CREATE TABLE shares (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id             INTEGER NOT NULL,
    recipient_id        INTEGER NOT NULL,
    granted_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (file_id) REFERENCES files(id),
    FOREIGN KEY (recipient_id) REFERENCES users(id)
);
