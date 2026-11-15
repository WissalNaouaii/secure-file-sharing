# Secure File Sharing : Projet Sécurité Informatique GLSI 3_4

Application Flask locale de partage sécurisé de fichiers.

**Binôme :** Wissal Naouai (application et accès) et Ines Jridi (cryptographie, PKI, tests).
**Professeure :** Rabeb Ben Othmen

> **Branche `vulnerable` (Livrable 2).** Cette version contient des failles volontaires, listées dans `docs/vulnerabilities_known.md`. Elle ne doit tourner qu'en local.

## Installation

```
python -m venv venv
venv\Scripts\Activate.ps1        (Linux / macOS : source venv/bin/activate)
pip install -r requirements.txt
```

## Lancement

```
python init_db.py      crée app.db et le dossier storage/
python seed.py         crée Alice, Bob et un fichier partagé (données fictives)
python run.py          http://127.0.0.1:5000
```

L'autorité de certification locale est créée automatiquement dans `pki/ca/` à la première inscription. Les scripts `pki/init_ca.sh` et `pki/issue_cert.sh` font la même chose avec OpenSSL en ligne de commande (à lancer depuis Git Bash sous Windows).

Comptes de démonstration : `alice@example.com` / `Alice-Demo-2026!` et `bob@example.com` / `Bob-Demo-2026!`

## Tests

```
python -m pytest tests -v
```

## Scénario de démonstration

1. Alice se connecte, dépose un PDF : il est chiffré (AES-256-GCM), son empreinte SHA-256 est calculée puis signée (ECDSA P-256).
2. Alice le partage avec Bob.
3. Bob se connecte, clique sur « Vérifier » : certificat d'Alice, déchiffrement, intégrité et signature sont contrôlés.
4. Falsification : modifier un octet du fichier `.bin` dans `storage/`, puis recliquer sur « Vérifier » : l'échec est signalé et journalisé dans `audit.log`.

## Structure

```
app/            routes Flask, templates
security/       crypto.py (AES-GCM, clés), hashing.py (SHA-256),
                signature.py (ECDSA), certificates.py (X.509, AC locale)
pki/            scripts OpenSSL de l'AC locale
tests/          tests unitaires et scénario Alice / Bob
docs/           failles volontaires
storage/        fichiers chiffrés (hors Git)
```

## Branches

- `vulnerable` : Livrable 2 (cette branche)
- `secure` : Livrable 3, version corrigée
