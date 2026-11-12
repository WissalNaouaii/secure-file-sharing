# Secure File Sharing — Projet Sécurité Informatique GLSI 3_4

Application Flask de partage sécurisé de fichiers.
**Binôme :** Wissal Naouai (app) & Ines Jridi (crypto + PKI).

> ⚠️ **Branche `vulnerable`** : version contenant des failles volontaires pour le Livrable 2.
> Ne jamais déployer en production. Voir `docs/vulnerabilities_known.md`.

## Installation

```bash
python -m venv venv
source venv/bin/activate      # Windows : venv\Scripts\activate
pip install -r requirements.txt
```

## Lancer

```bash
python init_db.py             # crée app.db + /storage
bash pki/setup_ca.sh          # crée l'AC locale (quand Ines l'a poussée)
python run.py                 # http://127.0.0.1:5000
```

## Structure

```
app/            Flask app (routes, templates)
security/       crypto helpers (AES-GCM, SHA-256, ECDSA)
pki/            scripts OpenSSL pour l'AC locale
storage/        fichiers chiffrés (gitignored)
docs/           documentation (vulnérabilités connues)
schema.sql      tables SQLite
init_db.py      création de la BD
run.py          point d'entrée
```

## Branches Git

- `main` : squelette commun
- `vulnerable` : **livrable 2** (cette branche)
- `secure` : livrable 3 (créée après le 15/11)
