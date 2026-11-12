# Vulnérabilités volontaires — Version Vulnérable

Ce fichier liste les failles laissées intentionnellement dans la branche `vulnerable` pour le Livrable 2. Elles seront exploitées puis corrigées dans la branche `secure` pour le Livrable 3.

## Déjà en place dans cette version

| # | Faille | Fichier | Catégorie OWASP |
|---|---|---|---|
| V1 | Requête SQL par concaténation dans `/register` (email + password_hash) | `app/routes.py` register() | A03 Injection |
| V2 | Requête SQL par concaténation dans `/login` (email) | `app/routes.py` login() | A03 Injection |
| V3 | Pas de jeton CSRF sur les formulaires POST (register, login, upload, share) | tous les templates | A01 CSRF |
| V4 | Cookies de session sans HttpOnly / Secure / SameSite | `app/__init__.py` | A07 Auth fail |
| V5 | `secret_key` hardcodée dans le code source | `app/__init__.py` | A05 Misconfig |
| V6 | Pas de limitation du débit ni de verrouillage sur /login | `app/routes.py` login() | A07 Auth fail |
| V7 | Messages d'erreur révèlent l'existence d'un compte | `app/routes.py` login() | A07 Auth fail |
| V8 | IDOR sur `/download/<file_id>` : pas de vérification de propriété | `app/routes.py` download() | A01 Access control |

## À documenter en ajoutant la crypto (jeudi)

| # | Faille | Fichier | Catégorie OWASP |
|---|---|---|---|
| V9 | Clé AES de chaque fichier stockée en clair en base (`files.aes_key`) | `schema.sql` | A02 Crypto fail |
| V10 | Clé privée ECDSA utilisateur stockée en clair en base | `schema.sql` | A02 Crypto fail |
| V11 | Pas de validation de type / taille sur l'upload | route upload() | A05 Misconfig |
| V12 | Pas d'échappement explicite des noms de fichiers dans les templates | templates | A03 XSS |

## Corrections prévues pour le Livrable 3 (branche `secure`)

- V1, V2 : requêtes paramétrées (`?` placeholders)
- V3 : Flask-WTF avec CSRFProtect
- V4 : `SESSION_COOKIE_HTTPONLY = True`, `SESSION_COOKIE_SECURE = True`, `SESSION_COOKIE_SAMESITE = 'Lax'`, régénération à la connexion
- V5 : clé lue depuis `.env` via `python-dotenv`
- V6 : limitation avec `flask-limiter`, compteur de tentatives dans la BD
- V7 : message générique "Email ou mot de passe incorrect"
- V8 : vérifier `owner_id == session.user_id OR exists(share)`
- V9 : `aes_key` chiffrée par une clé maître en variable d'environnement
- V10 : chiffrée via PBKDF2-HMAC-SHA256(password, salt) à l'inscription, déchiffrée en mémoire à la connexion
- V11 : liste blanche d'extensions, limite 10 Mo, détection MIME, renommage serveur
- V12 : vérifier l'auto-échappement Jinja2, ajouter en-tête Content-Security-Policy
