# Vulnérabilités volontaires : version vulnérable (Livrable 2)

Failles laissées intentionnellement dans la branche `vulnerable`. Elles seront exploitées (preuves) puis corrigées dans la branche `secure` pour le Livrable 3.

| # | Faille | Où | Catégorie OWASP | Correctif prévu (branche `secure`) |
|---|---|---|---|---|
| V1 | Requête SQL par concaténation à l'inscription | `app/routes.py` register() | A03 Injection | Requêtes paramétrées |
| V2 | Requête SQL par concaténation à la connexion | `app/routes.py` login() | A03 Injection | Requêtes paramétrées |
| V3 | Aucun jeton CSRF sur les formulaires POST | tous les templates | A01 Broken Access Control | Flask-WTF CSRFProtect, SameSite |
| V4 | Cookie de session sans Secure ni SameSite, pas de régénération ni d'expiration | `app/__init__.py` | A07 Auth Failures | Cookies durcis, régénération à la connexion, expiration 30 min |
| V5 | `secret_key` écrite dans le code source | `app/__init__.py` | A05 Misconfiguration | Clé lue depuis une variable d'environnement |
| V6 | Pas de limitation des tentatives de connexion | `app/routes.py` login() | A07 Auth Failures | Compteur d'échecs, verrouillage après 5 essais |
| V7 | Messages d'erreur qui révèlent l'existence d'un compte, erreurs SQL affichées | `app/routes.py` login() | A07 Auth Failures | Message générique |
| V8 | IDOR : `/download/<id>`, `/verify/<id>` et `/share/<id>` sans contrôle des droits | `app/routes.py` | A01 Broken Access Control | Vérification propriétaire ou partage actif, réponse 403 |
| V9 | Clé AES de chaque fichier stockée en clair en base (`files.aes_key`) | `app/routes.py` upload() | A02 Cryptographic Failures | `crypto.wrap_key` avec clé maître en variable d'environnement, `wrap_key_for_recipient` (ECDH, HKDF) pour le partage |
| V10 | Clé privée ECDSA de l'utilisateur stockée en clair en base | `app/routes.py` register() | A02 Cryptographic Failures | `crypto.encrypt_private_key` (PBKDF2 + AES-GCM) |
| V11 | Aucun contrôle du type, de la taille ni du nom du fichier déposé | `app/routes.py` upload() | A04 Insecure Design | Liste blanche d'extensions, limite 10 Mo, détection MIME |
| V12 | Nom de fichier affiché sans échappement (XSS stocké) | `app/templates/dashboard.html` | A03 Injection | Retrait du filtre `safe`, en-tête Content-Security-Policy |
| V13 | Clé privée de l'AC non chiffrée sur disque (créée sans passphrase) | `pki/ca/` | A02 Cryptographic Failures | Passphrase obligatoire (`CA_PASSPHRASE`) |
| V14 | Serveur lancé en mode debug (console Werkzeug accessible) | `run.py` | A05 Misconfiguration | `debug=False` |
| V15 | Pas de politique de mots de passe | `app/routes.py` register() | A07 Auth Failures | 12 caractères minimum, 4 classes |

## Ce qui est déjà solide dans cette version

Les mécanismes cryptographiques eux-mêmes sont corrects et testés (`tests/test_security.py`) : AES-256-GCM avec nonce aléatoire de 96 bits par chiffrement, SHA-256 comparé en temps constant, signature ECDSA P-256, certificats X.509 validés (chaîne, dates, usage, identité). Les failles ci-dessus portent sur l'application Web et sur le stockage des clés, pas sur les algorithmes.

Les fonctions de la version sécurisée existent déjà dans `security/crypto.py` (enveloppement par clé maître, partage hybride, chiffrement de la clé privée) ; elles ne sont pas encore branchées dans les routes.
