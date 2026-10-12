# CryptoLink - messagerie chiffree

Application locale de messagerie utilisant RSA-OAEP et AES-GCM. L'interface principale est une page HTML/CSS/JavaScript, sans React, Tailwind ni installation npm. La cryptographie est executee par Web Crypto dans le navigateur.

## Fichiers

- `app.py` : serveur web local et relais TCP des paquets chiffres.
- `web/index.html`, `web/styles.css`, `web/app.js` : interface responsive et chiffrement cote navigateur.
- `FONCTIONNEMENT.md` : details du flux et des choix techniques.

## Prerequis

- Python 3.9 ou plus recent recommande.
- Navigateur moderne avec Web Crypto (Edge, Chrome ou Firefox).
- Aucun paquet Python supplementaire pour l'interface web.

## Lancer sur deux PC

### PC destinataire

Dans le dossier du projet :

```powershell
python app.py --role receiver
```

La page s'ouvre sur `http://127.0.0.1:8765`. Dans la page, saisis une phrase secrete d'au moins 10 caracteres, puis clique sur **Generer une paire RSA**. Deux fichiers sont telecharges :

- `cle_publique.pem` : a transmettre au PC emetteur.
- `cle_privee_protegee.json` : a garder sur le PC destinataire avec sa phrase secrete.

Le relais recoit automatiquement sur TCP `5000`. L'adresse IP locale a communiquer a l'emetteur est affichee dans le terminal.

### PC emetteur

Copie le projet sur l'autre PC, puis lance :

```powershell
python app.py --role sender
```

Dans la page, saisis l'IP du destinataire, choisis `cle_publique.pem`, ecris le message et clique sur **Chiffrer et envoyer**.

Le PC destinataire doit autoriser les connexions entrantes TCP sur le port `5000` dans son pare-feu. `127.0.0.1` ne fonctionne que si les deux roles tournent sur le meme PC.

## Securite et limites

- RSA-OAEP-SHA256 protege une cle AES aleatoire; AES-256-GCM chiffre et authentifie le contenu.
- La cle privee est chiffree localement avec PBKDF2-SHA256 et AES-256-GCM. Elle n'est jamais envoyee au relais.
- Le relais ne garde les paquets qu'en memoire; les messages en attente sont perdus si le processus s'arrete.
- La phrase secrete ne peut pas etre recuperee. Conserve-la separement du fichier de cle privee.
- Ce projet pedagogique n'authentifie pas l'expediteur et ne verifie pas automatiquement l'identite de la cle publique. Compare son empreinte via un canal de confiance.
- Le relais TCP est destine a un reseau local de confiance; il n'inclut ni TLS, ni signature d'expediteur, ni protection contre le deni de service.

## Options

```powershell
python app.py --role receiver --port 8765 --tcp-port 5000
python app.py --role sender --port 8765 --no-browser
```

Le serveur web reste lie a `127.0.0.1`; seule l'ecoute TCP du destinataire est accessible sur le reseau local.
