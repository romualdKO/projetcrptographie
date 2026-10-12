# Guide d'utilisation de CryptoLink

Ce guide explique comment lancer CryptoLink et echanger un message chiffre. Il couvre l'utilisation sur deux ordinateurs et le test sur un seul ordinateur.

## 1. Prerequis

- Python 3.9 ou une version plus recente.
- Un navigateur recent : Chrome, Edge ou Firefox.
- Les fichiers du projet, notamment `app.py` et le dossier `web`.
- Les deux ordinateurs sur le meme reseau local pour un echange entre machines.

L'interface web n'a pas besoin de React, Tailwind, Node.js ni d'installation de paquets Python. Web Crypto doit etre ouvert depuis `http://127.0.0.1` ; ne pas ouvrir directement le fichier HTML.

## 2. Demarrer le recepteur

Sur le PC qui doit recevoir les messages :

1. Ouvre PowerShell dans le dossier du projet.
2. Lance :

```powershell
python app.py --role receiver
```

3. La page du recepteur s'ouvre sur `http://127.0.0.1:8765`.
4. Laisse la fenetre PowerShell ouverte pendant l'utilisation.

Le serveur web reste local a l'ordinateur. En parallele, le programme ouvre le port TCP `5000` sur le reseau local pour recevoir les paquets chiffres. L'adresse IP a donner a l'emetteur est affichee dans PowerShell.

## 3. Creer les cles du destinataire

Dans la page du recepteur :

1. Saisis une phrase secrete d'au moins 10 caracteres.
2. Clique sur **Generer une paire RSA**.
3. Le navigateur telecharge deux fichiers :
   - `cle_publique.pem` : cette cle peut etre transmise a l'emetteur.
   - `cle_privee_protegee.json` : garde ce fichier sur le PC recepteur.
4. Conserve la phrase secrete separement du fichier prive. Elle est indispensable pour deverrouiller la cle.

La cle privee est protegee dans le navigateur avant son telechargement. Ne transmets jamais le fichier de cle privee ni sa phrase secrete. Si tu perds la phrase secrete, le fichier de cle privee ne pourra pas etre ouvert.

## 4. Demarrer l'emetteur

Sur le PC qui envoie le message :

1. Copie le projet sur cet ordinateur.
2. Ouvre PowerShell dans le dossier du projet et lance :

```powershell
python app.py --role sender
```

3. La page de l'emetteur s'ouvre sur `http://127.0.0.1:8765`.

Si l'emetteur et le recepteur tournent sur deux PC differents, chaque application utilise son propre port web `8765`. C'est normal : `127.0.0.1` designe toujours l'ordinateur courant.

## 5. Envoyer un message

Dans la page de l'emetteur :

1. Dans **Adresse IP du destinataire**, saisis l'adresse affichee dans le terminal du PC recepteur.
2. Dans **Cle publique RSA**, choisis `cle_publique.pem` transfere depuis le recepteur.
3. Compare l'empreinte SHA-256 affichee avec celle du destinataire par un canal de confiance (appel, rencontre ou autre canal deja authentifie).
4. Ecris le message.
5. Clique sur **Chiffrer et envoyer**.

Le message est chiffre dans le navigateur avant son transfert. Le texte clair n'est pas envoye au serveur web ni au relais TCP.

## 6. Lire le message

Dans la page du recepteur :

1. Selectionne `cle_privee_protegee.json`.
2. Saisis la phrase secrete utilisee lors de la generation.
3. Clique sur **Deverrouiller la cle**.
4. Le message dechiffre apparait dans **Messages recus**.

Le relais retire le paquet de sa file apres un dechiffrement reussi. La cle privee dechiffree reste dans la memoire de l'onglet du navigateur ; si tu fermes ou actualises cet onglet, deverrouille de nouveau la cle.

## 7. Tester sur un seul ordinateur

Ouvre deux fenetres PowerShell dans le meme dossier.

Dans la premiere, lance le recepteur avec un port web different :

```powershell
python app.py --role receiver --port 8766 --tcp-port 5000
```

Dans la seconde, lance l'emetteur :

```powershell
python app.py --role sender --port 8765 --tcp-port 5000
```

Utilise `127.0.0.1` comme adresse du destinataire. Genere les cles dans le navigateur du recepteur, puis charge la cle publique dans l'emetteur.

## 8. Depannage

### « Web Crypto indisponible »

Ouvre l'adresse locale `http://127.0.0.1:8765` ou celle indiquee par le terminal. Ne lance pas la page en double-cliquant sur `index.html`.

### La connexion au recepteur echoue

- Verifie que le recepteur est lance et que PowerShell est toujours ouvert.
- Sur deux PC, utilise l'adresse IP locale du recepteur et non `127.0.0.1`.
- Autorise les connexions entrantes TCP sur le port `5000` dans le pare-feu du recepteur.
- Verifie que les deux PC sont sur le meme reseau local.

### Le message ne peut pas etre dechiffre

- Verifie que la cle publique chargee par l'emetteur appartient a la cle privee du recepteur.
- Verifie la phrase secrete et le bon fichier prive.
- Si tu as remplace la paire de cles, les anciens messages adresses a l'ancienne cle ne pourront plus etre ouverts avec la nouvelle.

### Arreter l'application

Dans chaque fenetre PowerShell, appuie sur `Ctrl+C`. Les messages encore en attente sont stockes uniquement en memoire et sont perdus quand le serveur recepteur s'arrete.

## Rappels de securite

- Partage uniquement `cle_publique.pem`.
- Ne partage jamais `cle_privee_protegee.json` ni la phrase secrete.
- Compare l'empreinte de la cle publique par un canal fiable.
- Ce projet pedagogique ne signe pas les messages et n'authentifie pas l'expediteur.