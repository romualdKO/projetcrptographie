# Fonctionnement de CryptoLink

L'application est lancee par `app.py`. Son interface est construite avec HTML, CSS et JavaScript et sa cryptographie utilise Web Crypto dans le navigateur.

## Architecture

Chaque ordinateur lance localement le meme serveur web :

- le PC destinataire utilise `python app.py --role receiver` ;
- le PC emetteur utilise `python app.py --role sender`.

Les pages s'ouvrent sur `http://127.0.0.1:8765`. Le serveur web n'est lie qu'a la boucle locale. Le PC destinataire ouvre en plus un relais TCP sur le port 5000 pour recevoir les paquets chiffres.

## Cote destinataire

1. Le navigateur genere une paire RSA-OAEP de 2048 bits via Web Crypto.
2. La cle publique est exportee au format PEM.
3. La cle privee PKCS#8 est chiffree dans le navigateur avec AES-256-GCM. La cle de protection est derivee de la phrase secrete par PBKDF2-SHA-256 (310 000 iterations).
4. Le navigateur telecharge `cle_publique.pem` et `cle_privee_protegee.json`.
5. Le destinataire transfere uniquement la cle publique a l'emetteur.
6. Le relais TCP recoit les paquets et les garde temporairement en memoire. Il ne charge aucune cle privee et ne dechiffre rien.

La phrase secrete et la cle privee ne sont pas envoyees au serveur. Pour lire les messages, le navigateur du destinataire ouvre le fichier protege avec la phrase secrete. La cle privee dechiffree reste dans la memoire de cet onglet.

## Cote emetteur

1. L'utilisateur choisit le fichier PEM public et saisit l'adresse IP du destinataire.
2. Le navigateur importe la cle publique et affiche son empreinte SHA-256 pour permettre sa comparaison par un canal de confiance.
3. Web Crypto genere une cle AES-256 aleatoire et un nonce de 12 octets.
4. AES-GCM chiffre le message et RSA-OAEP-SHA-256 chiffre la cle AES.
5. Le navigateur produit le paquet JSON :

```json
{
  "alg": "RSA-OAEP-SHA256+A256GCM",
  "key": "cle AES chiffree par RSA, encodee en Base64",
  "nonce": "nonce AES-GCM, encode en Base64",
  "ciphertext": "message et tag GCM, encodes en Base64"
}
```

6. Le navigateur envoie ce paquet au serveur local de l'emetteur. Python ouvre une connexion TCP vers le PC destinataire et transmet uniquement le JSON chiffre.

Le texte clair n'est pas inclus dans les requetes HTTP ou TCP. Le chiffrement est effectue localement par le navigateur avant le transfert.

## Reception et dechiffrement

1. Le relais TCP reassemble les octets recus jusqu'a la fermeture de la connexion, verifie la taille et le format, puis ajoute le paquet dans une file en memoire.
2. La page du destinataire interroge cette file toutes les 1,2 secondes lorsqu'elle est visible.
3. Le navigateur dechiffre la cle AES avec la cle privee RSA qu'il a deverrouillee localement.
4. AES-GCM dechiffre le texte et verifie le tag d'authenticite des donnees. Un paquet modifie ou une mauvaise cle provoque un echec au lieu d'afficher un texte altere.
5. Apres un dechiffrement reussi, la page accuse reception au relais, qui retire le paquet de la file.

## Performance et limites

- L'interface n'utilise aucun framework ni paquet front-end a telecharger ; elle est servie directement depuis les fichiers locaux.
- Les operations cryptographiques sont asynchrones et deleguees a Web Crypto.
- La reception se fait dans un thread Python separe de l'interface HTTP.
- Le serveur garde au maximum 100 paquets en attente et limite leur taille. La file n'est pas persistante : un redemarrage efface les messages non lus.
- Pour des raisons de securite navigateur, ouvrir l'application via `127.0.0.1` est requis pour Web Crypto.

## Garanties et limites de securite

- RSA-OAEP protege la cle AES ; AES-GCM chiffre le message et detecte sa modification.
- PBKDF2 et AES-GCM protegent le fichier de cle privee au repos. La force pratique depend aussi de la phrase secrete choisie.
- L'application n'authentifie pas l'expediteur et ne certifie pas l'identite de la cle publique. Il faut comparer son empreinte par un canal de confiance.
- Le relais TCP n'utilise pas TLS ; le paquet reste chiffre de bout en bout, mais le protocole ne fournit pas de protection generale contre le deni de service.
