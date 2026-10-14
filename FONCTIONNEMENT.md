# Fonctionnement detaille du projet CryptoLink

Ce document presente les objectifs du projet, son architecture, le role de chaque fonction de `app.py`, le parcours cryptographique d'un message et l'utilisation de chaque partie des interfaces.

## 1. Objectifs du projet

### Objectif general

Concevoir une application de demonstration qui permet a deux personnes d'echanger un message chiffre sur un reseau local, sans transmettre le texte en clair ni partager la cle privee du destinataire.

### Objectifs specifiques

- Mettre en pratique une paire de cles RSA publique/privee.
- Utiliser un chiffrement hybride : RSA-OAEP protege une cle AES temporaire et AES-GCM chiffre le message.
- Generer la paire de cles dans le navigateur du destinataire.
- Proteger la cle privee exportee par une phrase secrete.
- Transporter uniquement un paquet chiffre entre les deux ordinateurs.
- Proposer trois vues distinctes : accueil, emetteur et recepteur.
- Fournir une interface responsive, avec des animations legeres et accessibles.
- Montrer les limites d'un prototype par rapport a une messagerie de production.

## 2. Vue d'ensemble

CryptoLink est constitue de deux parties qui cooperent :

1. `app.py` sert l'interface web en local et fait office de relais TCP sur le PC destinataire.
2. Le navigateur execute les interfaces HTML/CSS/JavaScript et les operations cryptographiques avec Web Crypto.

Les principales routes sont :

| Route | Fonction |
| --- | --- |
| `/` | Accueil, presentation du parcours et choix du role actif. |
| `/emetteur` | Chargement de la cle publique, composition et envoi du message. |
| `/recepteur` | Generation ou deverrouillage des cles et lecture des messages. |

Le serveur n'active qu'un role a la fois. Pour utiliser les deux roles sur le meme ordinateur, il faut lancer deux processus avec des ports web differents. Sur deux ordinateurs, chacun peut utiliser le port web `8765`, car chaque serveur web ecoute uniquement sur son propre `127.0.0.1`.

## 3. Fichiers du projet

- `app.py` : serveur HTTP local, relais TCP et gestion de la file de reception.
- `web/index.html` : structure des trois vues et de leurs controles.
- `web/styles.css` : couleurs, mise en page responsive, animations et etats visuels.
- `web/app.js` : navigation par role, chiffrement/dechiffrement Web Crypto et interactions.
- `README.md` : presentation et commandes de lancement.
- `GUIDE_UTILISATION.md` : guide pratique pas a pas.
- `RAPPORT_PROJET.md` : rapport technique a personnaliser.

## 4. Explication du code `app.py`

### 4.1 Imports et constantes

`argparse` lit les options de lancement. `http.server` sert les pages et les API locales. `socket` gere TCP, `threading` separe la reception des requetes HTTP, `json` lit les paquets, `ipaddress` valide l'adresse de destination, et `uuid` cree un identifiant de message.

Les constantes definissent notamment :

- `WEB_DIR` : dossier contenant les ressources du navigateur.
- `MAX_PACKET_SIZE` : taille maximale d'un paquet TCP (1 Mio).
- `MAX_HTTP_BODY` : taille maximale d'une requete HTTP envoyee au serveur local.
- `PACKET_ALGORITHM` : identifiant du format RSA-OAEP-SHA256 + AES-256-GCM.
- `INBOX` et `INBOX_LOCK` : file temporaire des paquets et verrou pour proteger ses acces.
- `LISTENER_STATE` : indique si l'ecoute TCP est prete ou a echoue.
- `APP_ROLE` et `TCP_PORT` : role courant et port de communication, TCP 5000 par defaut.

### 4.2 `is_valid_packet(packet)`

Cette fonction controle la structure du paquet recu avant de l'accepter. Elle exige le bon identifiant d'algorithme, des champs texte `key`, `nonce` et `ciphertext`, un nonce encode de la longueur attendue et des tailles maximales. Elle ne dechiffre rien et ne peut pas prouver l'identite de l'expediteur.

### 4.3 `receive_loop()`

Cette boucle tourne dans un thread dedie sur le PC lance en role `receiver`.

1. Elle cree un socket TCP, ecoute sur toutes les interfaces reseau au port choisi et accepte une connexion a la fois.
2. Elle lit les blocs jusqu'a la fermeture de la connexion, avec un delai d'attente et une limite de taille.
3. Elle decode le JSON et appelle `is_valid_packet`.
4. Si le paquet est valide, elle l'ajoute a `INBOX` avec un identifiant, l'heure et l'adresse IP source.
5. Elle limite la file a 100 messages et protege les modifications avec `INBOX_LOCK`.

La file est en memoire : les paquets non lus disparaissent a l'arret du processus.

### 4.4 `RequestHandler`

Cette classe traite les requetes HTTP.

- `log_message(...)` desactive les journaux HTTP standards pour eviter du bruit dans le terminal.
- `send_bytes(...)` renvoie un contenu et ajoute les en-tetes de securite : pas de cache, protection MIME, politique de referent et Content Security Policy qui limite les scripts, feuilles de style et connexions a l'origine locale.
- `send_json(...)` encode une reponse API au format JSON.
- `read_json()` lit le corps d'une requete, verifie sa taille et rejette un JSON invalide.
- `do_GET()` sert `index.html`, `styles.css`, `app.js`, l'etat `/api/status`, et la file `/api/inbox` uniquement en role recepteur.
- `do_POST()` n'autorise que les routes compatibles avec le role : `/api/send` pour l'emetteur et `/api/ack` pour le recepteur.
- `send_packet()` valide l'adresse IP et le paquet, ouvre une connexion TCP au destinataire, envoie les octets chiffres et renvoie une reponse de succes ou une erreur reseau.
- `acknowledge_packet()` supprime de la file le paquet confirme apres son dechiffrement.

### 4.5 Serveur HTTP et `main()`

`LocalHTTPServer` autorise plusieurs requetes HTTP simultanees et reutilise le port apres l'arret.

`main()` lit les options :

```powershell
python app.py --role receiver --port 8765 --tcp-port 5000
python app.py --role sender --port 8765
```

- `--role` choisit `sender` ou `receiver`.
- `--port` choisit le port de l'interface web, `8765` par defaut.
- `--tcp-port` choisit le port d'echange TCP, `5000` par defaut.
- `--no-browser` empeche l'ouverture automatique du navigateur.

En role recepteur, `main()` demarre `receive_loop()` dans un thread, affiche l'adresse IP locale, puis demarre le serveur web. Le serveur web est attache a `127.0.0.1`; l'ecoute TCP du recepteur est accessible au reseau local. `Ctrl+C` arrete le serveur.

`lan_address()` determine l'adresse IP locale a communiquer a l'emetteur en ouvrant une sonde UDP sans envoyer de message applicatif.

## 5. Fonctionnement cryptographique

### 5.1 Creation des cles cote recepteur

Le navigateur genere une paire RSA-OAEP de 2048 bits. Il exporte la cle publique en PEM, puis chiffre la cle privee PKCS#8 avec AES-256-GCM. La cle qui protege le fichier prive est derivee de la phrase secrete par PBKDF2-SHA-256 avec 310 000 iterations et un sel aleatoire.

Le navigateur telecharge `cle_publique.pem` et `cle_privee_protegee.json`. Seule la cle publique doit etre partagee. La phrase secrete et le fichier prive restent sur le PC destinataire.

### 5.2 Chiffrement cote emetteur

1. L'utilisateur choisit le fichier PEM public et saisit l'IP du recepteur.
2. Web Crypto importe la cle publique et calcule son empreinte SHA-256 pour permettre une comparaison par un canal de confiance.
3. Le navigateur genere une cle AES-256 aleatoire et un nonce de 12 octets.
4. AES-GCM chiffre le message ; RSA-OAEP avec SHA-256 chiffre la cle AES.
5. Le navigateur construit un paquet JSON :

```json
{
  "alg": "RSA-OAEP-SHA256+A256GCM",
  "key": "cle AES chiffree avec RSA et encodee en Base64",
  "nonce": "nonce AES-GCM encode en Base64",
  "ciphertext": "message chiffre et tag GCM en Base64"
}
```

Le navigateur transmet ce paquet au serveur local de l'emetteur. Python le relaie par TCP ; le texte clair n'est jamais inclus dans cette transmission.

### 5.3 Reception et dechiffrement

Le navigateur du recepteur charge le fichier prive protege et demande la phrase secrete. Apres ouverture, la cle privee dechiffree reste dans la memoire de l'onglet. La page interroge la file du relais toutes les 1,2 secondes lorsqu'elle est visible.

Pour chaque paquet, le navigateur utilise RSA pour retrouver la cle AES, puis AES-GCM pour dechiffrer le texte et verifier son tag d'authentification. Si la cle est mauvaise ou si le paquet a ete modifie, le dechiffrement echoue. Apres succes, le navigateur accuse reception et le relais retire le paquet de sa file.

## 6. Guide visuel des interfaces

### 6.1 Elements communs

- **Logo CryptoLink** : identifie l'application et ramene a l'accueil.
- **Navigation Accueil / Emetteur / Recepteur** : ouvre la route correspondante. Si le role demande n'est pas celui lance sur cette instance, une page indique quelle commande executer dans un autre terminal.
- **Badge RSA-OAEP / AES-256-GCM** : rappelle les algorithmes utilises.
- **Indicateur d'etat** : affiche l'etat du serveur ou l'ecoute du recepteur.
- **Pied de page** : donne le role actif ou le port TCP.

### 6.2 Page d'accueil `/`

- **Titre et texte d'introduction** : expliquent le but de CryptoLink et que le texte clair ne part pas du navigateur emetteur.
- **Bouton principal** : ouvre le role actif du serveur.
- **Lien “Voir le parcours”** : fait defiler jusqu'a l'explication des etapes.
- **Schema anime** : illustre le trajet de la cle publique, du message chiffre puis de la cle privee. Le carre mobile represente le paquet chiffre en transit.
- **Bandeau de protocole** : rappelle RSA-OAEP, AES-GCM et TCP 5000.
- **Section “Trois etapes”** : resume la creation des cles, le chiffrement et le dechiffrement.
- **Section “Choisir un role”** : ouvre l'interface emetteur ou recepteur active. Si l'autre role n'est pas actif, elle montre la commande de lancement.

Les revelations au defilement et le paquet anime sont realises avec CSS et `IntersectionObserver`. La preference systeme de reduction des animations est respectee ; aucune bibliotheque GSAP n'est chargee.

### 6.3 Interface emetteur `/emetteur`

- **Adresse IP** : adresse locale du PC recepteur ; `127.0.0.1` ne convient que si les deux roles sont sur le meme ordinateur.
- **Cle publique RSA** : bouton de selection du fichier `cle_publique.pem`.
- **Empreinte SHA-256** : empreinte de la cle chargee ; le bouton permet de la copier afin de la comparer par un canal fiable.
- **Zone Message** : texte a chiffrer ; le compteur indique la taille saisie.
- **Note de confidentialite** : rappelle que le texte clair reste dans le navigateur.
- **Bouton Chiffrer et envoyer** : lance le chiffrement Web Crypto puis demande au serveur Python de transmettre le paquet TCP.
- **Zone de retour** : affiche la reussite, les champs manquants, une cle invalide ou une erreur reseau.

### 6.4 Interface recepteur `/recepteur`

- **Bouton Generer une paire RSA** : cree les deux cles dans le navigateur et telecharge la cle publique et le fichier prive protege.
- **Champ Phrase secrete** : phrase d'au moins 10 caracteres utilisee pour proteger et ouvrir la cle privee.
- **Etat de la cle** : indique si une paire a ete generee ou si la cle privee est deverrouillee en memoire dans l'onglet.
- **Champ de fichier prive** : selectionne le fichier `cle_privee_protegee.json`.
- **Bouton Deverrouiller la cle** : derive la cle AES depuis la phrase secrete et importe la cle RSA privee dans Web Crypto.
- **Indicateur de veille** : indique l'activite de recherche des paquets recus.
- **Boite Messages recus** : affiche l'adresse source, l'heure, le message dechiffre ou l'erreur de dechiffrement.
- **Compteur** : nombre de messages conserves dans l'affichage de l'onglet.

## 7. Performance et limites

- L'interface est HTML/CSS/JavaScript natif, sans compilation ni telechargement de dependances front-end.
- Web Crypto execute les operations cryptographiques de facon asynchrone dans le navigateur.
- `ThreadingHTTPServer` et le thread TCP evitent de bloquer le serveur web pendant la reception.
- Le relais limite les paquets a 1 Mio et sa file a 100 messages ; la file est volatile et est videe a l'arret.
- Les pages web sont servies sur la boucle locale. Le destinataire doit autoriser le port TCP 5000 sur son reseau local.

## 8. Securite et limites

- RSA-OAEP protege la cle AES ; AES-256-GCM chiffre le contenu et detecte sa modification.
- PBKDF2 et AES-GCM protegent la cle privee exportee. La phrase secrete doit etre gardee separement et ne pas etre oubliee.
- Le projet n'authentifie pas l'expediteur et n'utilise pas de signature numerique.
- L'identite de la cle publique n'est pas certifiee automatiquement : compare son empreinte via un canal de confiance.
- Le relais TCP n'utilise pas TLS et la file n'est pas persistante. Le projet est pedagogique et n'est pas concu pour etre expose sur Internet.
