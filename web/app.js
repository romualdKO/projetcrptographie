const encoder = new TextEncoder();
const decoder = new TextDecoder();
const MAX_MESSAGE_LENGTH = 20000;
const KDF_ITERATIONS = 310000;
const ALGORITHM = "RSA-OAEP-SHA256+A256GCM";

const elements = Object.fromEntries([
  "connectionState", "connectionLabel", "roleCaption", "introCopy", "footerRole",
  "secureContextNotice", "senderView", "receiverView", "targetIp", "publicKeyFile",
  "publicKeyDrop", "publicKeyName", "keyFingerprint", "fingerprintValue",
  "copyFingerprint", "messageText", "messageCount", "sendButton", "senderFeedback",
  "passphrase", "generateKeys", "keyStatus", "privateKeyFile", "unlockKey", "keyReady",
  "inboxCount", "pollIndicator", "inboxList", "receiverFeedback", "toastRegion",
].map((id) => [id, document.getElementById(id)]));

const state = {
  role: null,
  publicKeyFile: null,
  publicKey: null,
  fingerprint: "",
  privateKey: null,
  inbox: new Map(),
  processing: new Set(),
  pollBusy: false,
};

function bytesToBase64(bytes) {
  let binary = "";
  const chunkSize = 0x8000;
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + chunkSize));
  }
  return btoa(binary);
}

function base64ToBytes(value) {
  const binary = atob(value);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function pemToBytes(pem, label) {
  const begin = `-----BEGIN ${label}-----`;
  const end = `-----END ${label}-----`;
  const startIndex = pem.indexOf(begin);
  const endIndex = pem.indexOf(end);
  if (startIndex < 0 || endIndex < 0 || endIndex <= startIndex) {
    throw new Error("Le fichier PEM ne contient pas le bloc de clé attendu.");
  }
  const body = pem.slice(startIndex + begin.length, endIndex).replace(/\s/g, "");
  return base64ToBytes(body);
}

function bytesToPem(bytes, label) {
  const base64 = bytesToBase64(new Uint8Array(bytes));
  const lines = base64.match(/.{1,64}/g) || [];
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----\n`;
}

function showFeedback(element, message, kind = "") {
  element.textContent = message;
  element.className = `feedback ${kind}`.trim();
  element.hidden = false;
}

function hideFeedback(element) {
  element.hidden = true;
  element.textContent = "";
}

function toast(message, kind = "") {
  const item = document.createElement("div");
  item.className = `toast ${kind}`.trim();
  item.textContent = message;
  elements.toastRegion.append(item);
  window.setTimeout(() => item.remove(), 3800);
}

function setConnection(online, label) {
  elements.connectionState.classList.toggle("online", online);
  elements.connectionState.classList.toggle("offline", !online);
  elements.connectionLabel.textContent = label;
}

async function getJson(url, options = {}) {
  const response = await fetch(url, { cache: "no-store", ...options });
  let payload;
  try {
    payload = await response.json();
  } catch {
    throw new Error("Réponse invalide du serveur local.");
  }
  if (!response.ok) throw new Error(payload.error || `Erreur serveur (${response.status}).`);
  return payload;
}

async function initialize() {
  if (!window.isSecureContext || !window.crypto?.subtle) {
    elements.secureContextNotice.hidden = false;
    setConnection(false, "Crypto indisponible");
    return;
  }

  try {
    const status = await getJson("/api/status");
    state.role = status.role;
    const isSender = status.role === "sender";
    elements.senderView.hidden = !isSender;
    elements.receiverView.hidden = isSender;
    elements.roleCaption.textContent = isSender ? "/ EMETTEUR" : "/ RECEPTEUR";
    elements.footerRole.textContent = isSender ? "POSTE EMETTEUR" : `RELAIS TCP :${status.tcpPort}`;
    elements.introCopy.textContent = isSender
      ? "Le chiffrement se fait ici, dans votre navigateur. Seul le paquet chiffré est transmis au destinataire."
      : "Les paquets restent chiffres sur le relais. Le dechiffrement se fait dans ce navigateur, avec votre cle privee.";
    if (isSender) {
      setConnection(true, "Serveur local prêt");
    } else {
      setConnection(status.listenerReady, status.listenerReady ? "Ecoute active" : "Ecoute indisponible");
      if (status.listenerError) {
        showFeedback(elements.receiverFeedback, `Le relais TCP n'a pas démarré : ${status.listenerError}`, "error");
      }
      updateInbox();
      window.setInterval(updateInbox, 1200);
    }
  } catch (error) {
    setConnection(false, "Serveur indisponible");
    toast(error.message, "error");
  }
}

async function selectPublicKey(file) {
  state.publicKeyFile = file;
  state.publicKey = null;
  elements.publicKeyName.textContent = file ? file.name : "Choisir le fichier PEM";
  elements.publicKeyDrop.classList.toggle("has-file", Boolean(file));
  elements.keyFingerprint.hidden = true;
  hideFeedback(elements.senderFeedback);
  if (!file) return;

  try {
    const bytes = pemToBytes(await file.text(), "PUBLIC KEY");
    state.publicKey = await crypto.subtle.importKey(
      "spki", bytes, { name: "RSA-OAEP", hash: "SHA-256" }, false, ["encrypt"],
    );
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
    state.fingerprint = [...digest].map((byte) => byte.toString(16).padStart(2, "0")).join("").match(/.{1,4}/g).join(":");
    elements.fingerprintValue.textContent = state.fingerprint;
    elements.keyFingerprint.hidden = false;
    toast("Clé publique RSA chargée.", "success");
  } catch (error) {
    state.publicKey = null;
    elements.publicKeyName.textContent = file.name;
    showFeedback(elements.senderFeedback, `Clé publique invalide : ${error.message}`, "error");
  }
}

async function encryptMessage(message) {
  const aesKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt"]);
  const rawAesKey = await crypto.subtle.exportKey("raw", aesKey);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const [encryptedKey, ciphertext] = await Promise.all([
    crypto.subtle.encrypt({ name: "RSA-OAEP" }, state.publicKey, rawAesKey),
    crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, tagLength: 128 }, aesKey, encoder.encode(message)),
  ]);
  return {
    alg: ALGORITHM,
    key: bytesToBase64(new Uint8Array(encryptedKey)),
    nonce: bytesToBase64(nonce),
    ciphertext: bytesToBase64(new Uint8Array(ciphertext)),
  };
}

async function sendMessage() {
  hideFeedback(elements.senderFeedback);
  const ip = elements.targetIp.value.trim();
  const message = elements.messageText.value.trim();
  const byteLength = encoder.encode(message).length;
  if (!ip || !message || !state.publicKey) {
    showFeedback(elements.senderFeedback, "Renseigne l'adresse, choisis la clé publique et écris un message.", "error");
    return;
  }
  if (byteLength > 256 * 1024) {
    showFeedback(elements.senderFeedback, "Le message dépasse la limite réseau de 256 Ko.", "error");
    return;
  }

  elements.sendButton.disabled = true;
  elements.sendButton.querySelector(".button-label").textContent = "CHIFFREMENT EN COURS";
  try {
    const packet = await encryptMessage(message);
    const result = await getJson("/api/send", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ip, packet }),
    });
    if (result.sent) {
      showFeedback(elements.senderFeedback, `Message chiffré et transmis vers ${ip}. Le texte clair n'a pas quitté ce navigateur.`, "success");
      elements.messageText.value = "";
      updateMessageCount();
    }
  } catch (error) {
    showFeedback(elements.senderFeedback, error.message, "error");
  } finally {
    elements.sendButton.disabled = false;
    elements.sendButton.querySelector(".button-label").textContent = "CHIFFRER ET ENVOYER";
  }
}

async function derivePrivateKeyEncryptionKey(passphrase, salt, iterations) {
  const material = await crypto.subtle.importKey("raw", encoder.encode(passphrase), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

async function generateKeyPair() {
  const passphrase = elements.passphrase.value;
  if (passphrase.length < 10) {
    elements.passphrase.focus();
    toast("Choisis une phrase secrète d'au moins 10 caractères.", "error");
    return;
  }

  elements.generateKeys.disabled = true;
  elements.generateKeys.textContent = "GENERATION RSA...";
  elements.keyStatus.textContent = "Création de la paire et protection de la clé privée dans le navigateur...";
  try {
    const pair = await crypto.subtle.generateKey(
      { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
      true,
      ["encrypt", "decrypt"],
    );
    const [publicKey, privateKey] = await Promise.all([
      crypto.subtle.exportKey("spki", pair.publicKey),
      crypto.subtle.exportKey("pkcs8", pair.privateKey),
    ]);
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const wrappingKey = await derivePrivateKeyEncryptionKey(passphrase, salt, KDF_ITERATIONS);
    const encryptedPrivateKey = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, wrappingKey, privateKey);
    const protectedKey = {
      format: "CRYPTOLINK-PRIVATE-KEY",
      version: 1,
      kdf: { name: "PBKDF2-SHA256", iterations: KDF_ITERATIONS, salt: bytesToBase64(salt) },
      cipher: { name: "AES-256-GCM", iv: bytesToBase64(iv), ciphertext: bytesToBase64(new Uint8Array(encryptedPrivateKey)) },
    };

    downloadFile("cle_publique.pem", bytesToPem(publicKey, "PUBLIC KEY"), "application/x-pem-file");
    downloadFile("cle_privee_protegee.json", JSON.stringify(protectedKey, null, 2), "application/json");
    elements.keyStatus.textContent = "Paire créée. Transfère cle_publique.pem à l'émetteur ; conserve la clé privée protégée et sa phrase secrète.";
    toast("Paire RSA créée et clé privée protégée.", "success");
  } catch (error) {
    elements.keyStatus.textContent = `Génération impossible : ${error.message}`;
    toast(error.message, "error");
  } finally {
    elements.generateKeys.disabled = false;
    elements.generateKeys.textContent = "GENERER UNE PAIRE RSA";
  }
}

function downloadFile(filename, content, contentType) {
  const url = URL.createObjectURL(new Blob([content], { type: contentType }));
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

async function unlockPrivateKey() {
  const file = elements.privateKeyFile.files[0];
  const passphrase = elements.passphrase.value;
  if (!file || !passphrase) {
    toast("Choisis le fichier protégé et sa phrase secrète.", "error");
    return;
  }

  elements.unlockKey.disabled = true;
  elements.unlockKey.textContent = "DEVERROUILLAGE...";
  try {
    const envelope = JSON.parse(await file.text());
    if (envelope.format !== "CRYPTOLINK-PRIVATE-KEY" || envelope.version !== 1) {
      throw new Error("Format de clé privée non reconnu.");
    }
    const salt = base64ToBytes(envelope.kdf.salt);
    const iv = base64ToBytes(envelope.cipher.iv);
    const wrappingKey = await derivePrivateKeyEncryptionKey(passphrase, salt, envelope.kdf.iterations);
    const pkcs8 = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv }, wrappingKey, base64ToBytes(envelope.cipher.ciphertext),
    );
    state.privateKey = await crypto.subtle.importKey(
      "pkcs8", pkcs8, { name: "RSA-OAEP", hash: "SHA-256" }, false, ["decrypt"],
    );
    elements.keyReady.hidden = false;
    elements.keyStatus.textContent = "Clé déverrouillée uniquement dans la mémoire de cet onglet.";
    for (const item of state.inbox.values()) delete item.error;
    toast("Clé privée déverrouillée localement.", "success");
    updateInbox();
  } catch {
    state.privateKey = null;
    elements.keyReady.hidden = true;
    toast("Impossible d'ouvrir la clé. Vérifie le fichier et la phrase secrète.", "error");
  } finally {
    elements.unlockKey.disabled = false;
    elements.unlockKey.textContent = "DEVERROUILLER LA CLE";
  }
}

async function decryptPacket(packet) {
  if (packet.alg !== ALGORITHM) throw new Error("Algorithme de paquet inconnu.");
  const rawAesKey = await crypto.subtle.decrypt({ name: "RSA-OAEP" }, state.privateKey, base64ToBytes(packet.key));
  const aesKey = await crypto.subtle.importKey("raw", rawAesKey, "AES-GCM", false, ["decrypt"]);
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: base64ToBytes(packet.nonce), tagLength: 128 },
    aesKey,
    base64ToBytes(packet.ciphertext),
  );
  return decoder.decode(plaintext);
}

async function updateInbox() {
  if (state.role !== "receiver" || state.pollBusy || document.hidden) return;
  state.pollBusy = true;
  elements.pollIndicator.classList.add("active");
  try {
    const data = await getJson("/api/inbox");
    let changed = false;
    for (const item of data.messages) {
      let localItem = state.inbox.get(item.id);
      if (!localItem) {
        localItem = item;
        state.inbox.set(item.id, localItem);
        changed = true;
      }
      if (state.privateKey && !state.processing.has(item.id) && !localItem.decrypted && !localItem.error) {
        state.processing.add(item.id);
        try {
          localItem.plaintext = await decryptPacket(item.packet);
          localItem.decrypted = true;
          changed = true;
          await getJson("/api/ack", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ id: item.id }),
          });
        } catch {
          localItem.error = "Déchiffrement impossible : vérifie que cette clé correspond à la clé publique utilisée.";
          changed = true;
        } finally {
          state.processing.delete(item.id);
        }
      }
    }
    if (changed) renderInbox();
  } catch (error) {
    setConnection(false, "Relais indisponible");
    showFeedback(elements.receiverFeedback, error.message, "error");
  } finally {
    state.pollBusy = false;
    elements.pollIndicator.classList.toggle("active", Boolean(state.privateKey));
  }
}

function renderInbox() {
  const items = [...state.inbox.values()].sort((left, right) => right.receivedAt.localeCompare(left.receivedAt));
  for (const oldItem of items.slice(50)) state.inbox.delete(oldItem.id);
  items.length = Math.min(items.length, 50);
  elements.inboxCount.textContent = `${items.length} MESSAGE${items.length === 1 ? "" : "S"}`;
  elements.inboxList.replaceChildren();
  if (items.length === 0) {
    const empty = document.createElement("div");
    empty.className = "empty-state";
    empty.innerHTML = '<span class="empty-symbol" aria-hidden="true">···</span><strong>Aucun message pour le moment</strong><span>Les nouveaux paquets apparaîtront ici.</span>';
    elements.inboxList.append(empty);
    return;
  }

  for (const item of items) {
    const card = document.createElement("article");
    card.className = "message-card";
    const top = document.createElement("div");
    top.className = "message-card-top";
    const sender = document.createElement("strong");
    sender.textContent = item.senderIp || "EMETTEUR";
    const time = document.createElement("time");
    time.dateTime = item.receivedAt;
    time.textContent = new Date(item.receivedAt).toLocaleTimeString();
    top.append(sender, time);
    card.append(top);

    if (item.decrypted) {
      const message = document.createElement("p");
      message.className = "message-card-text";
      message.textContent = item.plaintext;
      card.append(message);
    } else if (item.error) {
      const error = document.createElement("p");
      error.className = "message-card-error";
      error.textContent = item.error;
      card.append(error);
      const actions = document.createElement("div");
      actions.className = "message-card-actions";
      const discard = document.createElement("button");
      discard.className = "discard-button";
      discard.type = "button";
      discard.textContent = "SUPPRIMER LE PAQUET";
      discard.addEventListener("click", () => discardMessage(item.id));
      actions.append(discard);
      card.append(actions);
    } else {
      const waiting = document.createElement("p");
      waiting.className = "message-card-text";
      waiting.textContent = "Paquet chiffré reçu. Déverrouille la clé privée pour le lire.";
      card.append(waiting);
    }
    elements.inboxList.append(card);
  }
}

async function discardMessage(id) {
  try {
    await getJson("/api/ack", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id }),
    });
    state.inbox.delete(id);
    renderInbox();
  } catch (error) {
    toast(error.message, "error");
  }
}

function updateMessageCount() {
  const count = encoder.encode(elements.messageText.value).length;
  elements.messageCount.textContent = `${count.toLocaleString("fr-FR")} / ${MAX_MESSAGE_LENGTH.toLocaleString("fr-FR")}`;
}

async function copyFingerprint() {
  try {
    await navigator.clipboard.writeText(state.fingerprint);
    toast("Empreinte copiée.", "success");
  } catch {
    toast("Copie indisponible dans ce navigateur.", "error");
  }
}

elements.publicKeyFile.addEventListener("change", (event) => selectPublicKey(event.target.files[0]));
elements.copyFingerprint.addEventListener("click", copyFingerprint);
elements.messageText.addEventListener("input", updateMessageCount);
elements.sendButton.addEventListener("click", sendMessage);
elements.generateKeys.addEventListener("click", generateKeyPair);
elements.unlockKey.addEventListener("click", unlockPrivateKey);
elements.privateKeyFile.addEventListener("change", () => {
  state.privateKey = null;
  elements.keyReady.hidden = true;
});
document.addEventListener("visibilitychange", () => {
  if (!document.hidden) updateInbox();
});

initialize();