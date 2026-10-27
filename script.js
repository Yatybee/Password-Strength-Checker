/*
  Password Strength Checker
  - Everything runs in the browser. The password is never sent, saved or logged.
  - Part 1: analyzePassword() is a "pure" function: text in, results out. No page access.
  - Part 2: the page code connects that function to the HTML.
*/

/* =====================  PART 1: THE LOGIC  ===================== */

// A tiny sample of very common password "bases". Real lists have millions of entries.
const COMMON_PASSWORDS = [
  "password", "passw0rd", "123456", "12345678", "123456789", "qwerty", "qwertyuiop",
  "abc123", "letmein", "welcome", "admin", "iloveyou", "monkey", "dragon",
  "football", "baseball", "login", "master", "sunshine", "princess", "trustno1"
];

const LEVELS = ["Weak", "Fair", "Good", "Strong"];

// Is the password just a common word with digits/symbols stuck on the ends?
// e.g. "Password123!" -> "password" -> common.
function isCommonPassword(password) {
  const lower = password.toLowerCase();
  const stripped = lower.replace(/^[^a-z]+|[^a-z]+$/g, ""); // trim non-letters from both ends
  return COMMON_PASSWORDS.includes(lower) || (stripped.length > 0 && COMMON_PASSWORDS.includes(stripped));
}

// Three or more of the same character in a row: "aaa", "111"
function hasRepeatedChars(password) {
  return /(.)\1\1/.test(password);
}

// Four characters in a row going up or down by one: "abcd", "1234", "4321"
function hasSequence(password) {
  const lower = password.toLowerCase();
  for (let i = 0; i <= lower.length - 4; i++) {
    const step = lower.charCodeAt(i + 1) - lower.charCodeAt(i);
    if (step !== 1 && step !== -1) continue;
    let run = true;
    for (let j = 1; j < 3; j++) {
      if (lower.charCodeAt(i + j + 1) - lower.charCodeAt(i + j) !== step) { run = false; break; }
    }
    if (run) return true;
  }
  return false;
}

// Returns { checks, score, levelIndex, level, suggestions }
function analyzePassword(password) {
  // Step 1: the six requirement checks (true/false each)
  const checks = {
    length8:  password.length >= 8,
    length12: password.length >= 12,
    upper:    /[A-Z]/.test(password),
    lower:    /[a-z]/.test(password),
    number:   /[0-9]/.test(password),
    special:  /[^A-Za-z0-9\s]/.test(password) // anything that isn't a letter, digit or space
  };

  // Step 2: empty input is handled up front
  if (password.length === 0) {
    return { checks, score: 0, levelIndex: -1, level: null, suggestions: [] };
  }

  // Step 3: base score = how many checks passed (0 to 6)
  let score = Object.values(checks).filter(Boolean).length;

  // Step 4: look for bad patterns
  const common = isCommonPassword(password);
  const repeated = hasRepeatedChars(password);
  const sequence = hasSequence(password);
  if (repeated) score -= 1;
  if (sequence) score -= 1;
  score = Math.max(0, score);

  // Step 5: turn the score into one of four levels
  //   0-2 Weak | 3 Fair | 4-5 Good | 6 Strong
  let levelIndex = score <= 2 ? 0 : score === 3 ? 1 : score <= 5 ? 2 : 3;

  // Step 6: caps. Some problems should never be hidden by points elsewhere.
  if (!checks.length8 || common) levelIndex = 0;      // too short or common -> Weak
  else if (!checks.length12) levelIndex = Math.min(levelIndex, 2); // under 12 -> never Strong

  // Step 7: friendly suggestions
  const suggestions = [];
  if (common) suggestions.push("This looks like a very common password. Avoid common words, even with numbers added.");
  if (!checks.length8) suggestions.push("Make it at least 8 characters long.");
  else if (!checks.length12) suggestions.push("Aim for 12 or more characters. Length helps the most.");
  if (!checks.upper) suggestions.push("Add an uppercase letter.");
  if (!checks.lower) suggestions.push("Add a lowercase letter.");
  if (!checks.number) suggestions.push("Add a number.");
  if (!checks.special) suggestions.push("Add a special character such as ! ? # or $.");
  if (repeated) suggestions.push("Avoid repeating the same character three or more times in a row.");
  if (sequence) suggestions.push("Avoid sequences like \"abcd\" or \"1234\".");
  if (suggestions.length === 0) {
    suggestions.push("Nice work. Use a unique password for every account, ideally with a password manager.");
  }

  return { checks, score, levelIndex, level: LEVELS[levelIndex], suggestions };
}

/* =====================  PART 1b: THE GENERATOR LOGIC  ===================== */

const CHARSETS = {
  upper:   "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  lower:   "abcdefghijklmnopqrstuvwxyz",
  numbers: "0123456789",
  symbols: "!@#$%^&*()-_=+[]{};:,.?/"
};
const MIN_LENGTH = 12;
const MAX_LENGTH = 64;

// Returns a fair random whole number from 0 up to (but not including) max.
//
// Why not just "random32bitNumber % max"? 2^32 usually doesn't divide evenly by max, so the
// smaller results would come up slightly more often. That is "modulo bias".
// Fix (rejection sampling): only accept numbers below the largest exact multiple of max,
// and throw away (re-roll) anything above it. Then every result is equally likely.
function secureRandomInt(max) {
  if (!Number.isInteger(max) || max < 1 || max > 2 ** 32) {
    throw new RangeError("max must be a whole number between 1 and 2^32");
  }
  const range = 2 ** 32;
  const limit = range - (range % max); // biggest multiple of max that fits
  const buffer = new Uint32Array(1);
  let value;
  do {
    globalThis.crypto.getRandomValues(buffer); // cryptographically secure randomness
    value = buffer[0];
  } while (value >= limit); // re-roll the unfair leftover zone
  return value % max;
}

// Fisher-Yates shuffle using the secure random function above (shuffles in place).
function secureShuffle(array) {
  for (let i = array.length - 1; i > 0; i--) {
    const j = secureRandomInt(i + 1);
    [array[i], array[j]] = [array[j], array[i]];
  }
  return array;
}

// options: { length, upper, lower, numbers, symbols, noDuplicates }
// Throws an Error with a user-friendly message if the settings are invalid.
function generatePassword(options) {
  const { length, noDuplicates = false } = options;

  if (!Number.isInteger(length) || length < MIN_LENGTH || length > MAX_LENGTH) {
    throw new Error("Length must be a whole number from " + MIN_LENGTH + " to " + MAX_LENGTH + ".");
  }

  // Which character sets did the user choose?
  const selected = Object.keys(CHARSETS).filter((name) => options[name] === true);
  if (selected.length === 0) {
    throw new Error("Select at least one character type.");
  }

  // One big pool of every allowed character. (The sets don't overlap, so no repeats here.)
  const pool = selected.map((name) => CHARSETS[name]).join("").split("");
  if (noDuplicates && length > pool.length) {
    throw new Error(
      "Only " + pool.length + " unique characters are available with these settings. " +
      "Lower the length, add character types, or turn off \"no duplicates\"."
    );
  }

  const result = [];

  // Take one random character from the pool; remove it if duplicates are not allowed.
  function takeFrom(chars) {
    const index = secureRandomInt(chars.length);
    const char = chars[index];
    if (noDuplicates) {
      const poolIndex = pool.indexOf(char);
      pool.splice(poolIndex, 1);
      if (chars !== pool) chars.splice(index, 1);
    }
    return char;
  }

  // 1) Guarantee at least one character from every selected type
  selected.forEach((name) => result.push(takeFrom(CHARSETS[name].split(""))));

  // 2) Fill the rest from the whole pool
  while (result.length < length) result.push(takeFrom(pool));

  // 3) Shuffle so the guaranteed characters aren't always at the start
  return secureShuffle(result).join("");
}

/* =====================  PART 1c: THE VAULT CRYPTO CORE  =====================

  How it works, in plain English:
  1. The master password is NEVER stored. It is turned into a 256-bit encryption key with
     PBKDF2: the password plus a random "salt" is scrambled 600,000 times. This makes every
     password guess slow for an attacker, and the salt makes each vault's key unique.
  2. The vault (a JSON object) is encrypted with AES-GCM using that key and a fresh random
     12-byte "nonce" (called iv below) for every single encryption. AES-GCM is "authenticated":
     any change to the data, or the wrong key, makes decryption fail instead of returning junk.
  3. Only the envelope below is saved: version, KDF settings, salt, nonce and ciphertext.
     There is no stored password check. "Unlock" simply means "try to decrypt".
  4. The derived key lives only inside a session object while unlocked. Locking drops it.

  Envelope format (version 1):
  { format: "securenest-vault", v: 1,
    kdf:    { name: "PBKDF2", hash: "SHA-256", iterations: 600000, salt: <base64, 16 bytes> },
    cipher: { name: "AES-GCM", iv: <base64, 12 bytes> },
    data:   <base64 ciphertext + 16-byte auth tag> }
*/

const VAULT_FORMAT = "securenest-vault";
const VAULT_VERSION = 1;
const VAULT_STORAGE_KEY = "securenest.vault";
const PBKDF2_ITERATIONS = 600000;     // OWASP's 2023 recommendation for PBKDF2-HMAC-SHA256
const MIN_ITERATIONS = 100000;        // refuse imported vaults that claim to be weaker than this
const MAX_ITERATIONS = 10000000;      // refuse absurd values that could freeze the browser
const SALT_BYTES = 16;
const IV_BYTES = 12;
const GCM_TAG_BYTES = 16;
const MAX_ENVELOPE_CHARS = 10 * 1024 * 1024;
const MIN_MASTER_LENGTH = 10;

// An error type with a machine-readable code. Messages never contain secrets.
class VaultError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "VaultError";
    this.code = code;
  }
}

/* ----- small helpers: text <-> bytes <-> base64 ----- */
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

function bytesToBase64(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

function base64ToBytes(text) {
  if (typeof text !== "string" || !/^[A-Za-z0-9+/]*={0,2}$/.test(text) || text.length % 4 !== 0) {
    throw new VaultError("INVALID_FORMAT", "The vault data is not valid.");
  }
  const binary = atob(text);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function randomBytes(count) {
  return globalThis.crypto.getRandomValues(new Uint8Array(count));
}

/* ----- key derivation ----- */

// Turns the master password + salt into an AES key. extractable=false means the browser will
// not let any code read the raw key bytes back out.
async function deriveKey(masterPassword, salt, iterations) {
  // normalize() makes visually identical Unicode text produce identical bytes on every device
  const passwordBytes = textEncoder.encode(masterPassword.normalize("NFKC"));
  const baseKey = await globalThis.crypto.subtle.importKey("raw", passwordBytes, "PBKDF2", false, ["deriveKey"]);
  return globalThis.crypto.subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

function checkMasterPassword(masterPassword) {
  if (typeof masterPassword !== "string" || masterPassword.length < MIN_MASTER_LENGTH) {
    throw new VaultError("WEAK_MASTER", "The master password must be at least " + MIN_MASTER_LENGTH + " characters.");
  }
}

/* ----- envelope checking ----- */

// The "additional authenticated data": the settings that are not secret but must not be
// tampered with. They are not encrypted, yet AES-GCM will refuse to decrypt if they change.
function buildAad(kdf, version) {
  return textEncoder.encode(
    [VAULT_FORMAT, version, kdf.name, kdf.hash, kdf.iterations, kdf.salt, "AES-GCM"].join("|")
  );
}

// Checks an envelope's shape and returns its decoded binary parts. Throws VaultError if bad.
function validateEnvelope(env) {
  const bad = () => new VaultError("INVALID_FORMAT", "This is not a valid SecureNest vault.");
  if (env === null || typeof env !== "object" || Array.isArray(env)) throw bad();
  if (env.format !== VAULT_FORMAT) throw bad();
  if (!Number.isInteger(env.v) || env.v < 1) throw bad();
  if (env.v > VAULT_VERSION) {
    throw new VaultError("UNSUPPORTED_VERSION", "This vault was made by a newer version of SecureNest.");
  }
  const { kdf, cipher } = env;
  if (!kdf || typeof kdf !== "object" || !cipher || typeof cipher !== "object") throw bad();
  if (kdf.name !== "PBKDF2" || kdf.hash !== "SHA-256" || cipher.name !== "AES-GCM") throw bad();
  if (!Number.isInteger(kdf.iterations) || kdf.iterations < MIN_ITERATIONS || kdf.iterations > MAX_ITERATIONS) throw bad();
  const salt = base64ToBytes(kdf.salt);
  const iv = base64ToBytes(cipher.iv);
  if (typeof env.data !== "string" || env.data.length > MAX_ENVELOPE_CHARS) throw bad();
  const ciphertext = base64ToBytes(env.data);
  if (salt.length !== SALT_BYTES || iv.length !== IV_BYTES || ciphertext.length < GCM_TAG_BYTES) throw bad();
  return { salt, iv, ciphertext };
}

// Text (from a file or storage) -> checked envelope object. Does NOT decrypt anything.
function parseEnvelopeText(text) {
  if (typeof text !== "string" || text.length > MAX_ENVELOPE_CHARS) {
    throw new VaultError("INVALID_FORMAT", "This is not a valid SecureNest vault.");
  }
  let env;
  try {
    env = JSON.parse(text);
  } catch (e) {
    throw new VaultError("INVALID_FORMAT", "This is not a valid SecureNest vault.");
  }
  validateEnvelope(env);
  return env;
}

/* ----- encrypt / decrypt ----- */

async function decryptWithKey(key, env) {
  const { iv, ciphertext } = validateEnvelope(env);
  let plain;
  try {
    plain = await globalThis.crypto.subtle.decrypt(
      { name: "AES-GCM", iv, additionalData: buildAad(env.kdf, env.v) },
      key,
      ciphertext
    );
  } catch (e) {
    // AES-GCM cannot tell "wrong password" from "data was changed", so we say both.
    throw new VaultError("WRONG_PASSWORD_OR_CORRUPT", "Could not unlock. The master password is wrong or the vault data is damaged.");
  }
  let data;
  try {
    data = JSON.parse(textDecoder.decode(plain));
  } catch (e) {
    throw new VaultError("WRONG_PASSWORD_OR_CORRUPT", "Could not unlock. The master password is wrong or the vault data is damaged.");
  }
  if (!data || typeof data !== "object" || !Array.isArray(data.entries)) {
    throw new VaultError("INVALID_FORMAT", "The vault contents are not in the expected format.");
  }
  return data;
}

// A session holds the key in a closure (a private variable nobody else can reach).
// Calling lock() drops the only reference we hold. (JavaScript can't wipe memory itself;
// the garbage collector frees it later.)
function makeSession(key, kdf) {
  let currentKey = key;
  return {
    get unlocked() { return currentKey !== null; },

    // Encrypts `data` with a FRESH random nonce and returns a new envelope.
    // It does not touch storage, so a failure can never damage the saved vault.
    async encrypt(data) {
      if (currentKey === null) throw new VaultError("LOCKED", "The vault is locked.");
      const iv = randomBytes(IV_BYTES);
      const kdfInfo = { name: "PBKDF2", hash: "SHA-256", iterations: kdf.iterations, salt: bytesToBase64(kdf.salt) };
      const ciphertext = await globalThis.crypto.subtle.encrypt(
        { name: "AES-GCM", iv, additionalData: buildAad(kdfInfo, VAULT_VERSION) },
        currentKey,
        textEncoder.encode(JSON.stringify(data))
      );
      const envelope = {
        format: VAULT_FORMAT,
        v: VAULT_VERSION,
        kdf: kdfInfo,
        cipher: { name: "AES-GCM", iv: bytesToBase64(iv) },
        data: bytesToBase64(new Uint8Array(ciphertext))
      };
      // Safety check: make sure what we are about to save can really be read back
      const check = await decryptWithKey(currentKey, envelope);
      if (JSON.stringify(check) !== JSON.stringify(data)) {
        throw new VaultError("ENCRYPT_FAILED", "Encryption check failed. Nothing was saved.");
      }
      return envelope;
    },

    lock() { currentKey = null; }
  };
}

// Creates a brand-new empty vault. Returns { session, envelope }. Does not save anything.
async function createVault(masterPassword) {
  checkMasterPassword(masterPassword);
  const salt = randomBytes(SALT_BYTES); // fresh salt for every new vault
  const key = await deriveKey(masterPassword, salt, PBKDF2_ITERATIONS);
  const session = makeSession(key, { salt, iterations: PBKDF2_ITERATIONS });
  const envelope = await session.encrypt({ v: VAULT_VERSION, entries: [] });
  return { session, envelope };
}

// Unlocks an existing vault by trying to decrypt it. Returns { session, data }.
async function unlockVault(envelope, masterPassword) {
  const { salt } = validateEnvelope(envelope);
  if (typeof masterPassword !== "string" || masterPassword.length === 0) {
    throw new VaultError("WRONG_PASSWORD_OR_CORRUPT", "Could not unlock. The master password is wrong or the vault data is damaged.");
  }
  const key = await deriveKey(masterPassword, salt, envelope.kdf.iterations);
  const data = await decryptWithKey(key, envelope);
  return { session: makeSession(key, { salt, iterations: envelope.kdf.iterations }), data };
}

/* ----- storage (only ever the encrypted envelope) ----- */

// Returns the saved envelope, or null if there is no vault yet.
// If the saved text is damaged this THROWS; it never deletes or resets anything.
function loadEnvelope(storage) {
  const text = storage.getItem(VAULT_STORAGE_KEY);
  return text === null ? null : parseEnvelopeText(text);
}

// Called only AFTER a new envelope was created successfully.
function saveEnvelope(storage, envelope) {
  validateEnvelope(envelope);
  try {
    storage.setItem(VAULT_STORAGE_KEY, JSON.stringify(envelope));
  } catch (e) {
    throw new VaultError("STORAGE_FAILED", "The browser could not save the vault (storage may be full or blocked). Your previous vault is unchanged.");
  }
}

// Export = the envelope as text. It is already encrypted, so it exposes no credentials.
function exportEnvelopeText(envelope) {
  validateEnvelope(envelope);
  return JSON.stringify(envelope, null, 2);
}

/* =====================  PART 2: THE PAGE  ===================== */

// Only run page code in a browser. This lets us test Part 1 in Node without a page.
if (typeof document !== "undefined") {
  const input = document.getElementById("password");
  const toggleBtn = document.getElementById("toggle");
  const resetBtn = document.getElementById("reset");
  const meterBar = document.getElementById("meter-bar");
  const strengthText = document.getElementById("strength-text");
  const suggestionsList = document.getElementById("suggestions");
  const checklistItems = document.querySelectorAll("#checklist li");

  const EMPTY_MESSAGE = "Enter a password to begin.";
  const WIDTHS = ["25%", "50%", "75%", "100%"]; // meter width per level

  function update() {
    const result = analyzePassword(input.value);

    // Checklist: mark each item met / not met
    checklistItems.forEach((item) => {
      const met = result.checks[item.dataset.rule];
      item.classList.toggle("met", met);
      item.querySelector(".status").textContent = met ? " (met)" : " (not met)";
    });

    // Meter + label (empty input = blank meter)
    if (result.levelIndex === -1) {
      meterBar.style.width = "0";
      meterBar.removeAttribute("data-level");
      strengthText.removeAttribute("data-level");
      strengthText.textContent = EMPTY_MESSAGE;
    } else {
      const key = result.level.toLowerCase();
      meterBar.style.width = WIDTHS[result.levelIndex];
      meterBar.dataset.level = key;
      strengthText.dataset.level = key;
      strengthText.textContent = "Strength: " + result.level;
    }

    // Suggestions: textContent is used so nothing is ever treated as HTML
    suggestionsList.replaceChildren();
    const tips = result.suggestions.length ? result.suggestions : ["Start typing to get tips."];
    tips.forEach((tip) => {
      const li = document.createElement("li");
      li.textContent = tip;
      suggestionsList.appendChild(li);
    });
  }

  function setVisible(visible) {
    input.type = visible ? "text" : "password";
    toggleBtn.textContent = visible ? "Hide" : "Show";
    toggleBtn.setAttribute("aria-pressed", String(visible));
  }

  input.addEventListener("input", update);
  toggleBtn.addEventListener("click", () => setVisible(input.type === "password"));
  resetBtn.addEventListener("click", () => {
    input.value = "";
    setVisible(false); // always go back to hidden
    update();
    input.focus();
  });

  update(); // draw the initial empty state

  /* ----- Generator ----- */
  const genBtn = document.getElementById("generate");
  const genOutput = document.getElementById("generated");
  const genToggle = document.getElementById("gen-toggle");
  const genCopy = document.getElementById("gen-copy");
  const genUse = document.getElementById("gen-use");
  const genLength = document.getElementById("gen-length");
  const genLengthValue = document.getElementById("gen-length-value");
  const genMessage = document.getElementById("gen-message");
  const genSave = document.getElementById("gen-save");
  const genActions = [genToggle, genCopy, genUse, genSave];

  function setGenMessage(text, isError) {
    genMessage.textContent = text;
    genMessage.classList.toggle("error", Boolean(isError));
  }

  function setGenVisible(visible) {
    genOutput.type = visible ? "text" : "password";
    genToggle.textContent = visible ? "Hide" : "Show";
    genToggle.setAttribute("aria-pressed", String(visible));
  }

  genLength.addEventListener("input", () => { genLengthValue.textContent = genLength.value; });

  genBtn.addEventListener("click", () => {
    try {
      genOutput.value = generatePassword({
        length: Number(genLength.value),
        upper: document.getElementById("gen-upper").checked,
        lower: document.getElementById("gen-lower").checked,
        numbers: document.getElementById("gen-numbers").checked,
        symbols: document.getElementById("gen-symbols").checked,
        noDuplicates: document.getElementById("gen-nodup").checked
      });
      genActions.forEach((b) => { b.disabled = false; });
      setGenVisible(false); // new passwords start hidden
      setGenMessage("Password generated. It is hidden; use Show to view it.", false);
    } catch (err) {
      // Messages are written by us and never contain the password
      genOutput.value = "";
      genActions.forEach((b) => { b.disabled = true; });
      setGenMessage(err.message, true);
    }
  });

  genToggle.addEventListener("click", () => setGenVisible(genOutput.type === "password"));

  genCopy.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(genOutput.value);
      setGenMessage("Copied to clipboard. Your clipboard may keep it until you copy something else.", false);
    } catch (err) {
      setGenMessage("Copy was blocked by the browser. Click Show, select the text and press Ctrl+C.", true);
    }
  });

  genUse.addEventListener("click", () => {
    input.value = genOutput.value;
    update();
    selectTab(document.getElementById("tab-checker"));
    document.getElementById("tab-checker").focus();
  });

  /* ----- Vault UI ----- */
  const AUTO_LOCK_MS = 5 * 60 * 1000; // lock after 5 minutes without activity
  const MAX_BACKUP_BYTES = 12 * 1024 * 1024; // refuse absurdly large files before reading them
  const $ = (id) => document.getElementById(id);

  const views = { setup: $("vault-setup"), locked: $("vault-locked"), damaged: $("vault-damaged"), open: $("vault-open") };
  const entryForm = $("entry-form");
  const entryFields = {
    name: $("entry-name"), url: $("entry-url"), username: $("entry-username"),
    password: $("entry-password"), notes: $("entry-notes")
  };
  const vaultList = $("vault-list");
  const vaultSearch = $("vault-search");
  const vaultStatus = $("vault-status");
  const vaultEmpty = $("vault-empty");
  const confirmDialog = $("confirm-dialog");

  // Browsers can block localStorage (private mode, blocked cookies), so test it safely
  let storage = null;
  try {
    storage = window.localStorage;
    storage.getItem(VAULT_STORAGE_KEY);
  } catch (e) {
    storage = null;
  }

  // Everything secret lives in these variables only while unlocked
  let session = null;       // holds the encryption key (inside, privately)
  let entries = [];         // decrypted accounts
  let editingId = null;     // which account the form is editing (null = adding)
  let busy = false;         // true while a slow operation (key derivation) runs
  let autoLockTimer = null;
  const revealed = new Set(); // ids of accounts whose password is currently shown

  // Small helper to build DOM elements safely (text always goes through textContent)
  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function setMessage(node, text, kind) {
    node.textContent = text;
    node.classList.toggle("error", kind === "error");
    node.classList.toggle("ok", kind === "ok");
  }

  function showView(name) {
    Object.keys(views).forEach((key) => { views[key].hidden = key !== name; });
    // "Restore from backup" is offered wherever no vault is currently unlocked
    $("vault-import").hidden = !(name === "setup" || name === "locked" || name === "damaged");
  }

  // Decide which screen to show based on what is in storage
  function refreshVaultView() {
    if (!storage) {
      $("vault-unavailable").hidden = false;
      showView(null);
      return;
    }
    try {
      showView(loadEnvelope(storage) === null ? "setup" : "locked");
    } catch (err) {
      setMessage($("damaged-message"), err.message, "error");
      showView("damaged"); // note: nothing is deleted
    }
  }

  // Disables a button and changes its label while a slow task runs
  function setBusy(button, isBusy, workingLabel) {
    busy = isBusy;
    if (isBusy) { button.dataset.label = button.textContent; button.textContent = workingLabel; }
    else if (button.dataset.label) { button.textContent = button.dataset.label; }
    button.disabled = isBusy;
  }

  /* --- Create a new vault --- */
  views.setup.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (busy) return;
    const msg = $("setup-message");
    const master = $("setup-master").value;
    if (master !== $("setup-confirm").value) { setMessage(msg, "The two master passwords do not match.", "error"); return; }
    if (!$("setup-ack").checked) { setMessage(msg, "Please confirm that you understand the password cannot be recovered.", "error"); return; }
    const button = $("setup-submit");
    setMessage(msg, "", "");
    setBusy(button, true, "Creating (this takes a moment)...");
    try {
      const created = await createVault(master);
      // Safety: never overwrite a vault that appeared meanwhile (e.g. created in another tab)
      if (storage.getItem(VAULT_STORAGE_KEY) !== null) {
        throw new VaultError("EXISTS", "A vault already exists in this browser. Reload the page to unlock it.");
      }
      saveEnvelope(storage, created.envelope);
      session = created.session;
      entries = [];
      ["setup-master", "setup-confirm"].forEach((id) => { $(id).value = ""; });
      $("setup-ack").checked = false;
      enterVault();
    } catch (err) {
      setMessage(msg, err instanceof VaultError ? err.message : "Something went wrong creating the vault.", "error");
    } finally {
      setBusy(button, false);
    }
  });

  /* --- Unlock --- */
  views.locked.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (busy) return;
    const msg = $("unlock-message");
    const masterInput = $("unlock-master");
    const button = $("unlock-submit");
    setMessage(msg, "", "");
    setBusy(button, true, "Unlocking...");
    try {
      const envelope = loadEnvelope(storage);
      if (envelope === null) { refreshVaultView(); return; }
      const result = await unlockVault(envelope, masterInput.value);
      session = result.session;
      entries = sanitizeEntries(result.data.entries).clean;
      masterInput.value = "";
      enterVault();
    } catch (err) {
      // A failed attempt only shows a message. It never changes or deletes the stored vault.
      setMessage(msg, err instanceof VaultError ? err.message : "Something went wrong while unlocking.", "error");
      masterInput.select();
    } finally {
      setBusy(button, false);
    }
  });

  function enterVault() {
    showView("open");
    setMessage(vaultStatus, "", "");
    renderList();
    resetAutoLock();
    $("vault-add").focus();
  }

  /* --- Lock --- */
  // Clears everything secret from memory/screen as far as JavaScript allows
  function lockVault(notice) {
    if (session) session.lock();
    session = null;
    entries = [];
    editingId = null;
    revealed.clear();
    clearTimeout(autoLockTimer);
    autoLockTimer = null;
    closeEntryForm();
    vaultSearch.value = "";
    vaultList.replaceChildren();
    $("import-master").value = "";
    if (confirmDialog.open) confirmDialog.close("cancel");
    setMessage($("unlock-message"), notice || "", "");
    refreshVaultView();
  }

  function resetAutoLock() {
    if (!session) return;
    clearTimeout(autoLockTimer);
    autoLockTimer = setTimeout(() => lockVault("Locked after 5 minutes of inactivity."), AUTO_LOCK_MS);
  }
  ["pointerdown", "keydown", "input", "scroll"].forEach((name) => {
    document.addEventListener(name, resetAutoLock, true);
  });

  $("vault-lock").addEventListener("click", () => {
    lockVault("Vault locked.");
    $("unlock-master").focus();
  });

  /* --- Save changes: encrypt first, write to storage only if that worked --- */
  async function persist(newEntries) {
    const mySession = session;
    if (!mySession) throw new VaultError("LOCKED", "The vault is locked.");
    const envelope = await mySession.encrypt({ v: VAULT_VERSION, entries: newEntries });
    if (session !== mySession) throw new VaultError("LOCKED", "The vault was locked before saving finished.");
    saveEnvelope(storage, envelope);
    entries = newEntries;
  }

  function errorText(err) {
    return err instanceof VaultError ? err.message : "Something went wrong. Nothing was changed.";
  }

  /* --- Confirmation dialog (falls back to the browser's confirm if <dialog> is unsupported) --- */
  function askConfirm(title, text, okLabel) {
    if (typeof confirmDialog.showModal !== "function") {
      return Promise.resolve(window.confirm(title + "\n\n" + text));
    }
    $("confirm-title").textContent = title;
    $("confirm-text").textContent = text;
    $("confirm-ok").textContent = okLabel;
    confirmDialog.returnValue = "";
    return new Promise((resolve) => {
      confirmDialog.addEventListener("close", () => resolve(confirmDialog.returnValue === "ok"), { once: true });
      confirmDialog.showModal();
    });
  }

  /* --- Erase vault (only ever started by the user, behind a confirmation) --- */
  async function eraseVault() {
    const ok = await askConfirm(
      "Erase the vault?",
      "This permanently deletes the encrypted vault from this browser. Without a backup it cannot be recovered.",
      "Erase permanently"
    );
    if (!ok) return;
    try {
      storage.removeItem(VAULT_STORAGE_KEY);
    } catch (e) { /* ignored: the view below will show the real state */ }
    refreshVaultView();
  }
  $("erase-locked").addEventListener("click", eraseVault);
  $("erase-damaged").addEventListener("click", eraseVault);

  /* --- Add / edit form --- */
  function setEntryVisible(visible) {
    entryFields.password.type = visible ? "text" : "password";
    $("entry-toggle").textContent = visible ? "Hide" : "Show";
    $("entry-toggle").setAttribute("aria-pressed", String(visible));
  }

  function openEntryForm(entry, prefill) {
    editingId = entry ? entry.id : null;
    const values = entry || prefill || {};
    Object.keys(entryFields).forEach((key) => { entryFields[key].value = values[key] || ""; });
    $("entry-form-title").textContent = entry ? "Edit account" : "Add account";
    setMessage($("entry-message"), "", "");
    setEntryVisible(false);
    entryForm.hidden = false;
    entryFields.name.focus();
  }

  function closeEntryForm() {
    Object.values(entryFields).forEach((field) => { field.value = ""; });
    setEntryVisible(false);
    editingId = null;
    entryForm.hidden = true;
  }

  // Accepts only http/https URLs (blocks things like javascript: links). Returns "" if empty.
  function cleanUrl(text) {
    const trimmed = text.trim();
    if (trimmed === "") return "";
    let url;
    try {
      url = new URL(/^[a-z][a-z0-9+.-]*:/i.test(trimmed) ? trimmed : "https://" + trimmed);
    } catch (e) {
      return null;
    }
    return url.protocol === "http:" || url.protocol === "https:" ? url.href : null;
  }

  // Short random id (not secret, just unique)
  function newId() {
    return Array.from(globalThis.crypto.getRandomValues(new Uint8Array(8)), (b) => b.toString(16).padStart(2, "0")).join("");
  }

  $("vault-add").addEventListener("click", () => openEntryForm(null));
  $("entry-cancel").addEventListener("click", () => { closeEntryForm(); $("vault-add").focus(); });
  $("entry-toggle").addEventListener("click", () => setEntryVisible(entryFields.password.type === "password"));
  $("entry-generate").addEventListener("click", () => {
    entryFields.password.value = generatePassword({ length: 20, upper: true, lower: true, numbers: true, symbols: true });
    setEntryVisible(true);
  });

  entryForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (busy) return;
    const msg = $("entry-message");
    const name = entryFields.name.value.trim();
    const username = entryFields.username.value.trim();
    const password = entryFields.password.value;
    const url = cleanUrl(entryFields.url.value);
    if (!name) { setMessage(msg, "Please enter a website or app name.", "error"); return; }
    if (url === null) { setMessage(msg, "That URL is not valid. Use an http:// or https:// address.", "error"); return; }
    if (!username) { setMessage(msg, "Please enter a username or email.", "error"); return; }
    if (!password) { setMessage(msg, "Please enter a password.", "error"); return; }

    const entry = {
      id: editingId || newId(), name, url, username, password,
      notes: entryFields.notes.value.trim(), updatedAt: new Date().toISOString()
    };
    const next = editingId ? entries.map((e) => (e.id === editingId ? entry : e)) : entries.concat(entry);
    const button = $("entry-save");
    setBusy(button, true, "Saving...");
    try {
      await persist(next);
      closeEntryForm();
      renderList();
      setMessage(vaultStatus, 'Saved "' + name + '".', "ok");
    } catch (err) {
      setMessage(msg, errorText(err), "error");
    } finally {
      setBusy(button, false);
    }
  });

  /* --- Loading entries safely ---
     Data from a backup file is encrypted, but whoever made the file chose its contents.
     So before using it we make sure every field has the right type and size, and we
     re-check every URL (so a "javascript:" link can never reach the page). */
  function sanitizeEntries(list) {
    const clean = [];
    const seen = new Set();
    let dropped = 0;
    for (const e of list) {
      if (!e || typeof e !== "object" || typeof e.name !== "string" || e.name.trim() === "" ||
          typeof e.username !== "string" || typeof e.password !== "string") {
        dropped++;
        continue;
      }
      const id = typeof e.id === "string" && /^[A-Za-z0-9-]{1,40}$/.test(e.id) && !seen.has(e.id) ? e.id : newId();
      seen.add(id);
      clean.push({
        id,
        name: e.name.slice(0, 100),
        url: typeof e.url === "string" ? (cleanUrl(e.url.slice(0, 300)) || "") : "",
        username: e.username.slice(0, 200),
        password: e.password.slice(0, 500),
        notes: typeof e.notes === "string" ? e.notes.slice(0, 1000) : "",
        updatedAt: typeof e.updatedAt === "string" ? e.updatedAt.slice(0, 40) : ""
      });
    }
    return { clean, dropped };
  }

  /* --- Export / import of the ENCRYPTED backup --- */
  function downloadText(filename, text) {
    const blob = new Blob([text], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  // Exports exactly what is already in storage: the encrypted envelope, never plaintext
  function exportBackup(messageNode) {
    try {
      const envelope = loadEnvelope(storage);
      if (envelope === null) { setMessage(messageNode, "There is no vault to export yet.", "error"); return; }
      const day = new Date().toISOString().slice(0, 10);
      downloadText("securenest-backup-" + day + ".json", exportEnvelopeText(envelope));
      setMessage(messageNode, "Encrypted backup downloaded. It needs your master password to open.", "ok");
    } catch (err) {
      setMessage(messageNode, errorText(err), "error");
    }
  }
  $("vault-export").addEventListener("click", () => exportBackup(vaultStatus));
  $("export-locked").addEventListener("click", () => exportBackup($("unlock-message")));

  function readFileText(file) {
    if (typeof file.text === "function") return file.text();
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(String(reader.result));
      reader.onerror = () => reject(reader.error);
      reader.readAsText(file);
    });
  }

  $("import-submit").addEventListener("click", async () => {
    if (busy) return;
    const msg = $("import-message");
    const fileInput = $("import-file");
    const masterInput = $("import-master");
    const button = $("import-submit");
    const file = fileInput.files && fileInput.files[0];
    if (!file) { setMessage(msg, "Choose a backup file first.", "error"); return; }
    if (file.size > MAX_BACKUP_BYTES) { setMessage(msg, "That file is too large to be a SecureNest backup.", "error"); return; }
    if (masterInput.value === "") { setMessage(msg, "Enter the master password of the backup.", "error"); return; }

    setMessage(msg, "", "");
    setBusy(button, true, "Checking backup...");
    try {
      // 1) Check the file's structure, then 2) prove it decrypts with the password given
      const envelope = parseEnvelopeText(await readFileText(file));
      const opened = await unlockVault(envelope, masterInput.value);

      // 3) Only now, and only with confirmation, replace anything that exists
      if (storage.getItem(VAULT_STORAGE_KEY) !== null) {
        const ok = await askConfirm(
          "Replace the vault in this browser?",
          "The backup is valid. Importing it will permanently replace the vault currently stored in this browser. " +
          "Export a backup of the current vault first if you might need it.",
          "Replace vault"
        );
        if (!ok) { opened.session.lock(); setMessage(msg, "Import cancelled. Nothing was changed.", ""); return; }
      }
      saveEnvelope(storage, envelope);
      session = opened.session;
      const result = sanitizeEntries(opened.data.entries);
      entries = result.clean;
      fileInput.value = "";
      masterInput.value = "";
      setMessage(msg, "", "");
      enterVault();
      setMessage(vaultStatus,
        "Backup imported (" + entries.length + (entries.length === 1 ? " account" : " accounts") + ")." +
        (result.dropped ? " " + result.dropped + " damaged item(s) were skipped." : ""), "ok");
    } catch (err) {
      setMessage(msg, err instanceof VaultError ? err.message : "Could not read that file.", "error");
    } finally {
      setBusy(button, false);
    }
  });

  /* --- Copy --- */
  async function copyValue(value, label) {
    try {
      await navigator.clipboard.writeText(value);
      setMessage(vaultStatus, label + " copied.", "ok");
    } catch (e) {
      setMessage(vaultStatus, "Copy was blocked by the browser. Show the value and copy it manually.", "error");
    }
  }

  /* --- The list --- */
  function matchesSearch(entry, query) {
    return [entry.name, entry.url, entry.username, entry.notes].some((f) => (f || "").toLowerCase().includes(query));
  }

  function makeButton(label, ariaLabel, onClick) {
    const b = el("button", "btn btn--ghost btn--small", label);
    b.type = "button";
    b.setAttribute("aria-label", ariaLabel);
    b.addEventListener("click", onClick);
    return b;
  }

  function renderEntry(entry) {
    const li = el("li", "entry");
    li.appendChild(el("h4", "entry__name", entry.name));
    li.appendChild(el("p", "entry__line", "User: " + entry.username));

    if (entry.url) {
      const line = el("p", "entry__line", "Site: ");
      const a = el("a", "", entry.url);
      a.href = entry.url;
      a.target = "_blank";
      a.rel = "noopener noreferrer";
      line.appendChild(a);
      li.appendChild(line);
    }

    const pwLine = el("p", "entry__line", "Password: ");
    const pwText = el("span", "entry__password", revealed.has(entry.id) ? entry.password : "••••••••••");
    pwLine.appendChild(pwText);
    li.appendChild(pwLine);

    if (entry.notes) li.appendChild(el("p", "entry__line", "Notes: " + entry.notes));

    const actions = el("div", "action-row");
    const showing = revealed.has(entry.id);
    const toggle = makeButton(showing ? "Hide" : "Show", (showing ? "Hide" : "Show") + " password for " + entry.name, () => {
      if (revealed.has(entry.id)) revealed.delete(entry.id); else revealed.add(entry.id);
      renderList();
    });
    toggle.setAttribute("aria-pressed", String(showing));
    actions.appendChild(toggle);
    actions.appendChild(makeButton("Copy user", "Copy username for " + entry.name, () => copyValue(entry.username, "Username")));
    actions.appendChild(makeButton("Copy password", "Copy password for " + entry.name, () => copyValue(entry.password, "Password")));
    actions.appendChild(makeButton("Edit", "Edit " + entry.name, () => openEntryForm(entry)));
    actions.appendChild(makeButton("Delete", "Delete " + entry.name, async () => {
      const ok = await askConfirm("Delete this account?", 'Delete "' + entry.name + '" from your vault? This cannot be undone.', "Delete");
      if (!ok || busy || !session) return;
      try {
        await persist(entries.filter((e) => e.id !== entry.id));
        revealed.delete(entry.id);
        renderList();
        setMessage(vaultStatus, 'Deleted "' + entry.name + '".', "ok");
      } catch (err) {
        setMessage(vaultStatus, errorText(err), "error");
      }
    }));
    li.appendChild(actions);
    return li;
  }

  function renderList() {
    vaultList.replaceChildren();
    const query = vaultSearch.value.trim().toLowerCase();
    const shown = entries
      .filter((e) => query === "" || matchesSearch(e, query))
      .sort((a, b) => a.name.localeCompare(b.name));

    if (entries.length === 0) {
      vaultEmpty.textContent = "Your vault is empty. Choose \"Add account\" to save your first login.";
    } else if (shown.length === 0) {
      vaultEmpty.textContent = "No accounts match your search.";
    }
    vaultEmpty.hidden = shown.length > 0;
    shown.forEach((entry) => vaultList.appendChild(renderEntry(entry)));
  }
  vaultSearch.addEventListener("input", renderList);

  /* --- Generator -> Vault --- */
  genSave.addEventListener("click", () => {
    if (!session) {
      setGenMessage("Unlock your vault first (open My Vault), then press Save to Vault again.", true);
      return;
    }
    selectTab($("tab-vault"));
    openEntryForm(null, { password: genOutput.value });
  });

  refreshVaultView();

  /* ----- Background code rain (purely decorative) -----
     Faint streaks of characters fall slowly down the screen, like a quiet "digital rain".
     It is kept cheap on purpose:
       - only a limited number of columns are active at once (fewer on phones)
       - drawn at about 30 frames per second
       - movement is based on elapsed time, so speed looks the same on any screen
       - it pauses when the tab is hidden and is switched off for "reduce motion"
     It uses a small fixed-seed generator (not the secure one), since it is only
     for looks and has nothing to do with security. */
  (function startCodeRain() {
    const canvas = $("bg-code");
    let ctx = null;
    try { ctx = canvas.getContext("2d"); } catch (e) { ctx = null; }
    if (!ctx || !window.requestAnimationFrame) return;

    const motionQuery = window.matchMedia ? window.matchMedia("(prefers-reduced-motion: reduce)") : null;
    const GLYPHS = "0123456789ABCDEF{}[]<>/\|=+*#$%&@!?;:~^";
    const COLORS = ["167, 139, 250", "167, 139, 250", "110, 200, 160", "122, 162, 255"]; // purple, purple, green, blue
    const LINE = 16;  // pixels between characters in a streak

    function makeRandom(seed) { // mulberry32: tiny deterministic generator
      return function () {
        seed = (seed + 0x6D2B79F5) | 0;
        let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
        t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
        return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
      };
    }
    const random = makeRandom(20240601);
    const glyph = () => GLYPHS[Math.floor(random() * GLYPHS.length)];

    let width = 0, height = 0, columns = [];
    let running = false, lastTime = 0, lastDraw = 0, resizeTimer = null;

    // Give a column new random look and speed, starting just above the top of the screen
    function respawn(col, anywhere) {
      col.len = 6 + Math.floor(random() * 9);                 // 6 to 14 characters long
      col.speed = 22 + random() * 38;                         // 22 to 60 pixels per second
      col.alpha = 0.10 + random() * 0.18;                     // faint
      col.color = COLORS[Math.floor(random() * COLORS.length)];
      col.chars = Array.from({ length: col.len }, glyph);
      col.y = anywhere ? random() * (height + col.len * LINE) : -random() * height * 0.6;
    }

    // Lay out the columns. Rebuilt when the width changes (not for small height changes
    // such as a phone's address bar hiding).
    function buildColumns() {
      const spacing = width < 600 ? 26 : 34;
      const slots = Math.floor(width / spacing);
      const active = Math.max(6, Math.min(width < 600 ? 10 : 28, Math.floor(slots * 0.4)));
      // pick evenly spread slots, with a little random shift so it is not a rigid grid
      columns = [];
      for (let i = 0; i < active; i++) {
        const col = { x: ((i + 0.5) / active) * width + (random() - 0.5) * spacing * 0.6 };
        respawn(col, true);
        columns.push(col);
      }
    }

    function sizeCanvas() {
      const ratio = Math.min(window.devicePixelRatio || 1, 1.5);
      canvas.width = Math.round(width * ratio);
      canvas.height = Math.round(height * ratio);
      ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
      ctx.font = "13px ui-monospace, Consolas, 'Courier New', monospace";
      ctx.textAlign = "center";
      ctx.textBaseline = "middle";
    }

    function handleResize() {
      const widthChanged = window.innerWidth !== width;
      width = window.innerWidth;
      height = window.innerHeight;
      sizeCanvas();
      if (widthChanged || columns.length === 0) buildColumns();
      if (!running) draw(0);
    }

    function draw(dt) {
      ctx.clearRect(0, 0, width, height);
      for (const col of columns) {
        col.y += col.speed * dt;
        if (col.y - col.len * LINE > height) respawn(col, false); // fully off the bottom: restart at top
        if (random() < dt * 2) col.chars[Math.floor(random() * col.len)] = glyph(); // occasional flicker of one character

        for (let i = 0; i < col.len; i++) {
          const y = col.y - i * LINE;                    // i = 0 is the leading (brightest) character
          if (y < -LINE || y > height + LINE) continue;
          const fade = 1 - i / col.len;                  // trail fades out behind the head
          ctx.fillStyle = "rgba(" + col.color + "," + (col.alpha * fade * (i === 0 ? 1.4 : 1)).toFixed(3) + ")";
          ctx.fillText(col.chars[i], col.x, y);
        }
      }
    }

    function frame(time) {
      if (!running) return;
      if (time - lastDraw >= 33) {                       // about 30 fps
        const dt = Math.min((time - (lastTime || time)) / 1000, 0.1); // never jump after a pause
        lastTime = time;
        lastDraw = time;
        draw(dt);
      }
      window.requestAnimationFrame(frame);
    }

    function sync() {
      const allowed = !(motionQuery && motionQuery.matches) && !document.hidden;
      if (allowed && !running) {
        running = true;
        lastTime = 0;
        window.requestAnimationFrame(frame);
      } else if (!allowed) {
        running = false;
        ctx.clearRect(0, 0, width, height);
      }
    }

    handleResize();
    window.addEventListener("resize", () => {
      clearTimeout(resizeTimer);
      resizeTimer = setTimeout(handleResize, 150);       // wait until resizing settles
    });
    document.addEventListener("visibilitychange", sync);
    if (motionQuery) {
      if (motionQuery.addEventListener) motionQuery.addEventListener("change", sync);
      else if (motionQuery.addListener) motionQuery.addListener(sync);
    }
    sync();
  })();

  /* ----- Navigation (tabs) ----- */
  const tabs = Array.from(document.querySelectorAll('#tablist [role="tab"]'));

  function selectTab(tab) {
    tabs.forEach((t) => {
      const selected = t === tab;
      t.setAttribute("aria-selected", String(selected));
      t.tabIndex = selected ? 0 : -1; // only the active tab is in the Tab key order
      document.getElementById(t.getAttribute("aria-controls")).hidden = !selected;
    });
  }

  tabs.forEach((tab, i) => {
    tab.addEventListener("click", () => selectTab(tab));
    // Arrow keys / Home / End move between tabs, as users expect from tab widgets
    tab.addEventListener("keydown", (e) => {
      let next = null;
      if (e.key === "ArrowRight") next = tabs[(i + 1) % tabs.length];
      else if (e.key === "ArrowLeft") next = tabs[(i - 1 + tabs.length) % tabs.length];
      else if (e.key === "Home") next = tabs[0];
      else if (e.key === "End") next = tabs[tabs.length - 1];
      if (next) { e.preventDefault(); selectTab(next); next.focus(); }
    });
  });
}

// Lets Node load the logic for testing. Browsers skip this (no "module" there).
if (typeof module !== "undefined") {
  module.exports = {
    analyzePassword, secureRandomInt, generatePassword, MIN_LENGTH, MAX_LENGTH,
    VaultError, createVault, unlockVault, loadEnvelope, saveEnvelope,
    parseEnvelopeText, exportEnvelopeText, VAULT_STORAGE_KEY
  };
}
