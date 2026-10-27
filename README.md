# SecureNest

A beginner-friendly cybersecurity project built with plain HTML, CSS and JavaScript. No frameworks, no backend, no external libraries. It has three tabs:

1. **Password Checker**: a real-time strength estimator.
2. **Password Generator**: random passwords from the browser's cryptographic random source.
3. **My Vault**: a small, encrypted password manager that lives in your browser.

> **Disclaimer:** This is an educational project. The strength checker is a basic estimator, and the vault has not been independently audited. Do not rely on it as your only copy of important passwords. For real-world use, prefer a well-established password manager.

## Getting started

Open `index.html` in a modern browser (Chrome, Edge, Firefox, Safari). No build step or server is needed.

## Password Checker

- Live meter: Weak, Fair, Good, Strong
- Checklist for length (8 and 12), uppercase, lowercase, number and special character
- Plain-English suggestions
- Detects very common passwords, repeated characters and simple sequences (`abcd`, `1234`)

**Scoring:** each of the six checks passed adds 1 point; repeated characters and sequences each subtract 1. Passwords under 8 characters or on the common list are always Weak, and passwords under 12 characters can't reach Strong.

## Password Generator

Uses `crypto.getRandomValues` with rejection sampling (no modulo bias, never `Math.random`). You choose the length and character sets. It can copy a password, send it to the checker, or save it to the vault.

## The Vault

### How the encryption works

1. Your **master password is never stored**. It is turned into a 256-bit key with **PBKDF2-HMAC-SHA256** (600,000 iterations, random 16-byte salt) through the Web Crypto API.
2. The vault is encrypted with **AES-256-GCM** using a fresh random 12-byte nonce on every save. GCM is authenticated, so a wrong password or any tampering makes decryption fail rather than return garbage.
3. Only the **encrypted envelope** (format, KDF settings, nonce, ciphertext) is written to `localStorage`. Account names, usernames, passwords and notes never appear in storage in plain text.
4. Decrypted data exists only in memory while the vault is unlocked. The vault **locks automatically after 5 minutes of inactivity**, and can be locked manually.

### Backups: export and import

- **Export backup** downloads the already-encrypted envelope as `securenest-backup-YYYY-MM-DD.json`. It is available from the open vault and from the locked screen. The file contains no plaintext credentials and needs your master password to open.
- **Restore from an encrypted backup** is offered on the create, locked and damaged-vault screens. Before anything is saved, the app:
  1. rejects files over 12 MB,
  2. checks the file's structure and rejects weak or absurd key-derivation settings,
  3. proves the file decrypts with the master password you entered,
  4. asks for confirmation if it would replace an existing vault.
- A failed or cancelled import changes nothing.
- Because whoever made a backup file chose its contents, entries are re-validated on load: malformed items are skipped (and counted), fields are length-limited, and `javascript:` or other non-web URLs are removed. All page text is inserted with `textContent`, never `innerHTML`.

### If something goes wrong

- A damaged saved vault is **never deleted automatically**. You are shown a clear message and can restore from a backup, or erase it deliberately (behind a confirmation).
- If the browser blocks `localStorage` (some private modes), the vault tab says so and the other tabs still work.

## Privacy

Everything runs locally in your browser. Nothing is sent over a network (the code contains no `fetch`, `XMLHttpRequest` or similar, and a test checks this). Passwords are never logged, and the code uses no cookies or `sessionStorage`.

## Limitations

Please read these before trusting the vault with anything important.

- **Forgotten master password = lost data.** There is no recovery and no reset. That is the point of the design.
- **Data lives in one browser profile.** Clearing site data, using another browser, or another device means an empty vault unless you restore a backup. Export backups regularly and keep them somewhere safe.
- **A weak master password weakens everything.** PBKDF2 slows guessing but cannot save a guessable password. Use a long passphrase (the app only requires 10 characters, which is a minimum, not a recommendation).
- **It cannot protect an already-compromised computer.** Malware, a malicious browser extension or someone with access to your unlocked session can read the vault while it is open. It also cannot clear the clipboard after you copy a password.
- **Backups are only as private as the master password.** Anyone who gets a backup file can try to guess the master password offline.
- **Not audited.** It uses standard, well-reviewed browser primitives, but the application code around them has had no professional review. JavaScript strings cannot be reliably wiped from memory.
- The strength checker's common-password list is tiny (about 20 entries), it does not check breach databases, and length and variety are only proxies for real strength.
- No sync, no autofill, no browser extension.

## Testing

The Node tests need Node 18 or newer.

| Command | What it covers |
| --- | --- |
| `node tests/vault.test.js` | Encryption core: no plaintext in storage, unlock, wrong password, tampering, bad or weak backup files, export/import round trip, master password rules, and source checks (no logging, no `Math.random`, no `innerHTML`, no network calls). |
| `node tests/generator.test.js` | Generator rules and randomness (including a chi-square check). |
| `node tests/ui.test.js` | Drives the real page to test backup export and import: download contents, restore, wrong password, bad or oversize file, replace confirmation (cancel and confirm), and hostile backup contents. Needs `npm install jsdom` first (a test-only tool; the app has no dependencies). |

## Project structure

```
index.html   page structure
style.css    styling
script.js    checker, generator and vault (Part 1: logic testable in Node, Part 2: the page)
tests/       vault, generator and UI tests
```

## Technologies

HTML5, CSS3, vanilla JavaScript (ES2020), Web Crypto API.

## License

MIT
