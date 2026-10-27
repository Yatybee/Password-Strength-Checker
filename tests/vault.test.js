// Run with:  node tests/vault.test.js
// Tests the encryption core in script.js (no browser needed). Needs Node 18+.
const assert = require("assert");
const fs = require("fs");
const path = require("path");
const S = require("../script.js");

// A tiny stand-in for localStorage
function fakeStorage(failWrites) {
  const map = new Map();
  return {
    getItem: (k) => (map.has(k) ? map.get(k) : null),
    setItem: (k, v) => { if (failWrites) throw new Error("quota"); map.set(k, String(v)); },
    removeItem: (k) => map.delete(k),
    dump: () => JSON.stringify([...map])
  };
}
const MASTER = "correct-horse-Battery-9";
const SECRET_ENTRY = { id: "1", name: "ExampleSite", username: "alice@example.com", password: "S3cretPassw0rd!xyz", notes: "my private note" };

async function rejects(promise, code) {
  try { await promise; } catch (e) {
    assert(e instanceof S.VaultError, "expected VaultError, got " + e);
    assert.strictEqual(e.code, code, "expected " + code + " got " + e.code);
    return;
  }
  assert.fail("expected rejection with " + code);
}
function throwsCode(fn, code) {
  try { fn(); } catch (e) { assert.strictEqual(e.code, code); return; }
  assert.fail("expected throw " + code);
}
const clone = (o) => JSON.parse(JSON.stringify(o));
let passed = 0;
async function test(name, fn) { await fn(); passed++; console.log("  ok  " + name); }

(async () => {
  // Shared vault for the tests
  const { session, envelope } = await S.createVault(MASTER);
  const saved = await session.encrypt({ v: 1, entries: [SECRET_ENTRY] });

  await test("stored text contains no plaintext secrets or master password", async () => {
    const storage = fakeStorage();
    S.saveEnvelope(storage, saved);
    const raw = storage.dump();
    for (const s of ["S3cretPassw0rd", "alice@example.com", "ExampleSite", "private note", MASTER, "entries"]) {
      assert(!raw.includes(s), "leaked: " + s);
    }
    assert.deepStrictEqual(Object.keys(saved).sort(), ["cipher", "data", "format", "kdf", "v"]);
  });

  await test("correct master password unlocks and returns the data", async () => {
    const { data } = await S.unlockVault(saved, MASTER);
    assert.deepStrictEqual(data.entries[0], SECRET_ENTRY);
  });

  await test("works after a 'refresh' (save to storage, reload from storage, unlock)", async () => {
    const storage = fakeStorage();
    S.saveEnvelope(storage, saved);
    const reloaded = S.loadEnvelope(storage);
    const { data } = await S.unlockVault(reloaded, MASTER);
    assert.strictEqual(data.entries[0].password, SECRET_ENTRY.password);
  });

  await test("wrong master password is rejected; stored vault is untouched", async () => {
    const storage = fakeStorage();
    S.saveEnvelope(storage, saved);
    const before = storage.dump();
    for (const bad of ["wrong-password-123", MASTER + " ", MASTER.toUpperCase(), ""]) {
      await rejects(S.unlockVault(S.loadEnvelope(storage), bad), "WRONG_PASSWORD_OR_CORRUPT");
    }
    assert.strictEqual(storage.dump(), before);
    assert.notStrictEqual(storage.getItem(S.VAULT_STORAGE_KEY), null);
  });

  await test("error messages never contain the password or data", async () => {
    try { await S.unlockVault(saved, "wrong-password-123"); } catch (e) {
      assert(!e.message.includes("wrong-password-123") && !e.message.includes(SECRET_ENTRY.password));
    }
  });

  await test("tampering with ANY field is detected", async () => {
    const flip = (b64) => {
      const bytes = Buffer.from(b64, "base64"); bytes[0] ^= 1; return bytes.toString("base64");
    };
    const mutations = {
      "ciphertext byte": (e) => { e.data = flip(e.data); },
      "iv": (e) => { e.cipher.iv = flip(e.cipher.iv); },
      "salt": (e) => { e.kdf.salt = flip(e.kdf.salt); },
      "iterations": (e) => { e.kdf.iterations += 1; },
      "truncated ciphertext": (e) => { e.data = Buffer.from(e.data, "base64").subarray(0, -1).toString("base64"); }
    };
    for (const [name, mutate] of Object.entries(mutations)) {
      const e = clone(saved); mutate(e);
      await rejects(S.unlockVault(e, MASTER), "WRONG_PASSWORD_OR_CORRUPT");
    }
  });

  await test("structurally invalid vaults are rejected gracefully", async () => {
    const cases = {
      "null": null, "array": [], "string": "x", "empty object": {},
      "wrong format": { ...clone(saved), format: "other" },
      "version 0": { ...clone(saved), v: 0 },
      "version 1.5": { ...clone(saved), v: 1.5 },
      "missing kdf": (() => { const e = clone(saved); delete e.kdf; return e; })(),
      "unknown kdf": (() => { const e = clone(saved); e.kdf.name = "scrypt"; return e; })(),
      "weak iterations": (() => { const e = clone(saved); e.kdf.iterations = 1; return e; })(),
      "huge iterations": (() => { const e = clone(saved); e.kdf.iterations = 1e9; return e; })(),
      "bad base64": (() => { const e = clone(saved); e.data = "!!!not base64!!!"; return e; })(),
      "short salt": (() => { const e = clone(saved); e.kdf.salt = "AAAA"; return e; })(),
      "short iv": (() => { const e = clone(saved); e.cipher.iv = "AAAA"; return e; })(),
      "data shorter than tag": (() => { const e = clone(saved); e.data = "AAAA"; return e; })()
    };
    for (const [name, e] of Object.entries(cases)) {
      await rejects(S.unlockVault(e, MASTER), "INVALID_FORMAT");
    }
    const newer = clone(saved); newer.v = 2;
    await rejects(S.unlockVault(newer, MASTER), "UNSUPPORTED_VERSION");
  });

  await test("corrupted stored text throws but is NOT deleted or reset", async () => {
    const storage = fakeStorage();
    for (const junk of ["{not json", "[]", "null", "{}", "x".repeat(100)]) {
      storage.setItem(S.VAULT_STORAGE_KEY, junk);
      throwsCode(() => S.loadEnvelope(storage), "INVALID_FORMAT");
      assert.strictEqual(storage.getItem(S.VAULT_STORAGE_KEY), junk);
    }
    assert.strictEqual(S.loadEnvelope(fakeStorage()), null); // no vault yet -> null
  });

  await test("repeated encryption: fresh nonce each time, same salt, always decryptable", async () => {
    const seenIv = new Set(), seenData = new Set();
    let last;
    for (let i = 0; i < 25; i++) {
      last = await session.encrypt({ v: 1, entries: [SECRET_ENTRY] }); // identical plaintext
      seenIv.add(last.cipher.iv); seenData.add(last.data);
      assert.strictEqual(last.kdf.salt, saved.kdf.salt);
    }
    assert.strictEqual(seenIv.size, 25);
    assert.strictEqual(seenData.size, 25);
    const { data } = await S.unlockVault(last, MASTER);
    assert.strictEqual(data.entries.length, 1);
  });

  await test("a new vault gets a new random salt and different ciphertext", async () => {
    const other = await S.createVault(MASTER);
    assert.notStrictEqual(other.envelope.kdf.salt, envelope.kdf.salt);
    assert.notStrictEqual(other.envelope.data, envelope.data);
  });

  await test("lock: session refuses to work and cannot expose a key", async () => {
    const { session: s } = await S.createVault(MASTER);
    assert.strictEqual(s.unlocked, true);
    s.lock();
    assert.strictEqual(s.unlocked, false);
    await rejects(s.encrypt({ v: 1, entries: [] }), "LOCKED");
    assert(!JSON.stringify(s).includes("key") && Object.keys(s).every((k) => !/key/i.test(k)));
  });

  await test("lock then unlock again gives a working new session; old one stays locked", async () => {
    const { session: s1, envelope: e1 } = await S.createVault(MASTER);
    s1.lock();
    const { session: s2, data } = await S.unlockVault(e1, MASTER);
    assert.deepStrictEqual(data.entries, []);
    assert.strictEqual(s1.unlocked, false);
    const e2 = await s2.encrypt({ v: 1, entries: [SECRET_ENTRY] });
    const again = await S.unlockVault(e2, MASTER);
    assert.strictEqual(again.data.entries.length, 1);
  });

  await test("a failed save leaves the previous vault intact", async () => {
    const storage = fakeStorage();
    S.saveEnvelope(storage, saved);
    const before = storage.dump();
    const next = await session.encrypt({ v: 1, entries: [] });
    const full = { getItem: storage.getItem, setItem() { throw new Error("quota"); } };
    throwsCode(() => S.saveEnvelope(full, next), "STORAGE_FAILED");
    assert.strictEqual(storage.dump(), before);
    // and a broken envelope is refused before it ever reaches storage
    throwsCode(() => S.saveEnvelope(storage, { bad: true }), "INVALID_FORMAT");
    assert.strictEqual(storage.dump(), before);
  });

  await test("export / import round trip, and the export has no plaintext", async () => {
    const text = S.exportEnvelopeText(saved);
    for (const s of ["S3cretPassw0rd", "alice@example.com", MASTER]) assert(!text.includes(s));
    const imported = S.parseEnvelopeText(text);
    const { data } = await S.unlockVault(imported, MASTER);
    assert.strictEqual(data.entries[0].username, SECRET_ENTRY.username);
    await rejects(S.unlockVault(imported, "not-the-master-pw"), "WRONG_PASSWORD_OR_CORRUPT");
    throwsCode(() => S.parseEnvelopeText("{oops"), "INVALID_FORMAT");
    throwsCode(() => S.parseEnvelopeText('{"a":1}'), "INVALID_FORMAT");
    throwsCode(() => S.parseEnvelopeText(42), "INVALID_FORMAT");
  });

  await test("master password rules and Unicode normalisation", async () => {
    for (const weak of ["", "short", "123456789", undefined, null, 12345678901]) {
      await rejects(S.createVault(weak), "WEAK_MASTER");
    }
    const composed = "café-passw0rd!!";   // é as one character
    const decomposed = "café-passw0rd!!"; // e + combining accent
    const { envelope: e } = await S.createVault(composed);
    await S.unlockVault(e, decomposed); // must succeed
  });

  await test("source code never logs or uses Math.random or web storage for secrets", async () => {
    const src = fs.readFileSync(path.join(__dirname, "..", "script.js"), "utf8");
    assert(!/console\./.test(src), "console usage found");
    assert(!/Math\.random/.test(src));
    assert(!/sessionStorage|document\.cookie/.test(src));
    assert(!/innerHTML|outerHTML|insertAdjacentHTML|eval\(/.test(src));
    assert(!/fetch\(|XMLHttpRequest|sendBeacon|WebSocket/.test(src));
  });

  console.log("\n" + passed + " vault tests passed");
})().catch((e) => { console.error("FAILED:", e); process.exit(1); });
