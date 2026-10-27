// Run with:  node tests/ui.test.js
// Drives the real page in jsdom to test backup export/import. Needs Node 18+ and: npm install jsdom
// (jsdom is a test-only tool; the app itself has no dependencies.)
const assert = require("assert");
const path = require("path");
const nodeCrypto = require("crypto");
const { JSDOM } = require("jsdom");

const PAGE = path.join(__dirname, "..", "index.html");
const MASTER = "correct-horse-Battery-9";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let passed = 0;

async function open() {
  const downloads = [];
  const fsx = require("fs");
  const root = path.dirname(PAGE);
  const tag = "<script src=\"script.js\"></script>";
  const code = fsx.readFileSync(path.join(root, "script.js"), "utf8").split("</script").join("<\\/script");
  const html = fsx.readFileSync(PAGE, "utf8").split(tag).join("<script>" + code + "</script>");
  const dom = new JSDOM(html, {
    runScripts: "dangerously", url: "http://localhost/",
    beforeParse(w) {
      Object.defineProperty(w, "crypto", { value: nodeCrypto.webcrypto, configurable: true });
      w.TextEncoder = TextEncoder; w.TextDecoder = TextDecoder;
      w.URL.createObjectURL = (blob) => { downloads.push(blob); return "blob:x"; };
      w.URL.revokeObjectURL = () => {};
      w.HTMLAnchorElement.prototype.click = function () { downloads.push({ name: this.download }); };
      w.confirm = () => (w.__confirm === undefined ? true : w.__confirm);
    }
  });
  await new Promise((r) => dom.window.addEventListener("load", r));
  await sleep(50);
  const w = dom.window, d = w.document;
  d.getElementById("tab-vault").click();
  return { dom, w, d, downloads, $: (id) => d.getElementById(id) };
}
async function until(fn, label) {
  for (let i = 0; i < 300; i++) { if (fn()) return; await sleep(50); }
  throw new Error("timeout: " + label);
}
async function setupVault(p, master) {
  p.$("setup-master").value = master; p.$("setup-confirm").value = master;
  p.$("setup-ack").checked = true; p.$("setup-submit").click();
  await until(() => !p.$("vault-open").hidden, "vault opens");
}
async function addEntry(p, name, pw) {
  p.$("vault-add").click();
  p.$("entry-name").value = name; p.$("entry-username").value = "user@x.com"; p.$("entry-password").value = pw;
  p.$("entry-save").click();
  await until(() => p.$("vault-list").textContent.includes(name), "entry listed");
}
function pickFile(p, text, name, size) {
  const file = new p.w.File([text], name || "b.json", { type: "application/json" });
  if (size !== undefined) Object.defineProperty(file, "size", { value: size });
  Object.defineProperty(p.$("import-file"), "files", { value: [file], configurable: true });
}
const stored = (p) => Object.values(p.w.localStorage)[0];
async function test(name, fn) { await fn(); passed++; console.log("  ok  " + name); }

(async () => {
  let backupText;

  await test("export downloads only the encrypted envelope", async () => {
    const p = await open();
    await setupVault(p, MASTER);
    await addEntry(p, "ExampleSite", "S3cretPassw0rd!xyz");
    p.$("vault-export").click();
    await sleep(100);
    const blob = p.downloads.find((x) => x.size !== undefined);
    const named = p.downloads.find((x) => x.name);
    assert(blob && named, "no download triggered");
    assert(/^securenest-backup-\d{4}-\d{2}-\d{2}\.json$/.test(named.name), named.name);
    backupText = Buffer.from(await blob.arrayBuffer()).toString("utf8");
    assert(!backupText.includes("S3cretPassw0rd") && !backupText.includes("ExampleSite") && !backupText.includes(MASTER));
    assert(JSON.parse(backupText).kdf.iterations >= 100000);
    p.w.close();
  });

  await test("export from the locked screen works", async () => {
    const p = await open();
    await setupVault(p, MASTER);
    p.$("vault-lock").click();
    await until(() => !p.$("vault-locked").hidden, "locked");
    p.$("export-locked").click();
    await sleep(100);
    assert(p.downloads.some((x) => x.size !== undefined), "no download");
    p.w.close();
  });

  await test("import into a fresh browser restores the entries", async () => {
    const p = await open();
    assert(!p.$("vault-import").hidden, "import section visible on setup screen");
    pickFile(p, backupText); p.$("import-master").value = MASTER; p.$("import-submit").click();
    await until(() => !p.$("vault-open").hidden, "vault opens after import");
    assert(p.$("vault-list").textContent.includes("ExampleSite"));
    assert(/imported \(1 account\)/.test(p.$("vault-status").textContent), p.$("vault-status").textContent);
    p.w.close();
  });

  await test("wrong password, bad file, oversize and missing input are rejected without changes", async () => {
    const p = await open();
    p.$("import-submit").click(); assert(/Choose a backup file/.test(p.$("import-message").textContent));
    pickFile(p, backupText); p.$("import-submit").click();
    assert(/master password/.test(p.$("import-message").textContent));
    p.$("import-master").value = "wrong-password-123"; p.$("import-submit").click();
    await until(() => /wrong|damaged|Could not/i.test(p.$("import-message").textContent), "wrong pw msg");
    pickFile(p, "{not json"); p.$("import-master").value = MASTER; p.$("import-submit").click();
    await until(() => p.$("import-message").classList.contains("error") && !/wrong/i.test(p.$("import-message").textContent), "bad file msg");
    pickFile(p, "{}", "big.json", 50 * 1024 * 1024); p.$("import-submit").click();
    assert(/too large/.test(p.$("import-message").textContent));
    assert.strictEqual(p.w.localStorage.length, 0, "storage must stay empty");
    assert(p.$("vault-open").hidden);
    p.w.close();
  });

  await test("importing over an existing vault asks first; cancel keeps it, confirm replaces it", async () => {
    const p = await open();
    await setupVault(p, "another-Master-pass-77");
    const before = stored(p);
    p.$("vault-lock").click();
    await until(() => !p.$("vault-locked").hidden, "locked");
    assert(!p.$("vault-import").hidden, "import visible when locked");
    p.w.__confirm = false;
    pickFile(p, backupText); p.$("import-master").value = MASTER; p.$("import-submit").click();
    await until(() => /cancelled/i.test(p.$("import-message").textContent), "cancel msg");
    assert.strictEqual(stored(p), before, "vault must be unchanged after cancel");
    p.w.__confirm = true;
    p.$("import-submit").click();
    await until(() => !p.$("vault-open").hidden, "opened after confirm");
    assert(p.$("vault-list").textContent.includes("ExampleSite"));
    assert.notStrictEqual(stored(p), before);
    p.w.close();
  });

  await test("hostile backup: javascript: URLs removed, malformed items skipped", async () => {
    const S = require("../script.js");
    const { session } = await S.createVault(MASTER);
    const saved = await session.encrypt({ v: 1, entries: [
      { id: "a", name: "Evil", url: "javascript:alert(1)", username: "u", password: "p", notes: "" },
      { id: "b", name: "Good", url: "https://example.com", username: "u", password: "p", notes: "" },
      { id: "c" }, null, "str", { name: 5, username: "u", password: "p" }
    ] });
    const p = await open();
    pickFile(p, S.exportEnvelopeText(saved));
    p.$("import-master").value = MASTER; p.$("import-submit").click();
    await until(() => !p.$("vault-open").hidden, "opened");
    const html = p.$("vault-list").innerHTML;
    assert(!/javascript:/i.test(html), "javascript: URL reached the page");
    assert(html.includes("Evil") && html.includes("Good"));
    assert(/4 damaged/.test(p.$("vault-status").textContent), p.$("vault-status").textContent);
    p.w.close();
  });

  console.log("\n" + passed + " UI import/export tests passed");
  process.exit(0);
})().catch((e) => { console.error("FAILED:", e); process.exit(1); });
