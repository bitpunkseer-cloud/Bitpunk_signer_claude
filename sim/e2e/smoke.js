// Simulator end-to-end check (M9-0), run in CI after the simulator build:
//   node sim/e2e/smoke.js dist/simulator.html
// Drives the page like a user: loads a seed through the camera's text input,
// signs a PSBT and compares the signed bytes with the M8 output baseline,
// uses the microSD panel, the boot check and the simulated vault. Uses only layout-independent
// keys (Fn+Q opens the scanner from any menu; Enter/Esc/Down inside flows).
"use strict";
const { chromium } = require("playwright");
const fs = require("fs");
const path = require("path");

const page_ = process.argv[2];
if (!page_) throw new Error("usage: node smoke.js <simulator.html>");
const root = path.join(__dirname, "..", "..");
const psbtB64 = fs.readFileSync(path.join(__dirname, "fixtures", "abandon-standard.psbt.txt"), "utf8").trim();
const golden = fs.readFileSync(path.join(root, "crates", "bp-app", "golden", "m8-outputs.txt"), "utf8");
const signedHex = golden.split("\n").find(l => l.startsWith("psbt.signed = hex:")).slice("psbt.signed = hex:".length);
const ABANDON = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

const fail = msg => { console.error("FAIL: " + msg); process.exitCode = 1; };

(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1200, height: 1600 }, acceptDownloads: true });
  const errors = [];
  page.on("pageerror", e => errors.push(String(e)));
  // the page's web fonts are decoration: never wait on the network
  await page.route(/^https?:/, r => r.abort());
  await page.goto("file://" + path.resolve(page_), { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(2500); // splash
  const key = async k => { await page.keyboard.press(k); await page.waitForTimeout(120); };
  const scanner = async () => {
    for (let i = 0; i < 4; i++) await key("Escape");
    await page.click('button[aria-label="Fn"]');
    await page.click('button[aria-label^="q"]');
    await page.waitForTimeout(150);
  };
  const paste = async text => {
    if (await page.locator("#pasteBox").isHidden()) await page.click("#pasteBtn");
    await page.fill("#pasteText", text);
    await page.click("#pasteSend");
    await page.waitForTimeout(200);
  };

  // 1. load the test seed through the camera's text input
  // screen help (C11): `?` opens it, the next key only closes it
  for (let i = 0; i < 3; i++) await key("Escape");
  await key("?");
  await key("Escape");
  await scanner();
  await paste(ABANDON);
  await key("Enter"); // Load
  await key("Enter"); // seed ready -> options

  // 2. sign a PSBT: overview, outputs, fee, approve
  await scanner();
  await paste(psbtB64);
  for (let i = 0; i < 4; i++) await key("Enter");
  await key("ArrowDown");
  await key("Enter");
  await page.waitForTimeout(300);
  const signed = await page.inputValue("#signedText").catch(() => "");
  const gotHex = Buffer.from(signed, "base64").toString("hex");
  if (!signed) fail("no signed PSBT shown");
  else if (gotHex !== signedHex) fail("signed PSBT differs from the M8 baseline");
  else console.log("ok: signed PSBT matches the M8 baseline");

  // 3. microSD: copy a file, see it listed, download it back
  for (let i = 0; i < 4; i++) await key("Escape");
  const tmp = path.join(require("os").tmpdir(), "bp-e2e-tx.psbt");
  fs.writeFileSync(tmp, Buffer.from(psbtB64, "base64"));
  await page.setInputFiles("#sdFiles", tmp);
  await page.waitForTimeout(400);
  const list = await page.locator("#sdList").innerText();
  if (!list.includes("bp-e2e-tx.psbt")) fail("copied file not listed: " + list);
  const [dl] = await Promise.all([
    page.waitForEvent("download", { timeout: 5000 }),
    page.locator("#sdList button", { hasText: "Download" }).first().click(),
  ]).catch(() => [null]);
  if (!dl || dl.suggestedFilename() !== "bp-e2e-tx.psbt") fail("download did not offer the file");
  else console.log("ok: microSD copy, list and download");
  await page.click("#sdInsert");
  if (!(await page.locator("#sdState").innerText()).includes("out of the device")) fail("card removal not shown");
  await page.click("#sdInsert");

  // 4. boot check: a network chip locks the device, removing it unlocks
  await page.click("#commBtn");
  if ((await page.getAttribute("#commBtn", "aria-pressed")) !== "true") fail("boot check did not turn on");
  await page.click("#commBtn");
  if ((await page.getAttribute("#commBtn", "aria-pressed")) !== "false") fail("boot check did not turn off");
  else console.log("ok: boot check toggles");

  // 5. vault (M10): set a PIN, power off and on, unlock on the lock screen.
  // Menu rows are positional here: Settings is row 6 of the main menu and
  // Security the 13th row of Settings; Power is row 7.
  const vaultIs = async (want, ms) => {
    const end = Date.now() + ms;
    while (Date.now() < end) {
      if ((await page.textContent("#vaultState")) === want) return true;
      await page.waitForTimeout(100);
    }
    return false;
  };
  const typeText = async t => { for (const ch of t) await key(ch); };
  if (!(await vaultIs("No vault", 1000))) fail("vault state not shown");
  // the boot check wiped RAM: load the test seed again
  await scanner();
  await paste(ABANDON);
  await key("Enter");
  await key("Enter");
  for (let i = 0; i < 4; i++) await key("Escape");
  await key("7"); // Settings (M11: Backup & tools is 6)
  for (let i = 0; i < 12; i++) await key("ArrowDown");
  await key("Enter"); // Security
  await key("1"); // PIN
  await key("Enter"); // the rules
  for (let i = 0; i < 2; i++) {
    await typeText("abcd"); await key("Enter");
    await typeText("efgh"); await key("Enter");
  }
  if (!(await vaultIs("Vault open", 30000))) fail("setting a PIN did not open a vault");
  await key("Enter"); // the words were seen
  // store the loaded seed: Seeds & keys (3), Seed vault (the row after the
  // loaded seed and the four fixed rows), Store a loaded seed, the seed
  for (let i = 0; i < 4; i++) await key("Escape");
  await key("3"); await key("6"); await key("1"); await key("Enter");
  await page.waitForTimeout(300);
  for (let i = 0; i < 4; i++) await key("Escape");
  await key("8"); await key("1"); // Power off
  await key("Enter"); // power on
  await page.waitForTimeout(2500); // splash
  if (!(await vaultIs("Vault locked", 3000))) fail("no lock screen after power on");
  // tamper check before the PIN (M10-7): Tab, a code, the words, back
  await key("Tab"); await typeText("check1"); await key("Enter");
  await page.waitForTimeout(800); await key("Enter");
  if (!(await page.textContent("#fwHash")).startsWith("SHA-256 ")) fail("firmware hash not shown");
  await typeText("abcd"); await key("Enter");
  await page.waitForTimeout(500); // the two words
  await key("Enter");
  await typeText("efgh"); await key("Enter");
  if (!(await vaultIs("Vault open", 30000))) fail("the PIN did not unlock the vault");
  else console.log("ok: vault PIN set, lock screen after power on, unlocked");
  // the stored seed is back: the same PSBT signs to the same bytes
  await scanner();
  await paste(psbtB64);
  for (let i = 0; i < 4; i++) await key("Enter");
  await key("ArrowDown");
  await key("Enter");
  await page.waitForTimeout(300);
  const again = await page.inputValue("#signedText").catch(() => "");
  if (Buffer.from(again, "base64").toString("hex") !== signedHex) fail("the seed from the vault did not sign the same PSBT");
  else console.log("ok: seed stored in the vault, back after power on, signs the M8 baseline");
  // 6. a trick PIN (M10-6): "look blank" starts without the vault, uses no
  // attempt, and the vault's own PIN still opens it. Security row 2.
  for (let i = 0; i < 4; i++) await key("Escape");
  await key("7"); // Settings
  for (let i = 0; i < 12; i++) await key("ArrowDown");
  await key("Enter"); // Security
  await key("2"); await key("1"); await key("4"); // Trick PINs, Add, Look blank
  for (let i = 0; i < 2; i++) {
    await typeText("zzzz"); await key("Enter");
    await typeText("4444"); await key("Enter");
  }
  await page.waitForTimeout(500);
  for (let i = 0; i < 4; i++) await key("Escape");
  await key("8"); await key("1"); await key("Enter");
  await page.waitForTimeout(2500);
  await typeText("zzzz"); await key("Enter");
  await page.waitForTimeout(500); await key("Enter");
  await typeText("4444"); await key("Enter");
  const blank = await vaultIs("No vault", 30000);
  for (let i = 0; i < 4; i++) await key("Escape");
  await key("8"); await key("1"); await key("Enter");
  await page.waitForTimeout(2500);
  await typeText("abcd"); await key("Enter");
  await page.waitForTimeout(500); await key("Enter");
  await typeText("efgh"); await key("Enter");
  if (!blank) fail("the look-blank trick PIN did not start without the vault");
  else if (!(await vaultIs("Vault open", 30000))) fail("the vault's PIN did not open it after the trick");
  else console.log("ok: trick PIN looks blank; the vault's PIN still opens it");

  // feature checklist: every inventory item, ticks counted, both languages
  const items = await page.locator("#checkList input[type=checkbox]").count();
  if (items < 90) fail("checklist has only " + items + " items");
  await page.click("#checkList details summary");
  await page.locator("#checkList input[type=checkbox]").first().check();
  const counted = await page.textContent("#checkCount");
  if (!counted.startsWith("1 / " + items)) fail("checklist count: " + counted);
  await page.click("#checkLang");
  if ((await page.textContent("#checkTitle")) !== "기능 점검표") fail("checklist did not switch to Korean");
  else console.log("ok: checklist " + items + " items, ticks and Korean");

  if (errors.length) fail("page errors: " + errors.join(" | "));
  else console.log("ok: no page errors");
  await browser.close();
})().catch(e => { console.error(e); process.exit(1); });
