// Simulator end-to-end check (M9-0), run in CI after the simulator build:
//   node sim/e2e/smoke.js dist/simulator.html
// Drives the page like a user: loads a seed through the camera's text input,
// signs a PSBT and compares the signed bytes with the M8 output baseline,
// uses the microSD panel and the boot check. Uses only layout-independent
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
