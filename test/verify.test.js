// Run: node test/verify.test.js
const assert = require("node:assert/strict");
const { verifyAgainstKeySet, decodeTextures } = require("../verify.js");
const keys = require("../keys.json");
const ex = require("./ex.json");

(async () => {
  const ok = await verifyAgainstKeySet(ex.value, ex.signature, keys);
  console.log(JSON.stringify(ok));
  assert.ok(ok.valid, "example should verify");
  assert.ok(ok.matches.some((m) => m.group === "profilePropertyKeys"));

  // Whitespace-wrapped input is tolerated.
  const wrapped = ex.signature.replace(/(.{64})/g, "$1\n");
  assert.ok((await verifyAgainstKeySet(ex.value, wrapped, keys)).valid);

  // Any change to the payload must fail.
  const p = decodeTextures(ex.value);
  p.profileName = "Notch";
  const forged = Buffer.from(JSON.stringify(p)).toString("base64");
  assert.ok(!(await verifyAgainstKeySet(forged, ex.signature, keys)).valid);

  // Corrupted signature must fail (or be rejected), never pass.
  const bad = ex.signature.slice(0, 10) + (ex.signature[10] === "A" ? "B" : "A") + ex.signature.slice(11);
  assert.ok(!(await verifyAgainstKeySet(ex.value, bad, keys)).valid);
  console.log("all passed");
})();
