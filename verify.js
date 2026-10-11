// Minecraft texture-property signature verification (WebCrypto, no dependencies).
//
// Mojang signs the *base64 string* of the "textures" property value (its ASCII
// bytes, exactly as sent) with RSA-4096, PKCS#1 v1.5 padding and SHA-1
// ("SHA1withRSA"). The signature is itself delivered as base64.
(function (root) {
  "use strict";

  const subtle = () => (root.crypto || require("node:crypto").webcrypto).subtle;

  function stripWs(s) {
    return String(s).replace(/\s+/g, "");
  }

  // Accepts standard and URL-safe base64, with or without padding.
  function b64ToBytes(b64) {
    let s = stripWs(b64).replace(/-/g, "+").replace(/_/g, "/");
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(s)) throw new Error("not valid base64");
    while (s.length % 4) s += "=";
    const bin = atob(s);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function bytesToHex(bytes) {
    return Array.from(new Uint8Array(bytes), (b) => b.toString(16).padStart(2, "0")).join("");
  }

  async function digestHex(alg, bytes) {
    return bytesToHex(await subtle().digest(alg, bytes));
  }

  // Decode the textures value into its JSON payload (throws on garbage).
  function decodeTextures(valueB64) {
    const bytes = b64ToBytes(valueB64);
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  }

  // Verify one signature against one SPKI/DER public key (base64).
  async function verifyWithKey(valueB64, signatureB64, publicKeyB64) {
    const key = await subtle().importKey(
      "spki",
      b64ToBytes(publicKeyB64),
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-1" },
      false,
      ["verify"]
    );
    const data = new TextEncoder().encode(stripWs(valueB64));
    return subtle().verify("RSASSA-PKCS1-v1_5", key, b64ToBytes(signatureB64), data);
  }

  // Try every key in every group of the /publickeys response.
  // Returns { valid, matches: [{group, index, fingerprint}], tried }.
  async function verifyAgainstKeySet(valueB64, signatureB64, keySet) {
    const matches = [];
    let tried = 0;
    for (const [group, list] of Object.entries(keySet)) {
      if (!Array.isArray(list)) continue;
      for (let index = 0; index < list.length; index++) {
        const pk = list[index] && list[index].publicKey;
        if (!pk) continue;
        tried++;
        if (await verifyWithKey(valueB64, signatureB64, pk)) {
          matches.push({
            group,
            index,
            fingerprint: await digestHex("SHA-256", b64ToBytes(pk)),
          });
        }
      }
    }
    return { valid: matches.length > 0, matches, tried };
  }

  const api = { stripWs, b64ToBytes, bytesToHex, digestHex, decodeTextures, verifyWithKey, verifyAgainstKeySet };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.MCSig = api;
})(typeof globalThis !== "undefined" ? globalThis : this);
