# MCSignature

In-browser verification of Minecraft `textures` property signatures against Mojang's
[public keys](https://api.minecraftservices.com/publickeys).

Live at <https://kolya5544.github.io/MCSignature>.

Paste the base64 `value` and its `signature` and the page checks them (RSA-4096, PKCS#1 v1.5, SHA-1, over the
ASCII bytes of the base64 `value`) using WebCrypto. Nothing leaves your browser.

- `index.html`: the UI (no build step, no dependencies)
- `verify.js`: the verification logic, also usable from Node
- `keys.json`: snapshot of `/publickeys`, refreshed daily by `.github/workflows/update-keys.yml`

`api.minecraftservices.com/publickeys` sends no CORS headers, so browsers cannot fetch it from another origin.
The page tries the live endpoint, falls back to `keys.json`, and lets you paste a fresh response.

Test: `node test/verify.test.js`

## Deploy

Repo settings → Pages → Deploy from branch → `master` / root.
