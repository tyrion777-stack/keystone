# Keystone Extension — Runbook

## Right now (before Store submission)

1. Build it:
   ```
   cd keystone-extension
   npm run build
   ```

2. Load it in Chrome:
   - Go to `chrome://extensions`
   - Turn on **Developer mode** (top-right toggle)
   - Click **Load unpacked** → select the `dist/` folder

3. The Keystone icon appears in your toolbar. Click it, set up your key.

4. Test the signing flow on a page that calls `window.keystone.sign()`.
   To test manually in the browser console:
   ```js
   const pubkey = await window.keystone.getPublicKey()
   const result = await window.keystone.sign("hello keystone")
   console.log(result) // { signature: "...", pubkey: "..." }
   ```

---

## After making code changes

```
npm run build
```

Then in `chrome://extensions` → click the **refresh icon** on the Keystone card.

The extension reloads immediately. No need to re-add it.

---

## Before publishing to the Chrome Web Store

Things you need:

- [ ] Google Developer account — one-time $5 fee at
      `chrome.google.com/webstore/devconsole`
- [ ] Privacy policy hosted at a public URL (one page, see below)
- [ ] Screenshots — at least one 1280×800 or 640×400 PNG showing the popup
- [ ] A short description (132 chars) and a long description for the listing

**Privacy policy** — host a page at your domain that says:

> Keystone stores your encrypted private key locally on your device using
> your browser's built-in storage. No key material, personal data, or
> usage information is ever transmitted to any server. The extension
> operates entirely on-device.

That is literally the entire policy. It's true and it's all the Store needs.

---

## Publishing for the first time

1. Bump version in both files:
   - `package.json` → `"version": "0.1.0"`
   - `vite.config.ts` → `version: '0.1.0'` inside `defineManifest`

2. Build:
   ```
   npm run build
   ```

3. Zip the dist folder:
   ```
   cd dist && zip -r ../keystone-extension-0.1.0.zip . && cd ..
   ```

4. Go to the Web Store Developer Dashboard → **New item** → upload the zip.

5. Fill in the listing: description, screenshots, privacy policy URL, category
   (Productivity).

6. Submit. Initial review takes a few days to two weeks.

---

## Publishing an update

1. Bump version in `package.json` and `vite.config.ts` — **required**, the
   Store rejects uploads with the same version number.

2. Build and zip:
   ```
   npm run build
   cd dist && zip -r ../keystone-extension-X.X.X.zip . && cd ..
   ```

3. Developer Dashboard → your listing → **Upload new package** → submit.

Update reviews are usually same-day.

---

## If something breaks in the extension

- Open `chrome://extensions` → find Keystone → click **Service Worker**
  to open the background script's DevTools console. Errors from
  `background.ts` appear here.

- For popup errors: right-click the extension icon → **Inspect popup**.

- For content script / inject errors: open DevTools on the page itself
  (F12) → Console. Errors from `inject.ts` and `content.ts` appear here.

---

## File map (what lives where)

```
src/background.ts   Service worker. Holds the key in memory, handles all
                    signing logic, opens the approval window.

src/inject.ts       Runs in the page's JS context. Exposes window.keystone.
                    Never touches key material.

src/content.ts      Bridge between the page and the service worker.
                    Passes messages, nothing else.

src/crypto.ts       All cryptographic operations: key encryption/decryption
                    (PBKDF2 + AES-GCM), Ed25519 signing, Blake3 hashing.

src/popup.ts        The toolbar popup: setup, unlock, lock, show pubkey.

src/approval.ts     The window that appears when a site requests signing.
                    Shows the origin and challenge, takes the password.
```

---

## Key facts about the security model

- The private key never leaves `background.ts`. `inject.ts` and `content.ts`
  only see messages, never key material.
- At rest: key is PBKDF2-SHA256 (300k iterations) + AES-256-GCM encrypted
  in `chrome.storage.local`.
- In session: decrypted seed lives in `chrome.storage.session` for 30
  minutes after unlock, then requires password again.
- `chrome.storage.session` is cleared automatically when the browser closes.
- The approval window always shows which site is asking before any signing
  happens. The user can deny any request.
