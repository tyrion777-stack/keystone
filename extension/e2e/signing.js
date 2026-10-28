// Loads extension/dist into a real Chrome and checks what a web page can get signed.
// Usage: npm run build, then
//   node e2e/signing.js <puppeteer-core dir> "$PWD/dist" "$PWD/node_modules"
// Needs Chrome and puppeteer-core (npm install puppeteer-core@23.11.1, outside this repo).
// Every signature is checked by keystone-core itself: the WebAssembly build in target/.
const puppeteer = require(process.argv[2]);
const dist = process.argv[3];
const nm = process.argv[4];
const fs = require('fs');
const http = require('http');
const path = require('path');

const results = [];
const check = (ok, what) => { results.push(`${ok ? 'PASS' : 'FAIL'} ${what}`); if (!ok) process.exitCode = 1; };

// keystone-core's checks, as the extension runs them (wasm/src/lib.rs).
async function loadCore() {
  const file = path.join(__dirname, '../../target/wasm32-unknown-unknown/wasm/keystone_wasm.wasm');
  const { instance } = await WebAssembly.instantiate(fs.readFileSync(file), {});
  const ex = instance.exports;
  return call => {
    const input = new TextEncoder().encode(JSON.stringify(call));
    const ptr = ex.ks_alloc(input.length);
    new Uint8Array(ex.memory.buffer, ptr, input.length).set(input);
    const packed = ex.ks_call(ptr, input.length);
    const out = [Number(packed >> 32n), Number(packed & 0xffffffffn)];
    const text = new TextDecoder().decode(new Uint8Array(ex.memory.buffer, out[0], out[1]));
    ex.ks_free(out[0], out[1]);
    return JSON.parse(text);
  };
}

(async () => {
  const core = await loadCore();
  const { ed25519 } = await import(`${nm}/@noble/curves/ed25519.js`);
  const { blake3 } = await import(`${nm}/@noble/hashes/blake3.js`);
  const { bytesToHex } = await import(`${nm}/@noble/hashes/utils.js`);
  const hex = n => bytesToHex(crypto.getRandomValues(new Uint8Array(n)));
  const signAs = (seed, content) => {
    const h = bytesToHex(blake3(new TextEncoder().encode(content)));
    return { author: bytesToHex(ed25519.getPublicKey(seed)), content, content_hash: h,
             signature: bytesToHex(ed25519.sign(new TextEncoder().encode(h), seed)) };
  };
  const now = () => Math.floor(Date.now() / 1000);
  const ORIGIN = 'http://localhost:8766';
  const serviceKey = crypto.getRandomValues(new Uint8Array(32));
  const otherKey = crypto.getRandomValues(new Uint8Array(32));
  const request = (over = {}, seed = serviceKey) => signAs(seed, JSON.stringify({
    kind: 'keystone.request', v: 1, service: 'Front desk', origin: ORIGIN, purpose: 'link',
    nonce: hex(16), issued_at: now() - 5, expires_at: now() + 120, ...over }));

  const server = http.createServer((_q, r) => { r.setHeader('content-type', 'text/html'); r.end('<!doctype html><title>some site</title>'); });
  await new Promise(r => server.listen(8766, '127.0.0.1', r));

  const browser = await puppeteer.launch({
    executablePath: '/usr/bin/google-chrome', headless: true, pipe: true, ignoreDefaultArgs: ['--disable-extensions'],
    args: ['--no-sandbox', '--enable-unsafe-extension-debugging'],
  });
  const cdp = await browser.target().createCDPSession();
  const { id } = await cdp.send('Extensions.loadUnpacked', { path: dist });

  // Make a key, as the popup does. This leaves the extension unlocked.
  const popup = await browser.newPage();
  await popup.goto(`chrome-extension://${id}/popup.html`);
  const setup = await popup.evaluate(() => chrome.runtime.sendMessage({ type: 'SETUP_GENERATE', password: 'correct horse' }));
  check(setup.ok, 'key created');
  const pubkey = setup.pubkeyHex;

  const page = await browser.newPage();
  await page.goto(`${ORIGIN}/`);
  await page.waitForFunction(() => window.keystone?.isInstalled);

  const windowsOpened = () => browser.targets().filter(t => t.url().includes('approval.html')).length;
  const nextWindow = async () => {
    const t = await browser.waitForTarget(t => t.url().includes('approval.html'), { timeout: 5000 });
    const w = await t.asPage();
    await w.waitForSelector('#content:not([hidden])');
    return w;
  };
  const shown = (w, sel) => w.$eval(sel, e => !e.hidden);
  const textOf = (w, sel) => w.$eval(sel, e => e.textContent);
  const tryCall = (fn, arg) => page.evaluate((fn, arg) => window.keystone[fn](arg).then(r => r, e => ({ error: e.message })), fn, arg);

  // 1. No way left to sign text the page chose.
  check(await page.evaluate(() => typeof window.keystone.sign) === 'undefined', 'bare sign() is gone');
  for (const [name, c] of [['approval JSON', '{"kind":"keystone.approval"}'], ['free text', 'I agree to pay'], ['uppercase hex', 'AB'.repeat(32)]]) {
    const r = await tryCall('signIn', c);
    check(r.error === 'Keystone signs sign-in challenges only', `signIn refuses ${name}`);
  }
  check(windowsOpened() === 0, 'no window for refused sign-ins');

  // 2. Sign-in, unlocked: names the real site; core accepts it here and nowhere else.
  const challenge = hex(32);
  const signing = tryCall('signIn', challenge);
  const w1 = await nextWindow();
  check(await textOf(w1, '#req-origin') === ORIGIN, 'sign-in window shows the real origin');
  check(!(await shown(w1, '#ap-pw-block')), 'unlocked: no password asked');
  await w1.click('#approve-btn');
  const signIn = await signing;
  const here = core({ op: 'verify_sign_in', signed: signIn, origin: ORIGIN, challenge });
  check(here.ok && here.person === pubkey, 'core accepts the sign-in on this site');
  check(!core({ op: 'verify_sign_in', signed: signIn, origin: 'https://bank.example.com', challenge }).ok, 'core refuses the same sign-in at another site');

  // 3. A request for another site is refused before any window.
  const elsewhere = await tryCall('approve', request({ origin: 'https://bank.example.com' }));
  check(elsewhere.error === 'This request is for https://bank.example.com, not this site', 'request for another site refused');
  const forged = { ...request(), content: request({ purpose: 'check-in' }).content };
  check((await tryCall('approve', forged)).error?.startsWith('Request not valid'), 'tampered request refused');
  check(windowsOpened() === 0, 'no window for refused requests');

  // 4. First link: verified, first time; the approval verifies at the service.
  const link = request();
  const approving = tryCall('approve', link);
  const w2 = await nextWindow();
  check(await textOf(w2, '#req-ask') === 'Link your Keystone to “Front desk”?', 'window says what is asked');
  check((await textOf(w2, '#req-note')).includes('First time'), 'window says first time');
  await w2.click('#approve-btn');
  const approval = await approving;
  const verified = core({ op: 'verify_approval', approval, issued: link, now: now() });
  check(verified.ok && verified.person === pubkey && verified.purpose === 'link', 'service accepts the approval');

  // 5. Same key again: remembered.
  const checkIn = request({ purpose: 'check-in' });
  const again = tryCall('approve', checkIn);
  const w3 = await nextWindow();
  check((await textOf(w3, '#req-note')).includes('same key'), 'second request: same key as before');
  await w3.click('#approve-btn');
  check(core({ op: 'verify_approval', approval: await again, issued: checkIn, now: now() }).ok, 'check-in approval accepted');

  // 6. A different key for the same site: blocked, nothing to approve.
  const impostor = tryCall('approve', request({ purpose: 'check-in' }, otherKey));
  const w4 = await nextWindow();
  check(await textOf(w4, '#title') === 'Blocked: this site’s key changed', 'changed key: blocked');
  check(!(await shown(w4, '#approve-btn')) && await shown(w4, '#forget-btn'), 'changed key: no approve button');
  await w4.click('#forget-btn');
  check((await impostor).error?.includes('forgotten'), 'forgetting the old key signs nothing');
  const fresh = tryCall('approve', request({}, otherKey));
  const w5 = await nextWindow();
  check((await textOf(w5, '#req-note')).includes('First time'), 'after forgetting: treated as new');
  await w5.click('#deny-btn');
  check((await fresh).error === 'User denied the request', 'deny reaches the page');

  // 7. Locked: the password is asked; a wrong one is refused, the right one signs.
  await popup.evaluate(() => chrome.runtime.sendMessage({ type: 'LOCK' }));
  const c2 = hex(32);
  const locked = tryCall('signIn', c2);
  const w6 = await nextWindow();
  check(await shown(w6, '#ap-pw-block'), 'locked: password asked');
  await w6.type('#ap-pw', 'wrong');
  await w6.click('#approve-btn');
  await w6.waitForFunction(() => document.getElementById('ap-error').textContent.includes('Wrong'));
  check(true, 'locked: wrong password refused');
  await w6.type('#ap-pw', 'correct horse');
  await w6.click('#approve-btn');
  check(core({ op: 'verify_sign_in', signed: await locked, origin: ORIGIN, challenge: c2 }).ok, 'locked sign-in verifies');

  console.log(results.join('\n'));
  await browser.close(); server.close();
})().catch(e => { console.log(results.join('\n')); console.error(e); process.exit(1); });
