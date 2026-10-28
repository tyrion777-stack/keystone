// Loads extension/dist into a real Chrome and checks what a web page can get signed.
// Usage: npm run build, then
//   node e2e/signing.js <puppeteer-core dir> "$PWD/dist" "$PWD/node_modules"
// Needs Chrome and puppeteer-core (npm install puppeteer-core@23.11.1, outside this repo).
const puppeteer = require(process.argv[2]);
const dist = process.argv[3];
const nm = process.argv[4];
const http = require('http');

const results = [];
const check = (ok, what) => { results.push(`${ok ? 'PASS' : 'FAIL'} ${what}`); if (!ok) process.exitCode = 1; };

(async () => {
  const { ed25519 } = await import(`${nm}/@noble/curves/ed25519.js`);
  const { blake3 } = await import(`${nm}/@noble/hashes/blake3.js`);
  const { bytesToHex, hexToBytes } = await import(`${nm}/@noble/hashes/utils.js`);

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
  await page.goto('http://localhost:8766/');
  await page.waitForFunction(() => window.keystone?.isInstalled);

  const windowsOpened = () => browser.targets().filter(t => t.url().includes('approval.html')).length;

  // 1. Structured content (an approval, a follow) is refused outright, with no window.
  const approval = JSON.stringify({ kind: 'keystone.approval', v: 1, request: 'ab'.repeat(32), service: 'ed'.repeat(32), purpose: 'sign' });
  for (const [name, content] of [['approval JSON', approval], ['follow JSON', '{"kind":"keystone.follow"}'], ['free text', 'I agree to pay'], ['uppercase hex', 'AB'.repeat(32)]]) {
    const r = await page.evaluate(c => window.keystone.sign(c).then(() => 'signed', e => e.message), content);
    check(r === 'Keystone signs sign-in challenges only', `page cannot get ${name} signed (${r})`);
  }
  check(windowsOpened() === 0, 'no approval window for refused content');

  // 2. A challenge, while unlocked: a window opens and waits. Nothing is signed silently.
  const challenge = bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
  const signing = page.evaluate(c => window.keystone.sign(c), challenge);
  const target = await browser.waitForTarget(t => t.url().includes('approval.html'), { timeout: 5000 });
  const ap = await target.asPage();
  await ap.waitForSelector('#content:not([hidden])');
  check(await ap.$eval('#req-origin', e => e.textContent) === 'http://localhost:8766', 'window shows the real origin');
  check(await ap.$eval('#ap-pw-block', e => e.hidden), 'unlocked: no password asked');
  await ap.click('#approve-btn');
  const signed = await signing;
  const msg = new TextEncoder().encode(bytesToHex(blake3(new TextEncoder().encode(challenge))));
  check(signed.pubkey === pubkey && ed25519.verify(hexToBytes(signed.signature), msg, hexToBytes(pubkey)), 'unlocked approve: signature verifies');

  // 3. Locked: the window asks for the password; a wrong one is refused, the right one signs.
  await popup.evaluate(() => chrome.runtime.sendMessage({ type: 'LOCK' }));
  const c2 = bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
  const signing2 = page.evaluate(c => window.keystone.sign(c), c2);
  const t2 = await browser.waitForTarget(t => t.url().includes('approval.html'), { timeout: 5000 });
  const ap2 = await t2.asPage();
  await ap2.waitForSelector('#content:not([hidden])');
  check(!(await ap2.$eval('#ap-pw-block', e => e.hidden)), 'locked: password asked');
  await ap2.type('#ap-pw', 'wrong');
  await ap2.click('#approve-btn');
  await ap2.waitForFunction(() => document.getElementById('ap-error').textContent.includes('Wrong'));
  check(true, 'locked: wrong password refused');
  await ap2.type('#ap-pw', 'correct horse');
  await ap2.click('#approve-btn');
  const s2 = await signing2;
  const m2 = new TextEncoder().encode(bytesToHex(blake3(new TextEncoder().encode(c2))));
  check(ed25519.verify(hexToBytes(s2.signature), m2, hexToBytes(pubkey)), 'locked approve: signature verifies');

  // 4. Deny returns an error to the page.
  const c3 = bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
  const signing3 = page.evaluate(c => window.keystone.sign(c).then(() => 'signed', e => e.message), c3);
  const t3 = await browser.waitForTarget(t => t.url().includes('approval.html'), { timeout: 5000 });
  const ap3 = await t3.asPage();
  await ap3.waitForSelector('#content:not([hidden])');
  await ap3.click('#deny-btn');
  check(await signing3 === 'User denied the request', 'deny reaches the page');

  console.log(results.join('\n'));
  await browser.close(); server.close();
})().catch(e => { console.log(results.join('\n')); console.error(e); process.exit(1); });
