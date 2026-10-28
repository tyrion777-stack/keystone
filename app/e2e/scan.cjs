// Runs the built app (app/build) in Chrome and checks what a scanned link can get signed.
// Usage: npm run build, then
//   node e2e/scan.cjs <puppeteer-core dir> "$PWD/build" "$PWD/node_modules"
// Needs Chrome and puppeteer-core (npm install puppeteer-core@23.11.1, outside this repo); the
// relay below uses the `ws` package puppeteer-core brings. Every answer the phone sends is
// checked by keystone-core itself: the WebAssembly build in target/.
const puppeteer = require(process.argv[2]);
const { WebSocketServer } = require(require.resolve('ws', { paths: [process.argv[2]] }));
const build = process.argv[3];
const nm = process.argv[4];
const fs = require('fs');
const http = require('http');
const path = require('path');

const results = [];
const check = (ok, what) => { results.push(`${ok ? 'PASS' : 'FAIL'} ${what}`); if (!ok) process.exitCode = 1; };

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
  const { bytesToHex, hexToBytes } = await import(`${nm}/@noble/hashes/utils.js`);
  const hex = n => bytesToHex(crypto.getRandomValues(new Uint8Array(n)));
  const b3 = s => bytesToHex(blake3(new TextEncoder().encode(s)));
  const signAs = (seed, content) => ({ author: bytesToHex(ed25519.getPublicKey(seed)), content, content_hash: b3(content),
    signature: bytesToHex(ed25519.sign(new TextEncoder().encode(b3(content)), seed)) });
  const now = () => Math.floor(Date.now() / 1000);
  const ORIGIN = 'https://desk.example.com';
  const serviceKey = crypto.getRandomValues(new Uint8Array(32));
  const otherKey = crypto.getRandomValues(new Uint8Array(32));
  const request = (over = {}, seed = serviceKey) => signAs(seed, JSON.stringify({
    kind: 'keystone.request', v: 1, service: 'Front desk', origin: ORIGIN, purpose: 'link',
    nonce: hex(16), issued_at: now() - 5, expires_at: now() + 120, ...over }));
  const b64u = s => Buffer.from(s).toString('base64url');

  // The app, served as the static build with its SPA fallback.
  const server = http.createServer((q, r) => {
    const file = path.join(build, decodeURIComponent(new URL(q.url, 'http://x').pathname));
    const real = file.startsWith(build) && fs.existsSync(file) && fs.statSync(file).isFile() ? file : path.join(build, 'index.html');
    const type = { '.js': 'text/javascript', '.css': 'text/css', '.html': 'text/html' }[path.extname(real)] ?? 'application/octet-stream';
    r.setHeader('content-type', type);
    r.end(fs.readFileSync(real));
  });
  await new Promise(r => server.listen(8767, '127.0.0.1', r));

  // A relay that keeps the last message sent on each channel.
  const relayed = new Map();
  const relay = new WebSocketServer({ port: 8768, host: '127.0.0.1' });
  relay.on('connection', (ws, req) => ws.on('message', m => { relayed.set(req.url.slice(1), JSON.parse(m)); ws.close(); }));
  const RELAY = 'ws://localhost:8768';
  const waitFor = async channel => {
    for (let i = 0; i < 100 && !relayed.has(channel); i++) await new Promise(r => setTimeout(r, 50));
    return relayed.get(channel);
  };

  const browser = await puppeteer.launch({ executablePath: '/usr/bin/google-chrome', headless: true, args: ['--no-sandbox'] });
  const page = await browser.newPage();
  await page.goto('http://localhost:8767/');

  // Make a key through the setup screen; that leaves the session unlocked.
  await page.waitForFunction(() => location.pathname === '/setup');
  await page.evaluate(() => [...document.querySelectorAll('button')].find(b => b.textContent.includes('Generate')).click());
  await page.waitForSelector('input[type=password]');
  const pw = await page.$$('input[type=password]');
  await pw[0].type('correct horse battery');
  await pw[1].type('correct horse battery');
  await page.evaluate(() => [...document.querySelectorAll('button')].find(b => /generate|create/i.test(b.textContent) && !b.classList.contains('outline')).click());
  await page.waitForFunction(() => location.pathname === '/home', { timeout: 30000 });
  const pubkey = await page.evaluate(() => localStorage.getItem('ks_pubkey_hex'));
  check(/^[0-9a-f]{64}$/.test(pubkey), 'identity created');

  // Open a scan link in the running app (as a tapped keystone://sign link does).
  const open = async params => {
    await page.evaluate(q => {
      const a = document.createElement('a');
      a.href = '/scan?' + q;
      document.body.appendChild(a);
      a.click();
    }, new URLSearchParams(params).toString());
    await page.waitForFunction(() => location.pathname === '/scan');
    await page.waitForFunction(() => document.querySelector('.card, .error'));
  };
  const text = () => page.evaluate(() => document.querySelector('.page').innerText);
  const click = label => page.evaluate(l => [...document.querySelectorAll('button')].find(b => b.textContent.trim() === l)?.click(), label);
  const hasButton = label => page.evaluate(l => [...document.querySelectorAll('button')].some(b => b.textContent.trim() === l), label);
  const home = async () => { await page.evaluate(() => history.back()); await page.waitForFunction(() => location.pathname !== '/scan'); };

  // 1. First link: verified, first time; the approval reaches the relay and the service accepts it.
  const link = request();
  await open({ request: b64u(JSON.stringify(link)), relay: RELAY, channel: 'channel-0001' });
  let t = await text();
  check(t.includes('LINK YOUR KEYSTONE TO') || t.includes('Link your Keystone to'), 'screen says what is asked');
  check(t.includes('“Front desk”') && t.includes(ORIGIN), 'screen shows the service and its origin');
  check(t.includes('First time Keystone sees it'), 'screen says first time');
  await click('Approve');
  const sent = await waitFor('channel-0001');
  check(sent?.type === 'ks_approval', 'approval sent over the relay');
  const ok = core({ op: 'verify_approval', approval: sent.approval, issued: link, now: now() });
  check(ok.ok && ok.person === pubkey && ok.purpose === 'link', 'service accepts the approval');
  await home();

  // 2. Same key again: remembered.
  const checkIn = request({ purpose: 'check-in' });
  await open({ request: b64u(JSON.stringify(checkIn)), relay: RELAY, channel: 'channel-0002' });
  check((await text()).includes('same key'), 'second request: same key as before');
  await click('Approve');
  check(core({ op: 'verify_approval', approval: (await waitFor('channel-0002')).approval, issued: checkIn, now: now() }).ok, 'check-in approval accepted');
  await home();

  // 3. Another key for the same origin: blocked, nothing to approve, nothing sent.
  await open({ request: b64u(JSON.stringify(request({ purpose: 'check-in' }, otherKey))), relay: RELAY, channel: 'channel-0003' });
  t = await text();
  check(t.toLowerCase().includes('blocked: key changed'), 'changed key: blocked');
  check(!(await hasButton('Approve')), 'changed key: no approve button');
  await click('Close');
  await new Promise(r => setTimeout(r, 300));
  check(!relayed.has('channel-0003'), 'changed key: nothing sent');
  await home();

  // 4. Expired and tampered requests are refused.
  await open({ request: b64u(JSON.stringify(request({ issued_at: now() - 900, expires_at: now() - 400 }))), relay: RELAY, channel: 'channel-0004' });
  check((await text()).includes('Request not valid'), 'expired request refused');
  await home();
  const tampered = { ...request(), content: request({ purpose: 'sign', payload: 'I owe you' }).content };
  await open({ request: b64u(JSON.stringify(tampered)), relay: RELAY, channel: 'channel-0005' });
  check((await text()).includes('Request not valid'), 'tampered request refused');
  await home();

  // 5. An old-style link carrying an approval instead of a challenge: refused.
  const forged = JSON.stringify({ kind: 'keystone.approval', v: 1, request: 'ab'.repeat(32), service_key: 'cd'.repeat(32), purpose: 'link' });
  await open({ challenge: forged, origin: 'https://bank.example.com', relay: RELAY, requestId: 'channel-0006' });
  check((await text()).includes('Keystone signs sign-in challenges only'), 'old link with an approval inside refused');
  await home();

  // 6. An old-style sign-in code still works, labelled unproven, signing only the challenge.
  const challenge = hex(32);
  await open({ challenge, origin: ORIGIN, relay: RELAY, requestId: 'channel-0007' });
  check((await text()).includes("doesn't prove who made it"), 'old code: origin labelled unproven');
  await click('Approve');
  const legacy = await waitFor('channel-0007');
  check(legacy?.pubkey === pubkey && ed25519.verify(hexToBytes(legacy.signature), new TextEncoder().encode(b3(challenge)), hexToBytes(pubkey)),
    'old code: signature over the challenge verifies');

  console.log(results.join('\n'));
  await browser.close(); server.close(); relay.close();
})().catch(e => { console.log(results.join('\n')); console.error(e); process.exit(1); });
