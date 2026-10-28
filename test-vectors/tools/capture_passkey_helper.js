// Runs js/keystone-passkey.js in Chrome against a virtual authenticator and prints its output
// in the capture format gen_webauthn.py reads, so the Rust tests prove the helper's output verifies.
// Usage: node capture_passkey_helper.js <path-to-puppeteer-core> > helper_capture.json
// Needs Chrome and puppeteer-core (npm install puppeteer-core@23.11.1, outside this repo).
const puppeteer = require(process.argv[2]);
const fs = require('fs');
const http = require('http');
const path = require('path');

const helper = fs.readFileSync(path.join(__dirname, '../../js/keystone-passkey.js'));
const server = http.createServer((req, res) => {
  if (req.url === '/keystone-passkey.js') {
    res.setHeader('content-type', 'text/javascript');
    return res.end(helper);
  }
  res.setHeader('content-type', 'text/html');
  res.end('<!doctype html><title>front desk</title>');
});

(async () => {
  await new Promise(r => server.listen(8765, '127.0.0.1', r));
  const browser = await puppeteer.launch({ executablePath: '/usr/bin/google-chrome', headless: true, args: ['--no-sandbox'] });
  const page = await browser.newPage();
  const cdp = await page.createCDPSession();
  await cdp.send('WebAuthn.enable');
  await cdp.send('WebAuthn.addVirtualAuthenticator', { options: {
    protocol: 'ctap2', transport: 'internal', hasResidentKey: true,
    hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
  await page.goto('http://localhost:8765/');

  const out = await page.evaluate(async () => {
    const k = await import('/keystone-passkey.js');
    const b64u = bytes => btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const ch = start => b64u(new Uint8Array(32).map((_, i) => i + start));
    const check = (ok, what) => { if (!ok) throw new Error('helper check failed: ' + what); };

    check(k.passkeysSupported(), 'passkeysSupported');
    let padded;
    try { await k.signInWithPasskey({ challenge: 'AA==', rpId: 'localhost' }); } catch (e) { padded = e; }
    check(padded && padded.name === 'PasskeyError' && padded.code === 'failed', 'padded challenge rejected');

    const link = await k.linkPasskey({ challenge: ch(101), rpId: 'localhost', rpName: 'Front desk', userName: 'visitor-0001' });
    const byPick = await k.signInWithPasskey({ challenge: ch(151), rpId: 'localhost' });
    const byId = await k.signInWithPasskey({ challenge: ch(201), rpId: 'localhost', credentialIds: [link.credentialId] });
    check(byPick.credentialId === link.credentialId && byId.credentialId === link.credentialId, 'credential id round-trips');
    check(byPick.userId === link.userId, 'discoverable sign-in returns the user id');

    return {
      origin: location.origin, rp_id: 'localhost',
      registration: { challenge: ch(101), message: link.registration },
      assertions: [
        { name: 'discoverable', challenge: ch(151), message: byPick.assertion },
        { name: 'by_id', challenge: ch(201), message: byId.assertion },
      ],
    };
  });
  console.log(JSON.stringify(out, null, 2));
  await browser.close(); server.close();
})().catch(e => { console.error(e); process.exit(1); });
