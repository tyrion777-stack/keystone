// Captures a real WebAuthn registration + assertion from Chrome's virtual authenticator.
// Usage: node capture_webauthn.js <path-to-puppeteer-core> > chrome_capture.json
// Needs Chrome and puppeteer-core (npm install puppeteer-core@23.11.1, outside this repo).
const puppeteer = require(process.argv[2]);
const http = require('http');

const PAGE = '<!doctype html><title>front desk</title>';
const server = http.createServer((_, res) => { res.setHeader('content-type', 'text/html'); res.end(PAGE); });

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
    const b64u = buf => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const regChallenge = new Uint8Array(32).map((_, i) => i + 1);
    const getChallenge = new Uint8Array(32).map((_, i) => i + 33);
    const cred = await navigator.credentials.create({ publicKey: {
      challenge: regChallenge, rp: { id: 'localhost', name: 'Front desk' },
      user: { id: new Uint8Array([1, 2, 3, 4]), name: 'visitor', displayName: 'Visitor' },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      authenticatorSelection: { userVerification: 'required' }, attestation: 'none' } });
    const r = cred.response;
    const asn = await navigator.credentials.get({ publicKey: {
      challenge: getChallenge, rpId: 'localhost', userVerification: 'required',
      allowCredentials: [{ type: 'public-key', id: cred.rawId }] } });
    const a = asn.response;
    return {
      origin: location.origin, rp_id: 'localhost',
      registration: {
        challenge: b64u(regChallenge),
        message: { public_key: b64u(r.getPublicKey()), public_key_algorithm: r.getPublicKeyAlgorithm(),
          authenticator_data: b64u(r.getAuthenticatorData()), client_data_json: b64u(r.clientDataJSON) } },
      assertion: {
        challenge: b64u(getChallenge),
        message: { authenticator_data: b64u(a.authenticatorData), client_data_json: b64u(a.clientDataJSON),
          signature: b64u(a.signature) } },
    };
  });
  console.log(JSON.stringify(out, null, 2));
  await browser.close(); server.close();
})().catch(e => { console.error(e); process.exit(1); });
