// Checks keystone-passkey.js's onPhone option in Chrome with virtual authenticators: with it, the
// built-in authenticator is never used and a roaming one (phone, security key) is; without it,
// nothing changes. Usage: node check_passkey_on_phone.js <puppeteer-core dir> ../../core/js/keystone-passkey.js
const puppeteer = require(process.argv[2]);
const fs = require('fs'), http = require('http');
const helper = fs.readFileSync(process.argv[3]);
const results = []; const check = (ok, w) => { results.push(`${ok ? 'PASS' : 'FAIL'} ${w}`); if (!ok) process.exitCode = 1; };
(async () => {
  const server = http.createServer((q, r) => { if (q.url === '/h.js') { r.setHeader('content-type', 'text/javascript'); return r.end(helper); } r.setHeader('content-type', 'text/html'); r.end('<!doctype html><title>desk</title>'); });
  await new Promise(r => server.listen(8769, '127.0.0.1', r));
  const browser = await puppeteer.launch({ executablePath: '/usr/bin/google-chrome', headless: true, args: ['--no-sandbox'] });
  const run = async (transport, fn) => {
    const page = await browser.newPage();
    const cdp = await page.createCDPSession();
    await cdp.send('WebAuthn.enable');
    await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport, hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
    await page.goto('http://localhost:8769/');
    const out = await page.evaluate(fn);
    await page.close();
    return out;
  };
  const body = (onPhone) => `(async () => {
    const k = await import('/h.js');
    const seen = [];
    const create = navigator.credentials.create.bind(navigator.credentials);
    const get = navigator.credentials.get.bind(navigator.credentials);
    navigator.credentials.create = o => { seen.push(o.publicKey); return create(o); };
    navigator.credentials.get = o => { seen.push(o.publicKey); return get(o); };
    const ch = btoa(String.fromCharCode(...new Uint8Array(32).fill(7))).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'');
    const race = p => Promise.race([p.then(r => ({ ok: r }), e => ({ err: e.code || e.name })), new Promise(r => setTimeout(() => r({ waiting: true }), 3000))]);
    const link = await race(k.linkPasskey({ challenge: ch, rpId: 'localhost', rpName: 'Desk', userName: 'visitor-1', onPhone: ${onPhone} }));
    const signIn = link.ok ? await race(k.signInWithPasskey({ challenge: ch, rpId: 'localhost', onPhone: ${onPhone} })) : null;
    const o = seen.map(p => ({ hints: p.hints ?? null, attach: p.authenticatorSelection?.authenticatorAttachment ?? null, timeout: p.timeout }));
    return { link: link.ok ? 'made' : link, signIn: signIn && (signIn.ok ? 'signed' : signIn), options: o };
  })()`;
  const a = await run('internal', body(true));
  check(a.link.waiting === true || a.link.err, `onPhone: the built-in authenticator is not used (${JSON.stringify(a.link)})`);
  check(a.options[0].attach === 'cross-platform' && a.options[0].hints?.[0] === 'hybrid' && a.options[0].timeout === 180000, 'onPhone: create asks for a phone, 3 minutes');
  const b = await run('usb', body(true));
  check(b.link === 'made' && b.signIn === 'signed', `onPhone: works with a roaming authenticator (${JSON.stringify(b)})`);
  check(b.options[1].hints?.[0] === 'hybrid' && b.options[1].timeout === 180000 && b.options[1].attach === null, 'onPhone: sign-in asks for a phone, 3 minutes');
  const c = await run('internal', body(false));
  check(c.link === 'made' && c.signIn === 'signed', 'default: built-in authenticator still works');
  check(c.options.every(o => o.hints === null && o.attach === null && o.timeout === 60000), 'default: options unchanged, 1 minute');
  console.log(results.join('\n'));
  await browser.close(); server.close();
})().catch(e => { console.log(results.join('\n')); console.error(e); process.exit(1); });
