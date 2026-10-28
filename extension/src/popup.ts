import QRCode from 'qrcode';
import { parsePhoneReply } from './pairing';

type View = 'setup' | 'backup' | 'locked' | 'main' | 'device';

function show(view: View) {
  for (const v of ['setup', 'backup', 'locked', 'main', 'device'] as const) {
    (document.getElementById(`v-${v}`) as HTMLElement).hidden = v !== view;
  }
}

function setErr(id: string, msg: string) {
  (document.getElementById(id) as HTMLElement).textContent = msg;
}
function clearErr(id: string) {
  (document.getElementById(id) as HTMLElement).textContent = '';
}
function el<T extends HTMLElement>(id: string): T {
  return document.getElementById(id) as T;
}

async function send(msg: object): Promise<Record<string, unknown>> {
  return chrome.runtime.sendMessage(msg) as Promise<Record<string, unknown>>;
}

async function init() {
  const { hasKey } = await send({ type: 'CHECK_SETUP' });
  if (!hasKey) { show('setup'); return; }

  const { locked } = await send({ type: 'GET_SESSION_STATUS' });
  if (locked) {
    show('locked');
  } else {
    const { pubkey } = await send({ type: 'GET_PUBKEY' });
    el('m-pubkey').textContent = pubkey as string;
    show('main');
  }
}

// --- Setup ---
el('s-submit').addEventListener('click', async () => {
  clearErr('s-error');
  const privkeyHex = el<HTMLInputElement>('s-privkey').value.trim();
  const pw  = el<HTMLInputElement>('s-pw').value;
  const pw2 = el<HTMLInputElement>('s-pw2').value;

  if (!pw)        { setErr('s-error', 'Password is required'); return; }
  if (pw !== pw2) { setErr('s-error', 'Passwords do not match'); return; }

  if (privkeyHex && privkeyHex.length !== 64) {
    setErr('s-error', 'Private key must be 64 hex characters (32 bytes)');
    return;
  }

  const result = privkeyHex
    ? await send({ type: 'SETUP_IMPORT', privkeyHex, password: pw })
    : await send({ type: 'SETUP_GENERATE', password: pw });

  if (!result['ok']) { setErr('s-error', result['error'] as string); return; }

  if (result['privkeyHex']) {
    // Newly generated — show backup prompt
    el('backup-key').textContent = result['privkeyHex'] as string;
    show('backup');
  } else {
    el('m-pubkey').textContent = result['pubkeyHex'] as string;
    show('main');
  }
});

el('backup-done').addEventListener('click', async () => {
  const { pubkey } = await send({ type: 'GET_PUBKEY' });
  el('m-pubkey').textContent = pubkey as string;
  show('main');
});

// --- Unlock ---
el('l-submit').addEventListener('click', async () => {
  clearErr('l-error');
  const pw = el<HTMLInputElement>('l-pw').value;
  if (!pw) { setErr('l-error', 'Password required'); return; }
  const result = await send({ type: 'UNLOCK', password: pw });
  if (!result['ok']) { setErr('l-error', (result['error'] as string) || 'Wrong password'); return; }
  el('m-pubkey').textContent = result['pubkeyHex'] as string;
  show('main');
});

el<HTMLInputElement>('l-pw').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') el('l-submit').click();
});

// --- Main ---
el('m-lock').addEventListener('click', async () => {
  await send({ type: 'LOCK' });
  el<HTMLInputElement>('l-pw').value = '';
  show('locked');
});

el('m-pubkey').addEventListener('click', () => {
  const text = el('m-pubkey').textContent ?? '';
  navigator.clipboard.writeText(text).catch(() => {/* non-fatal */});
});

// --- Add Device ---

let deviceWs: WebSocket | null = null;

// The site in the active tab, read when the popup opens (activeTab lets us see it then). It is
// read ahead so the click below can ask for access straight away: Chrome only shows the
// permission prompt while the click is still being handled.
let tabOrigin: string | null = null;
chrome.tabs.query({ active: true, currentWindow: true }).then(([tab]) => {
  try {
    if (tab?.url) tabOrigin = new URL(tab.url).origin;
  } catch {
    tabOrigin = null;
  }
});

el('m-add-device').addEventListener('click', async () => {
  const origin = tabOrigin;
  if (!origin) return;

  // Access to this one site, asked for now, not every site at install.
  const granted = await chrome.permissions.request({ origins: [`${origin}/*`] }).catch(() => false);

  // Reset device view
  el('d-site').textContent = origin;
  el('d-status').textContent = 'Connecting…';
  el<HTMLImageElement>('d-qr').hidden = true;
  el('d-error').textContent = '';
  el<HTMLElement>('d-success').hidden = true;
  deviceWs?.close();
  show('device');

  if (!granted) {
    el('d-error').textContent = 'Keystone needs access to this site to add a device';
    el('d-status').textContent = '';
    return;
  }

  const result = await send({ type: 'ADD_DEVICE_INIT', origin }) as Record<string, unknown>;
  if (!result['ok']) {
    el('d-error').textContent = result['error'] as string;
    el('d-status').textContent = '';
    return;
  }

  const { pairingId, deviceChallenge, relay } = result as {
    pairingId: string;
    deviceChallenge: string;
    relay: string;
  };

  // Render QR
  const payload = JSON.stringify({
    type: 'ks_add_device',
    pairingId,
    challenge: deviceChallenge,
    relay,
    origin,
  });

  const dataUrl = await QRCode.toDataURL(payload, { width: 240, margin: 1, color: { dark: '#000', light: '#fff' } });
  const qrImg = el<HTMLImageElement>('d-qr');
  qrImg.src = dataUrl;
  qrImg.hidden = false;
  el('d-status').textContent = 'Scan with Keystone on your phone';

  // Wait for phone to send its pubkey via relay
  const ws = new WebSocket(`${relay}/${pairingId}`);
  deviceWs = ws;

  ws.onmessage = async (e) => {
    ws.close();
    qrImg.hidden = true;
    el('d-status').textContent = 'Verifying…';

    const reply = parsePhoneReply(e.data);
    if (!reply) {
      el('d-status').textContent = '';
      el('d-error').textContent = 'The phone sent a reply Keystone cannot read';
      return;
    }
    const { pubkey, signature } = reply;
    const confirm = await send({ type: 'ADD_DEVICE_CONFIRM', origin, pairingId, pubkey, signature }) as Record<string, unknown>;

    if (confirm['ok']) {
      el('d-status').textContent = '';
      el<HTMLElement>('d-success').hidden = false;
      el('d-success').textContent = 'Device added — your phone can now sign in.';
    } else {
      el('d-status').textContent = '';
      el('d-error').textContent = confirm['error'] as string || 'Failed to register device';
    }
  };

  ws.onerror = () => {
    el('d-error').textContent = 'Relay connection failed';
    el('d-status').textContent = '';
  };
});

el('d-back').addEventListener('click', () => {
  deviceWs?.close();
  deviceWs = null;
  show('main');
});

init();
