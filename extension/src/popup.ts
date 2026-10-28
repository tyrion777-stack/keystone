// A module, as Vite bundles it: without this, tsc reads every page script as one global scope.
export {};

type View = 'setup' | 'backup' | 'locked' | 'main';

function show(view: View) {
  for (const v of ['setup', 'backup', 'locked', 'main'] as const) {
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

init();
