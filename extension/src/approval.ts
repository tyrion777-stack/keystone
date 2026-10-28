import type { Pending } from './requests';

const params = new URLSearchParams(window.location.search);
const requestId = params.get('id');

const approveBtn = document.getElementById('approve-btn') as HTMLButtonElement;
const denyBtn    = document.getElementById('deny-btn')    as HTMLButtonElement;
const forgetBtn  = document.getElementById('forget-btn')  as HTMLButtonElement;
const pwInput    = document.getElementById('ap-pw')       as HTMLInputElement;
const errEl      = document.getElementById('ap-error')    as HTMLElement;
const pwBlock    = document.getElementById('ap-pw-block') as HTMLElement;

// Unlocked: approving is one click. Locked, or the session ran out meanwhile: ask for the password.
let needPassword = true;

function askForPassword() {
  needPassword = true;
  pwBlock.hidden = false;
  pwInput.focus();
}

function text(id: string, value: string) {
  (document.getElementById(id) as HTMLElement).textContent = value;
}

function date(seconds: number): string {
  return new Date(seconds * 1000).toLocaleDateString();
}

// Everything a site supplies (its name, the text to sign) goes in as textContent.
function render(req: Pending) {
  text('req-origin', req.origin);

  if (req.kind === 'sign-in') {
    text('title', 'Sign in');
    text('req-ask', 'Sign in to this site with your Keystone?');
    text('req-note', 'The signature names this site, so it cannot be used anywhere else.');
    approveBtn.textContent = 'Sign in';
    return;
  }

  if (req.kind === 'blocked') {
    text('title', 'Blocked: this site’s key changed');
    text('req-ask', `A request names itself “${req.service}”, but it is signed by a different key than this site used before.`);
    const warning = document.getElementById('req-warning') as HTMLElement;
    warning.textContent =
      `Nothing will be signed. Someone may be pretending to be this site. If the site told you it ` +
      `changed its key, you can forget the old one (remembered ${date(req.pinned.since)}) and let ` +
      `it ask again.`;
    warning.hidden = false;
    text('req-note', `Old key: ${req.pinned.serviceKey}\nNew key: ${req.serviceKey}`);
    (document.getElementById('req-note') as HTMLElement).classList.add('key');
    approveBtn.hidden = true;
    forgetBtn.hidden = false;
    denyBtn.textContent = 'Close';
    return;
  }

  text('title', 'Approve request');
  const name = `“${req.service}”`;
  if (req.purpose === 'link') text('req-ask', `Link your Keystone to ${name}?`);
  else if (req.purpose === 'check-in') text('req-ask', `Check in at ${name}?`);
  else text('req-ask', `${name} asks you to sign this:`);

  if (req.payload !== null) {
    const payload = document.getElementById('req-payload') as HTMLElement;
    payload.textContent = req.payload;
    payload.hidden = false;
  }

  const note = document.getElementById('req-note') as HTMLElement;
  note.textContent =
    req.pinnedSince === null
      ? '✓ Signed by this site. First time it has asked: its key will be remembered.'
      : `✓ Signed by this site, with the same key as on ${date(req.pinnedSince)}.`;
  note.classList.add('verified');
  approveBtn.textContent = 'Approve';
}

async function init() {
  if (!requestId) {
    text('loading', 'Invalid request.');
    return;
  }

  const req = await chrome.runtime.sendMessage({ type: 'GET_PENDING', requestId }) as
    (Pending & { unlocked: boolean }) | null;

  if (!req) {
    text('loading', 'Request expired or already handled.');
    return;
  }

  render(req);
  (document.getElementById('loading') as HTMLElement).hidden = true;
  (document.getElementById('content') as HTMLElement).hidden = false;
  if (req.kind === 'blocked') return;
  if (req.unlocked) {
    needPassword = false;
    pwBlock.hidden = true;
    approveBtn.focus();
  } else {
    askForPassword();
  }
}

approveBtn.addEventListener('click', async () => {
  const pw = needPassword ? pwInput.value : undefined;
  if (needPassword && !pw) { errEl.textContent = 'Password required'; return; }

  const label = approveBtn.textContent;
  approveBtn.disabled = true;
  approveBtn.textContent = 'Signing…';
  errEl.textContent = '';

  const result = await chrome.runtime.sendMessage({
    type: 'SIGN_APPROVED',
    requestId,
    password: pw,
  }) as { error?: string } | null;

  if (result?.error === 'LOCKED') {
    errEl.textContent = 'Keystone locked meanwhile. Enter your password.';
    approveBtn.disabled = false;
    approveBtn.textContent = label;
    askForPassword();
  } else if (result?.error === 'WRONG_PASSWORD') {
    errEl.textContent = 'Wrong password — try again.';
    approveBtn.disabled = false;
    approveBtn.textContent = label;
    pwInput.value = '';
    pwInput.focus();
  } else {
    window.close();
  }
});

denyBtn.addEventListener('click', async () => {
  await chrome.runtime.sendMessage({ type: 'SIGN_DENIED', requestId });
  window.close();
});

forgetBtn.addEventListener('click', async () => {
  await chrome.runtime.sendMessage({ type: 'FORGET_PIN', requestId });
  window.close();
});

pwInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') approveBtn.click();
});

init();
