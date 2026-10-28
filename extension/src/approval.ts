const params = new URLSearchParams(window.location.search);
const requestId = params.get('id');

const approveBtn = document.getElementById('approve-btn') as HTMLButtonElement;
const denyBtn    = document.getElementById('deny-btn')   as HTMLButtonElement;
const pwInput    = document.getElementById('ap-pw')      as HTMLInputElement;
const errEl      = document.getElementById('ap-error')   as HTMLElement;
const pwBlock    = document.getElementById('ap-pw-block') as HTMLElement;

// Unlocked: approving is one click. Locked, or the session ran out meanwhile: ask for the password.
let needPassword = true;

function askForPassword() {
  needPassword = true;
  pwBlock.hidden = false;
  pwInput.focus();
}

async function init() {
  if (!requestId) {
    document.getElementById('loading')!.textContent = 'Invalid request.';
    return;
  }

  const req = await chrome.runtime.sendMessage({ type: 'GET_PENDING', requestId }) as
    { challenge: string; origin: string; unlocked: boolean } | null;

  if (!req) {
    document.getElementById('loading')!.textContent = 'Request expired or already handled.';
    return;
  }

  document.getElementById('req-origin')!.textContent    = req.origin;
  document.getElementById('req-challenge')!.textContent = req.challenge;
  document.getElementById('loading')!.hidden  = true;
  document.getElementById('content')!.hidden  = false;
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
    approveBtn.textContent = 'Sign & Approve';
    askForPassword();
  } else if (result?.error === 'WRONG_PASSWORD') {
    errEl.textContent = 'Wrong password — try again.';
    approveBtn.disabled = false;
    approveBtn.textContent = 'Sign & Approve';
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

pwInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') approveBtn.click();
});

init();
