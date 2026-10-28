// A module, as Vite bundles it: without this, tsc reads every page script as one global scope.
export {};

const params = new URLSearchParams(window.location.search);
const requestId = params.get('id');

const approveBtn = document.getElementById('approve-btn') as HTMLButtonElement;
const denyBtn    = document.getElementById('deny-btn')   as HTMLButtonElement;
const pwInput    = document.getElementById('ap-pw')      as HTMLInputElement;
const errEl      = document.getElementById('ap-error')   as HTMLElement;

async function init() {
  if (!requestId) {
    document.getElementById('loading')!.textContent = 'Invalid request.';
    return;
  }

  const req = await chrome.runtime.sendMessage({ type: 'GET_PENDING', requestId }) as
    { challenge: string; origin: string } | null;

  if (!req) {
    document.getElementById('loading')!.textContent = 'Request expired or already handled.';
    return;
  }

  document.getElementById('req-origin')!.textContent    = req.origin;
  document.getElementById('req-challenge')!.textContent = req.challenge;
  document.getElementById('loading')!.hidden  = true;
  document.getElementById('content')!.hidden  = false;
  pwInput.focus();
}

approveBtn.addEventListener('click', async () => {
  const pw = pwInput.value;
  if (!pw) { errEl.textContent = 'Password required'; return; }

  approveBtn.disabled = true;
  approveBtn.textContent = 'Signing…';
  errEl.textContent = '';

  const result = await chrome.runtime.sendMessage({
    type: 'SIGN_APPROVED',
    requestId,
    password: pw,
  }) as { error?: string } | null;

  if (result?.error === 'WRONG_PASSWORD') {
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
