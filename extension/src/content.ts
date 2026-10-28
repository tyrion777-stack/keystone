// Runs in ISOLATED world. Bridges window.keystone (MAIN world) ↔ service worker.
// Never touches private key material — just passes messages.

window.addEventListener('message', async (event) => {
  if (event.source !== window) return;
  const msg = event.data as Record<string, unknown>;
  if (!msg?.__ks) return;

  const id = msg['id'] as string;
  const type = msg['type'] as string;

  try {
    if (type === 'GET_PUBKEY') {
      const r = await chrome.runtime.sendMessage({ type: 'GET_PUBKEY' });
      window.postMessage({ __ks_resp: id, ...(r as object) }, '*');
    } else if (type === 'SIGN') {
      const r = await chrome.runtime.sendMessage({
        type: 'SIGN_REQUEST',
        challenge: msg['challenge'],
        origin: window.location.origin,
      });
      window.postMessage({ __ks_resp: id, ...(r as object) }, '*');
    }
  } catch (e) {
    window.postMessage({ __ks_resp: id, error: (e as Error).message }, '*');
  }
});
