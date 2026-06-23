// Runs in MAIN world (same JS context as the page).
// Exposes window.keystone — the only surface sites interact with.
// Private key material never reaches this script.

(function () {
  if ((window as unknown as Record<string, unknown>)['keystone']) return;

  let seq = 0;
  const callbacks = new Map<string, { resolve: (v: unknown) => void; reject: (e: Error) => void }>();

  window.addEventListener('message', (e) => {
    if (e.source !== window) return;
    const data = e.data as Record<string, unknown> | null;
    if (!data) return;
    const id = data['__ks_resp'] as string | undefined;
    if (!id) return;
    const cb = callbacks.get(id);
    if (!cb) return;
    callbacks.delete(id);
    if (data['error']) cb.reject(new Error(data['error'] as string));
    else cb.resolve(data);
  });

  function send(type: string, extra?: Record<string, unknown>): Promise<Record<string, unknown>> {
    const id = `ks${++seq}`;
    return new Promise((resolve, reject) => {
      callbacks.set(id, { resolve: resolve as (v: unknown) => void, reject });
      window.postMessage({ __ks: true, id, type, ...extra }, '*');
      setTimeout(() => {
        if (callbacks.has(id)) {
          callbacks.delete(id);
          reject(new Error('Keystone: request timed out'));
        }
      }, 120_000);
    });
  }

  (window as unknown as Record<string, unknown>)['keystone'] = {
    isInstalled: true,
    version: '0.1.0',

    async getPublicKey(): Promise<string | null> {
      const r = await send('GET_PUBKEY');
      return (r['pubkey'] as string) ?? null;
    },

    async sign(challenge: string): Promise<{ signature: string; pubkey: string }> {
      const r = await send('SIGN', { challenge });
      if (!r['signature']) throw new Error((r['error'] as string) ?? 'Signing failed');
      return { signature: r['signature'] as string, pubkey: r['pubkey'] as string };
    },
  };
})();
