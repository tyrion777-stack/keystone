// Checks on what a site, the relay and the phone hand the extension while adding a device.
// None of them is trusted to shape it.

// Pairing talks to the site from the worker, so the site must be https (or a local dev server).
export function isPairingOrigin(origin: string): boolean {
  try {
    const u = new URL(origin);
    return u.origin === origin && (u.protocol === 'https:' || (u.protocol === 'http:' && u.hostname === 'localhost'));
  } catch {
    return false;
  }
}

export function isRelayUrl(relay: unknown): relay is string {
  if (typeof relay !== 'string') return false;
  try {
    const u = new URL(relay);
    return u.protocol === 'wss:' || (u.protocol === 'ws:' && u.hostname === 'localhost');
  } catch {
    return false;
  }
}

// Public keys in core's wire form (core/src/key.rs): bare hex for Ed25519, `p256:` and the
// 33-byte compressed point for P-256. Either way the signature is 64 bytes.
const PUBLIC_KEY = /^(?:[0-9a-f]{64}|p256:0[23][0-9a-f]{64})$/;
const SIGNATURE = /^[0-9a-f]{128}$/;

// What the phone sends back over the relay.
export function parsePhoneReply(data: unknown): { pubkey: string; signature: string } | null {
  if (typeof data !== 'string' || data.length > 4096) return null;
  let reply: unknown;
  try {
    reply = JSON.parse(data);
  } catch {
    return null;
  }
  if (typeof reply !== 'object' || reply === null) return null;
  const { pubkey, signature } = reply as Record<string, unknown>;
  if (typeof pubkey !== 'string' || !PUBLIC_KEY.test(pubkey)) return null;
  if (typeof signature !== 'string' || !SIGNATURE.test(signature)) return null;
  return { pubkey, signature };
}
