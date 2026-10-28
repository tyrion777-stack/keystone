import {
  encryptSeed,
  decryptSeed,
  needsMigration,
  signChallenge,
  getPublicKeyHex,
  generateSeed,
  seedFromHex,
} from './crypto';
import { blake3 } from '@noble/hashes/blake3';
import { bytesToHex as b3Hex } from '@noble/hashes/utils';

// In-flight sign requests waiting on the approval window: requestId → resolve
const pending = new Map<string, (result: SignResult) => void>();

interface SignResult {
  signature?: string;
  pubkey?: string;
  error?: string;
}

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  switch (msg.type) {
    case 'CHECK_SETUP':
      chrome.storage.local.get('encryptedSeed').then(d => {
        sendResponse({ hasKey: !!d['encryptedSeed'] });
      });
      return true;

    case 'SETUP_IMPORT':
      setupFromHex(msg.privkeyHex as string, msg.password as string).then(sendResponse);
      return true;

    case 'SETUP_GENERATE':
      setupGenerate(msg.password as string).then(sendResponse);
      return true;

    case 'GET_PUBKEY':
      chrome.storage.local.get('pubkeyHex').then(d => {
        sendResponse({ pubkey: (d['pubkeyHex'] as string) ?? null });
      });
      return true;

    case 'GET_SESSION_STATUS':
      getSession().then(s => sendResponse({ locked: !s }));
      return true;

    case 'UNLOCK':
      unlockWithPassword(msg.password as string).then(sendResponse);
      return true;

    case 'LOCK':
      chrome.storage.session.remove('session').then(() => sendResponse({ ok: true }));
      return true;

    case 'SIGN_REQUEST':
      handleSignRequest(msg.challenge as string, msg.origin as string).then(sendResponse);
      return true;

    case 'SIGN_APPROVED':
      handleApproved(msg.requestId as string, msg.password as string).then(sendResponse);
      return true;

    case 'SIGN_DENIED':
      pending.get(msg.requestId as string)?.({ error: 'User denied the request' });
      pending.delete(msg.requestId as string);
      return false;

    case 'GET_PENDING':
      chrome.storage.session.get(`req_${msg.requestId as string}`).then(d => {
        sendResponse(d[`req_${msg.requestId as string}`] ?? null);
      });
      return true;

    case 'ADD_DEVICE_INIT':
      addDeviceInit(msg.origin as string).then(sendResponse);
      return true;

    case 'ADD_DEVICE_CONFIRM':
      addDeviceConfirm(
        msg.origin as string,
        msg.pairingId as string,
        msg.pubkey as string,
        msg.signature as string,
      ).then(sendResponse);
      return true;
  }
});

async function setupFromHex(privkeyHex: string, password: string) {
  try {
    const seed = seedFromHex(privkeyHex);
    return await storeSeed(seed, password);
  } catch (e) {
    return { ok: false, error: (e as Error).message };
  }
}

async function setupGenerate(password: string) {
  const seed = generateSeed();
  const privkeyHex = bytesToHex(seed);
  const result = await storeSeed(seed, password);
  return { ...result, privkeyHex };
}

async function storeSeed(seed: Uint8Array, password: string) {
  try {
    const encryptedSeed = await encryptSeed(seed, password);
    const pubkeyHex = getPublicKeyHex(seed);
    await chrome.storage.local.set({ encryptedSeed, pubkeyHex });
    await saveSession(seed);
    return { ok: true, pubkeyHex };
  } catch (e) {
    return { ok: false, error: (e as Error).message };
  }
}

async function unlockWithPassword(password: string) {
  try {
    const storage = await chrome.storage.local.get(['encryptedSeed', 'pubkeyHex']);
    if (!storage['encryptedSeed']) return { ok: false, error: 'No key configured' };
    const encBlob = storage['encryptedSeed'] as string;
    const seed = await decryptSeed(encBlob, password);
    // Silently migrate PBKDF2 → Argon2id on first unlock after upgrade
    if (needsMigration(encBlob)) {
      await chrome.storage.local.set({ encryptedSeed: await encryptSeed(seed, password) });
    }
    await saveSession(seed);
    return { ok: true, pubkeyHex: storage['pubkeyHex'] as string };
  } catch (e) {
    return { ok: false, error: (e as Error).message };
  }
}

async function handleSignRequest(challenge: string, origin: string): Promise<SignResult> {
  const session = await getSession();

  if (session) {
    // Already unlocked — sign immediately, no popup needed
    const d = await chrome.storage.local.get('pubkeyHex');
    return {
      signature: signChallenge(session, challenge),
      pubkey: d['pubkeyHex'] as string,
    };
  }

  // Locked — open approval window, wait for user
  const requestId = crypto.randomUUID();
  await chrome.storage.session.set({
    [`req_${requestId}`]: { challenge, origin },
  });

  await chrome.windows.create({
    url: chrome.runtime.getURL(`approval.html?id=${requestId}`),
    type: 'popup',
    width: 400,
    height: 360,
    focused: true,
  });

  return new Promise(resolve => {
    pending.set(requestId, resolve);
  });
}

async function handleApproved(requestId: string, password: string): Promise<{ error?: string }> {
  try {
    const storage = await chrome.storage.local.get(['encryptedSeed', 'pubkeyHex']);
    if (!storage['encryptedSeed']) {
      pending.get(requestId)?.({ error: 'No key configured' });
      pending.delete(requestId);
      return {};
    }

    const encBlob = storage['encryptedSeed'] as string;
    let seed: Uint8Array;
    try {
      seed = await decryptSeed(encBlob, password);
    } catch {
      return { error: 'WRONG_PASSWORD' };
    }

    if (needsMigration(encBlob)) {
      await chrome.storage.local.set({ encryptedSeed: await encryptSeed(seed, password) });
    }
    await saveSession(seed);

    const reqData = await chrome.storage.session.get(`req_${requestId}`);
    const req = reqData[`req_${requestId}`] as { challenge: string } | undefined;
    await chrome.storage.session.remove(`req_${requestId}`);

    const signature = signChallenge(seed, req?.challenge ?? '');
    pending.get(requestId)?.({ signature, pubkey: storage['pubkeyHex'] as string });
    pending.delete(requestId);
    return {};
  } catch (e) {
    pending.get(requestId)?.({ error: (e as Error).message });
    pending.delete(requestId);
    return {};
  }
}

// Session: decrypted seed stored in chrome.storage.session (cleared on browser close).
// Expires after 30 minutes of inactivity.

async function getSession(): Promise<Uint8Array | null> {
  const d = await chrome.storage.session.get('session');
  const s = d['session'] as { seed: number[]; exp: number } | undefined;
  if (!s) return null;
  if (Date.now() > s.exp) {
    await chrome.storage.session.remove('session');
    return null;
  }
  // Extend on use
  await chrome.storage.session.set({ session: { seed: s.seed, exp: Date.now() + 1_800_000 } });
  return new Uint8Array(s.seed);
}

async function saveSession(seed: Uint8Array): Promise<void> {
  await chrome.storage.session.set({
    session: { seed: Array.from(seed), exp: Date.now() + 1_800_000 },
  });
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

async function addDeviceInit(origin: string): Promise<Record<string, unknown>> {
  const session = await getSession();
  if (!session) return { ok: false, error: 'Extension is locked — unlock it first' };

  const storage = await chrome.storage.local.get('pubkeyHex');
  const pubkeyHex = storage['pubkeyHex'] as string | undefined;
  if (!pubkeyHex) return { ok: false, error: 'No key configured' };

  let challenge: string;
  try {
    const res = await fetch(`${origin}/api/auth/keystone?pubkey=${pubkeyHex}`);
    if (!res.ok) throw new Error();
    const data = await res.json() as { challenge: string };
    challenge = data.challenge;
  } catch {
    return { ok: false, error: 'Could not reach site — make sure you are on a Keystone-enabled page' };
  }

  const blake3Hash = b3Hex(blake3(new TextEncoder().encode(challenge)));
  const sig = signChallenge(session, challenge);
  const pairingId = crypto.randomUUID();

  try {
    const res = await fetch(`${origin}/api/auth/keystone/device`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        pubkey_hex:    pubkeyHex,
        content:       challenge,
        blake3_hash:   blake3Hash,
        signature_hex: sig,
        pairingId,
      }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({})) as { message?: string };
      return { ok: false, error: err.message ?? 'Pairing init failed' };
    }
    const { deviceChallenge, relay } = await res.json() as { deviceChallenge: string; relay: string };
    return { ok: true, pairingId, deviceChallenge, relay };
  } catch {
    return { ok: false, error: 'Network error during pairing init' };
  }
}

async function addDeviceConfirm(
  origin: string,
  pairingId: string,
  pubkey: string,
  signature: string,
): Promise<Record<string, unknown>> {
  try {
    const res = await fetch(`${origin}/api/auth/keystone/device`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pairingId, pubkey, signature }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({})) as { message?: string };
      return { ok: false, error: err.message ?? 'Device confirmation failed' };
    }
    return { ok: true };
  } catch {
    return { ok: false, error: 'Network error during device confirmation' };
  }
}
