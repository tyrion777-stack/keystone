import {
  encryptSeed,
  decryptSeed,
  signMessage,
  getPublicKeyHex,
  generateSeed,
  seedFromHex,
} from './crypto';
import {
  contentToSign,
  pinAfterApproval,
  prepareApproval,
  prepareSignIn,
  Refused,
  type Pending,
  type Pins,
} from './requests';
import { nowSeconds, type SignedMessage } from '../../wasm/js/keystone-core';

// In-flight requests waiting on the approval window: requestId → resolve
const pending = new Map<string, (result: SignResult) => void>();

interface SignResult {
  signed?: SignedMessage;
  error?: string;
}

// A web page reaches the worker only through content.ts, and only with these messages.
// Everything else (setup, unlock, approving a request) comes from the extension's own pages.
const PAGE_MESSAGES = new Set(['GET_PUBKEY', 'SIGN_IN_REQUEST', 'APPROVE_REQUEST']);

function isExtensionPage(sender: chrome.runtime.MessageSender): boolean {
  return sender.id === chrome.runtime.id && (sender.url ?? '').startsWith(chrome.runtime.getURL(''));
}

// The origin of the page that sent the message, as the browser reports it. Never a field of the
// message itself, which the page could set.
function senderOrigin(sender: chrome.runtime.MessageSender): string | null {
  try {
    const origin = sender.origin ?? new URL(sender.url ?? '').origin;
    return /^https?:\/\//.test(origin) ? origin : null;
  } catch {
    return null;
  }
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!isExtensionPage(sender) && !PAGE_MESSAGES.has(msg?.type)) return false;

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

    case 'SIGN_IN_REQUEST':
    case 'APPROVE_REQUEST': {
      const origin = senderOrigin(sender);
      if (isExtensionPage(sender) || !origin) {
        sendResponse({ error: 'Sign requests come from web pages only' });
        return false;
      }
      const prepare =
        msg.type === 'SIGN_IN_REQUEST'
          ? prepareSignIn(msg.challenge, origin)
          : loadPins().then(pins => prepareApproval(msg.request, origin, pins));
      prepare.then(askPerson, refusal).then(sendResponse);
      return true;
    }

    case 'FORGET_PIN':
      forgetPin(msg.requestId as string).then(sendResponse);
      return true;

    case 'SIGN_APPROVED':
      handleApproved(msg.requestId as string, msg.password as string | undefined).then(sendResponse);
      return true;

    case 'SIGN_DENIED':
      pending.get(msg.requestId as string)?.({ error: 'User denied the request' });
      pending.delete(msg.requestId as string);
      return false;

    case 'GET_PENDING':
      Promise.all([chrome.storage.session.get(`req_${msg.requestId as string}`), getSession()]).then(
        ([d, session]) => {
          const req = d[`req_${msg.requestId as string}`];
          sendResponse(req ? { ...req, unlocked: !!session } : null);
        },
      );
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
    const seed = await decryptSeed(storage['encryptedSeed'] as string, password);
    await saveSession(seed);
    return { ok: true, pubkeyHex: storage['pubkeyHex'] as string };
  } catch (e) {
    return { ok: false, error: (e as Error).message };
  }
}

// Every request opens the approval window, locked or not: the person sees which site is asking
// before anything is signed. Unlocked only means no password is asked for.
function refusal(e: unknown): SignResult {
  if (e instanceof Refused) return { error: e.message };
  console.error('Keystone: request failed', e);
  return { error: 'Keystone could not check that request' };
}

// Every request that passed its checks opens the approval window, locked or not: the person
// sees which site is asking, and for what, before anything is signed.
async function askPerson(p: Pending): Promise<SignResult> {
  const requestId = crypto.randomUUID();
  await chrome.storage.session.set({ [`req_${requestId}`]: p });

  await chrome.windows.create({
    url: chrome.runtime.getURL(`approval.html?id=${requestId}`),
    type: 'popup',
    width: 420,
    height: p.kind === 'sign-in' ? 360 : 480,
    focused: true,
  });

  return new Promise(resolve => {
    pending.set(requestId, resolve);
  });
}

// Service keys pinned per site, from the first request the person approved there.
async function loadPins(): Promise<Pins> {
  const d = await chrome.storage.local.get('pins');
  return (d['pins'] as Pins | undefined) ?? {};
}

// No password means the person approved while unlocked: sign with the session seed.
async function handleApproved(requestId: string, password: string | undefined): Promise<{ error?: string }> {
  const finish = (result: SignResult) => {
    pending.get(requestId)?.(result);
    pending.delete(requestId);
  };

  try {
    const reqData = await chrome.storage.session.get(`req_${requestId}`);
    const req = reqData[`req_${requestId}`] as Pending | undefined;
    if (!req) {
      finish({ error: 'Request expired or already handled' });
      return {};
    }

    const storage = await chrome.storage.local.get(['encryptedSeed']);
    if (!storage['encryptedSeed']) {
      finish({ error: 'No key configured' });
      return {};
    }

    let seed: Uint8Array;
    if (password) {
      try {
        seed = await decryptSeed(storage['encryptedSeed'] as string, password);
      } catch {
        return { error: 'WRONG_PASSWORD' };
      }
      await saveSession(seed);
    } else {
      const session = await getSession();
      if (!session) return { error: 'LOCKED' };
      seed = session;
    }

    await chrome.storage.session.remove(`req_${requestId}`);
    const pins = await loadPins();
    let content: string;
    try {
      content = await contentToSign(req, pins);
    } catch (e) {
      finish(refusal(e));
      return {};
    }
    const pinned = pinAfterApproval(req, pins, nowSeconds());
    if (pinned) await chrome.storage.local.set({ pins: pinned });
    finish({ signed: signMessage(seed, content) });
    return {};
  } catch (e) {
    finish({ error: (e as Error).message });
    return {};
  }
}

// The person chose to forget a site's old key after seeing it change. Nothing is signed; the
// site has to ask again, and is then treated as new.
async function forgetPin(requestId: string): Promise<{ ok: boolean }> {
  const reqData = await chrome.storage.session.get(`req_${requestId}`);
  const req = reqData[`req_${requestId}`] as Pending | undefined;
  if (!req || req.kind !== 'blocked') return { ok: false };
  const pins = await loadPins();
  delete pins[req.origin];
  await chrome.storage.local.set({ pins });
  await chrome.storage.session.remove(`req_${requestId}`);
  pending.get(requestId)?.({ error: 'The site’s old key was forgotten. Ask again.' });
  pending.delete(requestId);
  return { ok: true };
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
