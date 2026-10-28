// keystone-core's checks in JavaScript: the Rust code itself, compiled to WebAssembly
// (wasm/src/lib.rs), so the app and the extension verify exactly as services do.
//
// Every function is async: the module is compiled once, on first use.

import { WASM_BASE64 } from './keystone-core.wasm.generated';

export interface SignedMessage {
  author: string;
  content: string;
  content_hash: string;
  signature: string;
}

export type Purpose = 'link' | 'check-in' | 'sign';

export interface ServiceRequest {
  kind: 'keystone.request';
  v: number;
  /** A label only. Trust the service key, pinned on first use, not the name. */
  service: string;
  origin: string;
  purpose: Purpose;
  nonce: string;
  issued_at: number;
  expires_at: number;
  payload?: string;
}

export interface VerifiedRequest {
  /** The key that signed the request, wire form. Compare with the key pinned for its origin. */
  serviceKey: string;
  request: ServiceRequest;
  hash: string;
  /** What the person signs, with the SignedMessage rule, to approve this request. */
  approvalContent: string;
}

/** A check failed. `message` says which; its wording is not stable. */
export class KeystoneCoreError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'KeystoneCoreError';
  }
}

interface Exports {
  memory: WebAssembly.Memory;
  ks_alloc(len: number): number;
  ks_free(ptr: number, len: number): void;
  ks_call(ptr: number, len: number): bigint;
}

let loading: Promise<Exports> | null = null;

function load(): Promise<Exports> {
  loading ??= (async () => {
    const bytes = Uint8Array.from(atob(WASM_BASE64), c => c.charCodeAt(0));
    const { instance } = await WebAssembly.instantiate(bytes, {});
    return instance.exports as unknown as Exports;
  })();
  return loading;
}

async function call(request: Record<string, unknown>): Promise<Record<string, unknown>> {
  const ex = await load();
  const input = new TextEncoder().encode(JSON.stringify(request));
  const ptr = ex.ks_alloc(input.length);
  new Uint8Array(ex.memory.buffer, ptr, input.length).set(input);
  // ks_call takes ownership of the input buffer. The answer is (pointer << 32) | length.
  const packed = ex.ks_call(ptr, input.length);
  const outPtr = Number(packed >> 32n);
  const outLen = Number(packed & 0xffff_ffffn);
  // Read after the call: memory may have grown, which replaces memory.buffer.
  const text = new TextDecoder().decode(new Uint8Array(ex.memory.buffer, outPtr, outLen));
  ex.ks_free(outPtr, outLen);
  const answer = JSON.parse(text) as { ok: boolean; error?: string } & Record<string, unknown>;
  if (!answer.ok) throw new KeystoneCoreError(answer.error ?? 'check failed');
  return answer;
}

/** Unix seconds now, as the checks expect. */
export function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

/** Check a service's signed request: its signature, every field, and its time window. */
export async function verifyRequest(signed: SignedMessage, now = nowSeconds()): Promise<VerifiedRequest> {
  const a = await call({ op: 'verify_request', signed, now });
  return {
    serviceKey: a['service_key'] as string,
    request: a['request'] as ServiceRequest,
    hash: a['hash'] as string,
    approvalContent: a['approval_content'] as string,
  };
}

/** The text to sign to sign in at `origin` with `challenge`. Throws if either is malformed. */
export async function signInContent(origin: string, challenge: string): Promise<string> {
  return (await call({ op: 'sign_in_content', origin, challenge }))['content'] as string;
}

/** A service's check of a sign-in. Returns the person's key, wire form. */
export async function verifySignIn(signed: SignedMessage, origin: string, challenge: string): Promise<string> {
  return (await call({ op: 'verify_sign_in', signed, origin, challenge }))['person'] as string;
}

/** A service's check of an approval against the request it issued. */
export async function verifyApproval(
  approval: SignedMessage,
  issued: SignedMessage,
  now = nowSeconds(),
): Promise<{ person: string; purpose: Purpose; nonce: string }> {
  const a = await call({ op: 'verify_approval', approval, issued, now });
  return { person: a['person'] as string, purpose: a['purpose'] as Purpose, nonce: a['nonce'] as string };
}
