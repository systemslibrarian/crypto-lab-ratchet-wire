/**
 * Double Ratchet Algorithm — message encryption / decryption
 *
 * Reference: Signal Double Ratchet Specification, Section 3.4-3.5
 * https://signal.org/docs/specifications/doubleratchet/
 *
 * Combines the DH ratchet (break-in recovery) with the symmetric ratchet
 * (forward secrecy), and handles out-of-order delivery by storing skipped
 * message keys. The message header is authenticated as associated data, so a
 * tampered header causes decryption to fail.
 */

import { ratchetStep, ChainState, clearKey } from './symmetric-ratchet';
import { dhRatchet, RatchetState } from './dh-ratchet';
import { exportPublicKeyRaw, importPublicKeyRaw } from './x25519';

/** Maximum number of skipped message keys to retain (DoS guard). */
const MAX_SKIP = 1000;

/** A wire message: an authenticated header plus AES-256-GCM ciphertext. */
export interface Message {
  header: {
    /** Sender's current ratchet (DH) public key, base64. */
    dhPublicKey: string;
    /** Message number within the sender's current sending chain (Ns). */
    messageNumber: number;
    /** Length of the sender's previous sending chain (PN), for skip detection. */
    previousChainLength: number;
  };
  /** AES-256-GCM ciphertext, base64. */
  ciphertext: string;
  /** 12-byte AES-GCM IV, base64. */
  iv: string;
}

/** Skipped-key store: `${senderDHPublicKeyB64}:${messageNumber}` -> message key. */
export type SkippedKeys = Map<string, ArrayBuffer>;

/**
 * Encrypt a plaintext message (Signal's RatchetEncrypt).
 *
 * Advances the sending chain by one step, encrypts under the derived message
 * key with the header bound in as associated data, then clears the message key.
 *
 * @param state - Current ratchet state (must have a sending chain)
 * @param plaintext - Message to encrypt
 * @returns The wire message and the advanced ratchet state
 * @throws Error if the party has no sending chain yet (e.g. the responder
 *   before receiving the initiator's first message)
 */
export async function encrypt(
  state: RatchetState,
  plaintext: string
): Promise<{ message: Message; newState: RatchetState }> {
  if (!state.sendingChain) {
    throw new Error(
      'No sending chain yet — the responder must receive the first message before sending.'
    );
  }

  const { newState: advancedChain, messageKey } = await ratchetStep(state.sendingChain);

  const dhPublicKeyB64 = arrayBufferToBase64(
    await exportPublicKeyRaw(state.myDHKeyPair.publicKey)
  );

  const header: Message['header'] = {
    dhPublicKey: dhPublicKeyB64,
    messageNumber: messageKey.messageNumber,
    previousChainLength: state.previousSendingChainLength,
  };

  const { ciphertext, iv } = await encryptAESGCM(plaintext, messageKey.key, headerAad(header));
  clearKey(messageKey.key);

  return {
    message: { header, ciphertext, iv },
    newState: { ...state, sendingChain: advancedChain },
  };
}

/**
 * Decrypt a received message (Signal's RatchetDecrypt).
 *
 * Tries a previously-skipped key first; otherwise performs a DH ratchet if the
 * header carries a new ratchet key, skips any intervening message keys (storing
 * them for later), derives the target message key, and decrypts. The input
 * `state` and `skippedKeys` are never mutated — fresh values are returned.
 *
 * @param state - Current ratchet state
 * @param message - The received wire message
 * @param skippedKeys - Known skipped message keys (defaults to empty)
 * @returns The plaintext, the new ratchet state, and the updated skipped-key map
 */
export async function decrypt(
  state: RatchetState,
  message: Message,
  skippedKeys: SkippedKeys = new Map()
): Promise<{ plaintext: string; newState: RatchetState; skippedKeys: SkippedKeys }> {
  validateHeader(message.header);

  const senderPubB64 = message.header.dhPublicKey;
  const updatedSkipped: SkippedKeys = new Map(skippedKeys);
  const aad = headerAad(message.header);

  // 1. A key we skipped earlier? Use it without touching the ratchet.
  const skippedId = skippedKeyId(senderPubB64, message.header.messageNumber);
  const skipped = updatedSkipped.get(skippedId);
  if (skipped) {
    const plaintext = await decryptAESGCM(message.ciphertext, message.iv, skipped, aad);
    updatedSkipped.delete(skippedId);
    // NB: we do NOT clearKey(skipped) here — the buffer is shared with the
    // caller's input map (Map copy is shallow), and decrypt() is contractually
    // non-mutating. The consumed key is released with the old, discarded map.
    return { plaintext, newState: state, skippedKeys: updatedSkipped };
  }

  // 2. New ratchet key in the header? Skip the rest of the old chain, then ratchet.
  let workingState = state;
  const currentDHrB64 = state.theirDHPublicKey
    ? arrayBufferToBase64(await exportPublicKeyRaw(state.theirDHPublicKey))
    : null;

  if (senderPubB64 !== currentDHrB64) {
    if (state.receivingChain && currentDHrB64) {
      await skipMessageKeys(
        state.receivingChain,
        message.header.previousChainLength,
        currentDHrB64,
        updatedSkipped
      );
    }
    workingState = await dhRatchet(workingState, await importPublicKeyRaw(base64ToArrayBuffer(senderPubB64)));
  }

  if (!workingState.receivingChain) {
    throw new Error('No receiving chain available to decrypt this message.');
  }

  // 3. Skip forward within the current receiving chain to the target message.
  let chain: ChainState = workingState.receivingChain;
  assertSkipWithinBounds(chain.messageNumber, message.header.messageNumber);
  while (chain.messageNumber < message.header.messageNumber) {
    const { newState: advanced, messageKey } = await ratchetStep(chain);
    storeSkipped(updatedSkipped, senderPubB64, messageKey);
    chain = advanced;
  }

  // 4. Derive the target message key and advance the chain past it.
  const { newState: advancedChain, messageKey } = await ratchetStep(chain);
  const plaintext = await decryptAESGCM(message.ciphertext, message.iv, messageKey.key, aad);
  clearKey(messageKey.key);

  return {
    plaintext,
    newState: { ...workingState, receivingChain: advancedChain },
    skippedKeys: updatedSkipped,
  };
}

/**
 * Advance a chain up to `targetMessageNumber`, storing each derived key as a
 * skipped key. Used to consume the tail of an old receiving chain before a DH
 * ratchet, so out-of-order stragglers from that chain can still be decrypted.
 */
async function skipMessageKeys(
  chain: ChainState,
  targetMessageNumber: number,
  senderPubB64: string,
  skippedKeys: SkippedKeys
): Promise<void> {
  let current = chain;
  assertSkipWithinBounds(current.messageNumber, targetMessageNumber);
  while (current.messageNumber < targetMessageNumber) {
    const { newState, messageKey } = await ratchetStep(current);
    storeSkipped(skippedKeys, senderPubB64, messageKey);
    current = newState;
  }
}

/**
 * Reject a malformed wire header before it reaches the ratchet logic.
 *
 * `messageNumber` and `previousChainLength` arrive as untrusted JSON numbers.
 * A negative, fractional, `NaN`, or `Infinity` value would otherwise slip past
 * the {@link assertSkipWithinBounds} arithmetic and be silently mishandled
 * (e.g. `NaN` makes every `<` comparison false, skipping the loop and deriving
 * the wrong key). Fail fast with a clear error instead.
 */
function validateHeader(header: Message['header']): void {
  const isCount = (n: number): boolean => Number.isInteger(n) && n >= 0;
  if (!isCount(header.messageNumber) || !isCount(header.previousChainLength)) {
    throw new Error('Malformed message header: message numbers must be non-negative integers.');
  }
}

/**
 * Refuse to derive more than {@link MAX_SKIP} keys in a single skip operation.
 *
 * The message header (and therefore its `messageNumber`) is NOT yet
 * authenticated when we skip — AEAD verification happens only once we reach the
 * target key. Without this bound, a forged or corrupt header claiming a huge
 * `messageNumber` would make us run the KDF that many times before the auth tag
 * is ever checked, hanging the receiver (a denial-of-service). This mirrors the
 * Signal spec's `MAX_SKIP` guard.
 */
function assertSkipWithinBounds(from: number, to: number): void {
  if (to - from > MAX_SKIP) {
    throw new Error(
      `Refusing to skip ${to - from} message keys (max ${MAX_SKIP}) — ` +
        'the header claims too large a message number (possible DoS or excessive loss).'
    );
  }
}

function storeSkipped(
  skippedKeys: SkippedKeys,
  senderPubB64: string,
  messageKey: { key: ArrayBuffer; messageNumber: number }
): void {
  skippedKeys.set(skippedKeyId(senderPubB64, messageKey.messageNumber), messageKey.key);
  // Evict oldest entries beyond the cap (Map preserves insertion order).
  while (skippedKeys.size > MAX_SKIP) {
    const oldest = skippedKeys.keys().next().value;
    if (oldest === undefined) break;
    skippedKeys.delete(oldest);
  }
}

const skippedKeyId = (senderPubB64: string, messageNumber: number): string =>
  `${senderPubB64}:${messageNumber}`;

/** Canonical associated data for a header (must match on encrypt and decrypt). */
function headerAad(header: Message['header']): ArrayBuffer {
  return new TextEncoder().encode(
    `${header.dhPublicKey}|${header.messageNumber}|${header.previousChainLength}`
  ).buffer;
}

/** Encrypt with AES-256-GCM, binding `aad` for authentication. */
async function encryptAESGCM(
  plaintext: string,
  keyMaterial: ArrayBuffer,
  aad: ArrayBuffer
): Promise<{ ciphertext: string; iv: string }> {
  const key = await crypto.subtle.importKey('raw', keyMaterial, { name: 'AES-GCM' }, false, [
    'encrypt',
  ]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: aad },
    key,
    new TextEncoder().encode(plaintext)
  );

  return {
    ciphertext: arrayBufferToBase64(ciphertext),
    iv: arrayBufferToBase64(iv.buffer),
  };
}

/** Decrypt AES-256-GCM, verifying `aad`. Throws if authentication fails. */
async function decryptAESGCM(
  ciphertextB64: string,
  ivB64: string,
  keyMaterial: ArrayBuffer,
  aad: ArrayBuffer
): Promise<string> {
  const key = await crypto.subtle.importKey('raw', keyMaterial, { name: 'AES-GCM' }, false, [
    'decrypt',
  ]);
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: base64ToArrayBuffer(ivB64), additionalData: aad },
    key,
    base64ToArrayBuffer(ciphertextB64)
  );
  return new TextDecoder().decode(plaintext);
}

function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}
