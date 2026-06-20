/**
 * X25519 Elliptic Curve Diffie-Hellman
 *
 * Reference: RFC 7748 - Elliptic Curves for Security
 * https://tools.ietf.org/html/rfc7748
 *
 * Implemented with the audited, pure-JavaScript `@noble/curves` library rather
 * than the Web Crypto `X25519` algorithm. Web Crypto only gained X25519 very
 * recently (Chrome 133, 2025) and support is uneven across browsers, so relying
 * on it would make the demo fail to load on perfectly common setups. `@noble`
 * runs identically in every browser AND in Node, which also means the test
 * suite exercises exactly the same code path the browser does.
 *
 * Keys are represented as raw 32-byte `Uint8Array`s (the natural wire format).
 * The functions are kept `async` so call sites read the same as the rest of the
 * crypto layer (HKDF/AES-GCM, which remain genuinely async via Web Crypto).
 */

import { x25519 } from '@noble/curves/ed25519.js';
import { toArrayBuffer } from './bytes';

/** A raw X25519 key pair (32-byte public + 32-byte secret scalar). */
export interface KeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

/**
 * Generate an X25519 key pair.
 *
 * @returns The raw public and private keys
 */
export async function generateKeyPair(): Promise<KeyPair> {
  const privateKey = x25519.utils.randomSecretKey();
  const publicKey = x25519.getPublicKey(privateKey);
  return { publicKey, privateKey };
}

/**
 * Compute the X25519 shared secret from our private key and a peer's public key.
 *
 * `@noble` rejects non-contributory inputs (the identity element and the other
 * small-order points), so a peer who supplies a low-order public key to force a
 * fixed, publicly-known shared secret is refused with a thrown error rather than
 * silently producing predictable key material (cf. RFC 7748 §6.1).
 *
 * @param privateKey - Our private key (32-byte scalar)
 * @param publicKey - Peer's public key (32 bytes)
 * @returns The 32-byte shared secret
 * @throws Error if the peer's public key is a low-order point
 */
export async function deriveSharedSecret(
  privateKey: Uint8Array,
  publicKey: Uint8Array
): Promise<ArrayBuffer> {
  return toArrayBuffer(x25519.getSharedSecret(privateKey, publicKey));
}

/**
 * Export a public key as raw bytes (32 bytes for X25519) for transmission.
 *
 * @param publicKey - The public key to export
 * @returns 32 raw bytes
 */
export async function exportPublicKeyRaw(publicKey: Uint8Array): Promise<ArrayBuffer> {
  return toArrayBuffer(publicKey);
}

/**
 * Import a raw 32-byte public key. Validates the length so a malformed wire key
 * fails here with a clear error rather than deep inside a DH computation.
 *
 * @param publicKeyRaw - Raw 32-byte public key
 * @returns The public key as a `Uint8Array`
 */
export async function importPublicKeyRaw(publicKeyRaw: ArrayBuffer | Uint8Array): Promise<Uint8Array> {
  const bytes = publicKeyRaw instanceof Uint8Array ? publicKeyRaw : new Uint8Array(publicKeyRaw);
  if (bytes.byteLength !== 32) {
    throw new Error('Invalid X25519 public key: expected 32 bytes.');
  }
  return bytes;
}
