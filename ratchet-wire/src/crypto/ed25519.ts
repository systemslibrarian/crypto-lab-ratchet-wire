/**
 * Ed25519 Digital Signatures
 *
 * Reference: RFC 8032 - Edwards-Curve Digital Signature Algorithm (EdDSA)
 * https://tools.ietf.org/html/rfc8032
 *
 * Used to AUTHENTICATE the X3DH handshake: Bob signs his signed pre-key (SPK)
 * with his long-term Ed25519 identity key, and Alice verifies that signature
 * before deriving the session secret. Without this check a man-in-the-middle
 * could substitute their own pre-key and silently sit between the two parties.
 *
 * Implemented with the audited `@noble/curves` library rather than Web Crypto:
 * browser Web Crypto support for Ed25519 is very recent (Chrome 137, 2025) and
 * absent from many installed browsers, so using it would make the handshake
 * throw on load. `@noble` behaves identically in every browser and in Node.
 *
 * Note: production Signal uses XEdDSA, which lets a single Montgomery (X25519)
 * key do BOTH Diffie-Hellman and signing. We instead model the identity as a
 * dedicated Ed25519 signing key alongside the X25519 key used for DH. The
 * security property (the SPK is bound to a long-term identity the verifier can
 * pin) is the same, and it keeps the two roles legible for learners.
 */

import { ed25519 } from '@noble/curves/ed25519.js';
import { asUint8Array, toArrayBuffer } from './bytes';

/** An Ed25519 signing key pair (32-byte public + 32-byte secret). */
export interface SigningKeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

/**
 * Generate an Ed25519 signing key pair.
 *
 * @returns The public (verify) and private (sign) keys
 */
export async function generateSigningKeyPair(): Promise<SigningKeyPair> {
  const privateKey = ed25519.utils.randomSecretKey();
  const publicKey = ed25519.getPublicKey(privateKey);
  return { publicKey, privateKey };
}

/**
 * Sign a message with an Ed25519 private key.
 *
 * @param privateKey - The signer's Ed25519 private key
 * @param data - The bytes to sign
 * @returns A 64-byte Ed25519 signature
 */
export async function sign(privateKey: Uint8Array, data: BufferSource): Promise<ArrayBuffer> {
  return toArrayBuffer(ed25519.sign(asUint8Array(data), privateKey));
}

/**
 * Verify an Ed25519 signature.
 *
 * Returns a boolean rather than throwing, so callers decide how to react; a
 * malformed signature (e.g. wrong length) is treated as simply invalid.
 *
 * @param publicKey - The signer's Ed25519 public key
 * @param signature - The signature to check
 * @param data - The bytes that were supposedly signed
 * @returns true iff the signature is valid for `data` under `publicKey`
 */
export async function verify(
  publicKey: Uint8Array,
  signature: BufferSource,
  data: BufferSource
): Promise<boolean> {
  try {
    return ed25519.verify(asUint8Array(signature), asUint8Array(data), publicKey);
  } catch {
    return false;
  }
}

/**
 * Export an Ed25519 public key as raw bytes (32 bytes) for transmission.
 *
 * @param publicKey - The public key to export
 * @returns 32 raw bytes
 */
export async function exportSigningPublicKeyRaw(publicKey: Uint8Array): Promise<ArrayBuffer> {
  return toArrayBuffer(publicKey);
}

/**
 * Import a raw 32-byte Ed25519 public key, validating its length.
 *
 * @param publicKeyRaw - Raw 32-byte Ed25519 public key
 * @returns The public key as a `Uint8Array`
 */
export async function importSigningPublicKeyRaw(
  publicKeyRaw: ArrayBuffer | Uint8Array
): Promise<Uint8Array> {
  const bytes = publicKeyRaw instanceof Uint8Array ? publicKeyRaw : new Uint8Array(publicKeyRaw);
  if (bytes.byteLength !== 32) {
    throw new Error('Invalid Ed25519 public key: expected 32 bytes.');
  }
  return bytes;
}
