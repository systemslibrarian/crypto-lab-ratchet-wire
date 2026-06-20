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
 * Note: production Signal uses XEdDSA, which lets a single Montgomery (X25519)
 * key do BOTH Diffie-Hellman and signing. The Web Crypto API does not expose
 * XEdDSA, so we model the identity as a dedicated Ed25519 signing key alongside
 * the X25519 key used for DH. The security property (the SPK is bound to a
 * long-term identity the verifier can pin) is the same.
 */

/** The Web Crypto algorithm identifier for Ed25519 signatures. */
const ED25519_ALG = { name: 'Ed25519' } as const;

/** An Ed25519 signing key pair. */
export interface SigningKeyPair {
  publicKey: CryptoKey;
  privateKey: CryptoKey;
}

/**
 * Generate an Ed25519 signing key pair.
 *
 * @returns The public (verify) and private (sign) CryptoKeys
 * @throws Error if Web Crypto / Ed25519 is unavailable
 */
export async function generateSigningKeyPair(): Promise<SigningKeyPair> {
  if (!globalThis.crypto?.subtle?.generateKey) {
    throw new Error('Web Crypto API not available in this environment');
  }

  const keyPair = (await crypto.subtle.generateKey(ED25519_ALG, true, [
    'sign',
    'verify',
  ])) as CryptoKeyPair;

  return { publicKey: keyPair.publicKey, privateKey: keyPair.privateKey };
}

/**
 * Sign a message with an Ed25519 private key.
 *
 * @param privateKey - The signer's Ed25519 private key
 * @param data - The bytes to sign
 * @returns A 64-byte Ed25519 signature
 */
export async function sign(privateKey: CryptoKey, data: BufferSource): Promise<ArrayBuffer> {
  if (!crypto?.subtle?.sign) {
    throw new Error('Web Crypto API sign not available');
  }
  return crypto.subtle.sign(ED25519_ALG, privateKey, data);
}

/**
 * Verify an Ed25519 signature.
 *
 * Returns a boolean rather than throwing on a bad signature, so callers decide
 * how to react. (Web Crypto's verify is already designed to run in roughly
 * constant time with respect to the signature contents.)
 *
 * @param publicKey - The signer's Ed25519 public key
 * @param signature - The signature to check
 * @param data - The bytes that were supposedly signed
 * @returns true iff the signature is valid for `data` under `publicKey`
 */
export async function verify(
  publicKey: CryptoKey,
  signature: BufferSource,
  data: BufferSource
): Promise<boolean> {
  if (!crypto?.subtle?.verify) {
    throw new Error('Web Crypto API verify not available');
  }
  return crypto.subtle.verify(ED25519_ALG, publicKey, signature, data);
}

/**
 * Export an Ed25519 public key as raw bytes (32 bytes) for transmission.
 *
 * @param publicKey - The public key to export
 * @returns 32 raw bytes
 */
export async function exportSigningPublicKeyRaw(publicKey: CryptoKey): Promise<ArrayBuffer> {
  if (!crypto?.subtle?.exportKey) {
    throw new Error('Web Crypto API exportKey not available');
  }
  return crypto.subtle.exportKey('raw', publicKey);
}

/**
 * Import a raw 32-byte Ed25519 public key back into a CryptoKey.
 *
 * @param publicKeyRaw - Raw 32-byte Ed25519 public key
 * @returns The imported public CryptoKey (usable only for `verify`)
 */
export async function importSigningPublicKeyRaw(publicKeyRaw: BufferSource): Promise<CryptoKey> {
  if (!crypto?.subtle?.importKey) {
    throw new Error('Web Crypto API importKey not available');
  }
  return crypto.subtle.importKey('raw', publicKeyRaw, ED25519_ALG, true, ['verify']);
}
