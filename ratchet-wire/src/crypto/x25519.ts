/**
 * X25519 Elliptic Curve Diffie-Hellman
 *
 * Reference: RFC 7748 - Elliptic Curves for Security
 * https://tools.ietf.org/html/rfc7748
 * https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/deriveKey
 *
 * Uses the standard Web Crypto `X25519` algorithm (a dedicated key-agreement
 * algorithm in the W3C spec), supported by modern browsers and Node's
 * `crypto.webcrypto`. Note: this is NOT the same as `ECDH` with
 * `namedCurve: 'X25519'`, a non-standard form some older Chromium builds
 * accepted but which is unrecognized elsewhere.
 */

/** The Web Crypto algorithm identifier for X25519 key agreement. */
const X25519_ALG = { name: 'X25519' } as const;

export interface KeyPair {
  publicKey: CryptoKey;
  privateKey: CryptoKey;
}

/**
 * Generate an X25519 key pair.
 *
 * @returns The public and private CryptoKeys
 * @throws Error if Web Crypto / X25519 is unavailable
 */
export async function generateKeyPair(): Promise<KeyPair> {
  if (!globalThis.crypto?.subtle?.generateKey) {
    throw new Error('Web Crypto API not available in this environment');
  }

  const keyPair = (await crypto.subtle.generateKey(
    X25519_ALG,
    true, // extractable (so public keys can be exported for the wire)
    ['deriveBits']
  )) as CryptoKeyPair;

  return {
    publicKey: keyPair.publicKey,
    privateKey: keyPair.privateKey,
  };
}

/**
 * Compute the X25519 shared secret from our private key and a peer's public key.
 *
 * @param privateKey - Our private key
 * @param publicKey - Peer's public key
 * @returns The 32-byte shared secret
 */
export async function deriveSharedSecret(
  privateKey: CryptoKey,
  publicKey: CryptoKey
): Promise<ArrayBuffer> {
  if (!crypto?.subtle?.deriveBits) {
    throw new Error('Web Crypto API deriveBits not available');
  }

  return crypto.subtle.deriveBits(
    { name: 'X25519', public: publicKey },
    privateKey,
    256 // X25519 produces 256 bits (32 bytes)
  );
}

/**
 * Export a public key as raw bytes (32 bytes for X25519) for transmission.
 *
 * @param publicKey - The public key to export
 * @returns 32 raw bytes
 */
export async function exportPublicKeyRaw(publicKey: CryptoKey): Promise<ArrayBuffer> {
  if (!crypto?.subtle?.exportKey) {
    throw new Error('Web Crypto API exportKey not available');
  }

  return crypto.subtle.exportKey('raw', publicKey);
}

/**
 * Import a raw 32-byte public key back into a CryptoKey.
 *
 * @param publicKeyRaw - Raw 32-byte public key
 * @returns The imported public CryptoKey
 */
export async function importPublicKeyRaw(publicKeyRaw: ArrayBuffer): Promise<CryptoKey> {
  if (!crypto?.subtle?.importKey) {
    throw new Error('Web Crypto API importKey not available');
  }

  return crypto.subtle.importKey(
    'raw',
    publicKeyRaw,
    X25519_ALG,
    true, // extractable
    [] // public keys carry no usages
  );
}
