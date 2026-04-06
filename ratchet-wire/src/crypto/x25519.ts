/**
 * X25519 Elliptic Curve Diffie-Hellman (ECDH)
 * 
 * Reference: RFC 7748 - Elliptic Curves for Security
 * https://tools.ietf.org/html/rfc7748
 * https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/deriveKey
 */

/**
 * Generate an X25519 key pair.
 * 
 * @returns Promise resolving to an object with publicKey and privateKey (both CryptoKey)
 * @throws Error if Web Crypto API does not support X25519
 */
export async function generateKeyPair(): Promise<{
  publicKey: CryptoKey;
  privateKey: CryptoKey;
}> {
  // Check browser support
  if (!globalThis.crypto?.subtle?.generateKey) {
    throw new Error('Web Crypto API not available in this environment');
  }

  const keyPair = await crypto.subtle.generateKey(
    {
      name: 'ECDH',
      namedCurve: 'X25519',
    },
    true, // extractable
    ['deriveKey', 'deriveBits']
  );

  return {
    publicKey: keyPair.publicKey,
    privateKey: keyPair.privateKey,
  };
}

/**
 * Compute the shared secret from a private key and peer's public key.
 * 
 * @param privateKey - Our private key (CryptoKey)
 * @param publicKey - Peer's public key (CryptoKey)
 * @returns Promise resolving to the shared secret as ArrayBuffer
 */
export async function deriveSharedSecret(
  privateKey: CryptoKey,
  publicKey: CryptoKey
): Promise<ArrayBuffer> {
  if (!crypto?.subtle?.deriveBits) {
    throw new Error('Web Crypto API deriveBits not available');
  }

  const sharedSecret = await crypto.subtle.deriveBits(
    {
      name: 'ECDH',
      public: publicKey,
    },
    privateKey,
    256 // X25519 produces 256 bits (32 bytes)
  );

  return sharedSecret;
}

/**
 * Export a public key as raw bytes (32 bytes for X25519).
 * Useful for transmission over the wire.
 * 
 * @param publicKey - The public key to export
 * @returns Promise resolving to ArrayBuffer of 32 bytes
 */
export async function exportPublicKeyRaw(publicKey: CryptoKey): Promise<ArrayBuffer> {
  if (!crypto?.subtle?.exportKey) {
    throw new Error('Web Crypto API exportKey not available');
  }

  return crypto.subtle.exportKey('raw', publicKey);
}

/**
 * Import a raw public key (32 bytes) back into a CryptoKey.
 * 
 * @param publicKeyRaw - Raw 32-byte public key
 * @returns Promise resolving to CryptoKey
 */
export async function importPublicKeyRaw(publicKeyRaw: ArrayBuffer): Promise<CryptoKey> {
  if (!crypto?.subtle?.importKey) {
    throw new Error('Web Crypto API importKey not available');
  }

  return crypto.subtle.importKey(
    'raw',
    publicKeyRaw,
    {
      name: 'ECDH',
      namedCurve: 'X25519',
    },
    true, // extractable
    [] // no_usages for public key
  );
}
