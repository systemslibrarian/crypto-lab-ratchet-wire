/**
 * HKDF (HMAC-based Key Derivation Function) using SHA-256
 * 
 * Reference: RFC 5869 - HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
 * https://tools.ietf.org/html/rfc5869
 * https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/deriveKey
 */

/**
 * HKDF-SHA256 key derivation.
 * 
 * Implements RFC 5869: Extract-and-Expand using HMAC-SHA256.
 * 
 * @param inputKey - Input key material (IKM) as ArrayBuffer
 * @param salt - Optional salt (if length 0, will be treated as empty)
 * @param info - Context and application specific information string
 * @param length - Desired output length in bytes (typically 32 for keys)
 * @returns Promise resolving to derived key material as ArrayBuffer
 * 
 * @example
 * const key = await hkdf(ikm, saltBuffer, 'myapp-context', 32);
 */
export async function hkdf(
  inputKey: ArrayBuffer,
  salt: ArrayBuffer,
  info: string,
  length: number
): Promise<ArrayBuffer> {
  if (!crypto?.subtle?.importKey || !crypto?.subtle?.deriveBits) {
    throw new Error('Web Crypto API not available for HKDF');
  }

  // Step 1: Extract phase using HMAC-SHA256
  // PRK = HMAC-Hash(salt, IKM)
  const prkKey = await crypto.subtle.importKey(
    'raw',
    salt,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const prk = await crypto.subtle.sign('HMAC', prkKey, inputKey);

  // Step 2: Expand phase
  // This is handled by the native HKDF support in deriveBits
  const expandKey = await crypto.subtle.importKey(
    'raw',
    prk,
    { name: 'HKDF' },
    false,
    ['deriveBits']
  );

  const infoEncoded = new TextEncoder().encode(info);

  const derivedKey = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: salt,
      info: infoEncoded,
    },
    expandKey,
    length * 8 // Convert bytes to bits
  );

  return derivedKey;
}

/**
 * Domain separation labels for the Double Ratchet Algorithm.
 * These ensure different cryptographic contexts use different key material.
 */
export const DOMAIN_LABELS = {
  ROOT: 'ratchet-wire-root',
  CHAIN: 'ratchet-wire-chain',
  MESSAGE: 'ratchet-wire-message',
} as const;
