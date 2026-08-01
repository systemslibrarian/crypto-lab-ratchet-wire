/**
 * HKDF (HMAC-based Key Derivation Function) using SHA-256
 *
 * Reference: RFC 5869 - HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
 * https://tools.ietf.org/html/rfc5869
 * https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/deriveKey
 */

/**
 * HKDF-SHA256 key derivation (RFC 5869).
 *
 * The Web Crypto `HKDF` algorithm performs BOTH phases of RFC 5869 in a single
 * `deriveBits` call:
 *   1. Extract:  PRK = HMAC-SHA256(salt, IKM)
 *   2. Expand:   OKM = HKDF-Expand(PRK, info, L)
 *
 * The input key material is imported as the HKDF key; `salt` and `info` are
 * supplied as algorithm parameters. (A previous version of this file performed
 * the extract step by hand and then let Web Crypto extract a *second* time,
 * which produced output that did not match the RFC 5869 test vectors.)
 *
 * @param inputKey - Input key material (IKM)
 * @param salt - Salt (a zero-length salt is treated as all-zeros, per RFC 5869)
 * @param info - Context/application-specific info. A string is UTF-8 encoded;
 *   pass raw bytes (a BufferSource) when exact octets matter (e.g. test vectors).
 * @param length - Desired output length in bytes (typically 32)
 * @returns Derived key material (OKM) of `length` bytes
 *
 * @example
 * const key = await hkdf(ikm, saltBuffer, 'myapp-context', 32);
 */
export async function hkdf(
  inputKey: ArrayBuffer,
  salt: ArrayBuffer,
  info: string | BufferSource,
  length: number
): Promise<ArrayBuffer> {
  if (!crypto?.subtle?.importKey || !crypto?.subtle?.deriveBits) {
    throw new Error('Web Crypto API not available for HKDF');
  }

  const infoBytes = typeof info === 'string' ? new TextEncoder().encode(info) : info;

  // Import the IKM as an HKDF key. Web Crypto runs Extract-then-Expand internally.
  const ikmKey = await crypto.subtle.importKey(
    'raw',
    inputKey,
    { name: 'HKDF' },
    false,
    ['deriveBits']
  );

  const derivedKey = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt,
      info: infoBytes,
    },
    ikmKey,
    length * 8 // bytes -> bits
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

/**
 * KDF_RK — the root-key KDF of the Double Ratchet.
 *
 * Signal spec §3.1 ("External functions") states the contract: KDF_RK(rk,
 * dh_out) returns a 32-byte root key and a 32-byte chain key. §7.2
 * ("Recommended cryptographic algorithms") gives the instantiation followed
 * here — HKDF-SHA256 with rk as the salt, dh_out as the input key material,
 * an application-specific info string, and 64 bytes of output split in half.
 * (§7.2 was §5.2 before the spec gained its Sparse PQ Ratchet and Triple
 * Ratchet sections. Neither has ever been §3.3, which is "Initialization".)
 *
 * Derives a new root key and a new chain key from the current root key and a
 * fresh Diffie-Hellman output:
 *
 *   (RK', CK) = HKDF(salt = RK, IKM = dhOutput, info = "...", 64 bytes)
 *
 * Using the root key as the HKDF salt (and the DH output as the IKM) is what
 * lets both parties converge on the same RK'/CK: the DH output is identical on
 * both sides (it commutes), and they feed in the same RK.
 *
 * @param rootKey - Current 32-byte root key
 * @param dhOutput - 32-byte X25519 shared secret for this ratchet step
 * @returns The next root key and the new chain key (32 bytes each)
 */
export async function kdfRk(
  rootKey: ArrayBuffer,
  dhOutput: ArrayBuffer
): Promise<{ rootKey: ArrayBuffer; chainKey: ArrayBuffer }> {
  const material = await hkdf(dhOutput, rootKey, DOMAIN_LABELS.ROOT, 64);
  return {
    rootKey: material.slice(0, 32),
    chainKey: material.slice(32, 64),
  };
}
