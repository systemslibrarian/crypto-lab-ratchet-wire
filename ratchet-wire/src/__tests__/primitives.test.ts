/**
 * Tests for cryptographic primitives: X25519 and HKDF
 * 
 * HKDF test vectors from RFC 5869 Appendix A.1
 */

import { describe, it, expect } from 'vitest';
import {
  generateKeyPair,
  deriveSharedSecret,
  exportPublicKeyRaw,
  importPublicKeyRaw,
} from '../crypto/x25519';
import { hkdf, DOMAIN_LABELS } from '../crypto/hkdf';

describe('X25519 Key Exchange', () => {
  it('should generate a valid key pair (32-byte public and private keys)', async () => {
    const keyPair = await generateKeyPair();
    expect(keyPair.publicKey).toBeInstanceOf(Uint8Array);
    expect(keyPair.privateKey).toBeInstanceOf(Uint8Array);
    expect(keyPair.publicKey.byteLength).toBe(32);
    expect(keyPair.privateKey.byteLength).toBe(32);
  });

  it('should derive matching shared secrets between Alice and Bob', async () => {
    const aliceKeyPair = await generateKeyPair();
    const bobKeyPair = await generateKeyPair();

    // Alice derives shared secret using her private key and Bob's public key
    const aliceSharedSecret = await deriveSharedSecret(
      aliceKeyPair.privateKey,
      bobKeyPair.publicKey
    );

    // Bob derives shared secret using his private key and Alice's public key
    const bobSharedSecret = await deriveSharedSecret(
      bobKeyPair.privateKey,
      aliceKeyPair.publicKey
    );

    // Both should derive the same shared secret
    expect(aliceSharedSecret).toEqual(bobSharedSecret);
  });

  it('should export public keys as 32-byte raw format', async () => {
    const keyPair = await generateKeyPair();
    const rawPublicKey = await exportPublicKeyRaw(keyPair.publicKey);
    expect(rawPublicKey).toBeInstanceOf(ArrayBuffer);
    expect(rawPublicKey.byteLength).toBe(32);
  });

  it('should reject a low-order (all-zero) peer public key', async () => {
    // An all-zero u-coordinate is a low-order point that forces a zero shared
    // secret. deriveSharedSecret must reject it (our explicit guard, and most
    // runtimes also refuse at the deriveBits layer — either way it throws).
    const me = await generateKeyPair();
    const lowOrder = await importPublicKeyRaw(new Uint8Array(32).buffer);
    await expect(deriveSharedSecret(me.privateKey, lowOrder)).rejects.toThrow();
  });
});

describe('HKDF-SHA256', () => {
  it('should derive deterministic output from known inputs', async () => {
    // Test vectors from RFC 5869 Appendix A.1
    // SHA-256 case
    const ikm = new Uint8Array([
      0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
      0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
      0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    ]).buffer;

    const salt = new Uint8Array([
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
      0x08, 0x09, 0x0a, 0x0b, 0x0c,
    ]).buffer;

    // Raw info bytes (not a string — these octets must not be UTF-8 expanded).
    const info = new Uint8Array([
      0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
      0xf8, 0xf9,
    ]);

    const L = 42;

    // Expected output (OKM) from RFC 5869 Appendix A.1 (verified against the spec)
    const expectedOkm = new Uint8Array([
      0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a,
      0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
      0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
      0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
      0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
      0x58, 0x65,
    ]);

    const derived = await hkdf(ikm, salt, info, L);
    const derivedArray = new Uint8Array(derived);

    expect(derivedArray).toEqual(expectedOkm);
  });

  it('matches RFC 5869 test vector A.2 (longer IKM/salt/info, L=82)', async () => {
    const range = (start: number, count: number) =>
      Uint8Array.from({ length: count }, (_, i) => (start + i) & 0xff);

    const ikm = range(0x00, 80).buffer; // 0x00..0x4f
    const salt = range(0x60, 80).buffer; // 0x60..0xaf
    const info = range(0xb0, 80); // 0xb0..0xff
    const L = 82;

    // Expected OKM from RFC 5869 Appendix A.2.
    const expectedOkm = new Uint8Array([
      0xb1, 0x1e, 0x39, 0x8d, 0xc8, 0x03, 0x27, 0xa1, 0xc8, 0xe7, 0xf7, 0x8c, 0x59, 0x6a, 0x49,
      0x34, 0x4f, 0x01, 0x2e, 0xda, 0x2d, 0x4e, 0xfa, 0xd8, 0xa0, 0x50, 0xcc, 0x4c, 0x19, 0xaf,
      0xa9, 0x7c, 0x59, 0x04, 0x5a, 0x99, 0xca, 0xc7, 0x82, 0x72, 0x71, 0xcb, 0x41, 0xc6, 0x5e,
      0x59, 0x0e, 0x09, 0xda, 0x32, 0x75, 0x60, 0x0c, 0x2f, 0x09, 0xb8, 0x36, 0x77, 0x93, 0xa9,
      0xac, 0xa3, 0xdb, 0x71, 0xcc, 0x30, 0xc5, 0x81, 0x79, 0xec, 0x3e, 0x87, 0xc1, 0x4c, 0x01,
      0xd5, 0xc1, 0xf3, 0x43, 0x4f, 0x1d, 0x87,
    ]);

    const derived = new Uint8Array(await hkdf(ikm, salt, info, L));
    expect(derived).toEqual(expectedOkm);
  });

  it('should produce different outputs for different domain labels', async () => {
    const ikm = new Uint8Array(32).fill(0x42).buffer;
    const salt = new Uint8Array(32).fill(0xff).buffer;

    const rootKey = await hkdf(ikm, salt, DOMAIN_LABELS.ROOT, 32);
    const chainKey = await hkdf(ikm, salt, DOMAIN_LABELS.CHAIN, 32);
    const messageKey = await hkdf(ikm, salt, DOMAIN_LABELS.MESSAGE, 32);

    const rootArray = new Uint8Array(rootKey);
    const chainArray = new Uint8Array(chainKey);
    const messageArray = new Uint8Array(messageKey);

    expect(rootArray).not.toEqual(chainArray);
    expect(rootArray).not.toEqual(messageArray);
    expect(chainArray).not.toEqual(messageArray);
  });

  it('should be deterministic for identical inputs', async () => {
    const ikm = new Uint8Array(32).fill(0xaa).buffer;
    const salt = new Uint8Array(32).fill(0xbb).buffer;
    const info = 'test-context';

    const result1 = await hkdf(ikm, salt, info, 32);
    const result2 = await hkdf(ikm, salt, info, 32);

    expect(result1).toEqual(result2);
  });
});
