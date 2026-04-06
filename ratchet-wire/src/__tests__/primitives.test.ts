/**
 * Tests for cryptographic primitives: X25519 and HKDF
 * 
 * HKDF test vectors from RFC 5869 Appendix A.1
 */

import { describe, it, expect } from 'vitest';
import { generateKeyPair, deriveSharedSecret, exportPublicKeyRaw } from '../crypto/x25519';
import { hkdf, DOMAIN_LABELS } from '../crypto/hkdf';

describe('X25519 Key Exchange', () => {
  it('should generate a valid key pair', async () => {
    const keyPair = await generateKeyPair();
    expect(keyPair.publicKey).toBeDefined();
    expect(keyPair.privateKey).toBeDefined();
    expect(keyPair.publicKey.type).toBe('public');
    expect(keyPair.privateKey.type).toBe('private');
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

    const info = new Uint8Array([
      0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
      0xf8, 0xf9,
    ]);

    const infoStr = String.fromCharCode(...info);
    const L = 42;

    // Expected output from RFC 5869 Appendix A.1
    const expectedOkm = new Uint8Array([
      0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xcd, 0x58, 0x92,
      0x6e, 0x1f, 0xf5, 0xe6, 0x75, 0x06, 0x0b, 0x27,
      0x54, 0xd7, 0x7a, 0xff, 0xd3, 0xa6, 0x5d, 0xa2,
      0x2b, 0x3a, 0x5d, 0x64, 0x3d, 0x65, 0x70, 0xda,
      0xf2, 0x51, 0xb9, 0xc7, 0x7c, 0xf9, 0x7e, 0x62,
      0xf3, 0xc1,
    ]);

    const derived = await hkdf(ikm, salt, infoStr, L);
    const derivedArray = new Uint8Array(derived);

    expect(derivedArray).toEqual(expectedOkm);
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
