/**
 * Tests for Ed25519 signatures (used to authenticate the X3DH handshake).
 */

import { describe, it, expect } from 'vitest';
import {
  generateSigningKeyPair,
  sign,
  verify,
  exportSigningPublicKeyRaw,
  importSigningPublicKeyRaw,
} from '../crypto/ed25519';

describe('Ed25519 signatures', () => {
  it('verifies a genuine signature', async () => {
    const keys = await generateSigningKeyPair();
    const msg = new TextEncoder().encode('authenticate me');
    const sig = await sign(keys.privateKey, msg);

    expect(sig.byteLength).toBe(64);
    expect(await verify(keys.publicKey, sig, msg)).toBe(true);
  });

  it('rejects a tampered message', async () => {
    const keys = await generateSigningKeyPair();
    const msg = new TextEncoder().encode('original');
    const sig = await sign(keys.privateKey, msg);

    const tampered = new TextEncoder().encode('originai');
    expect(await verify(keys.publicKey, sig, tampered)).toBe(false);
  });

  it('rejects a tampered signature', async () => {
    const keys = await generateSigningKeyPair();
    const msg = new TextEncoder().encode('hello');
    const sig = await sign(keys.privateKey, msg);

    const bad = sig.slice(0);
    new Uint8Array(bad)[0] ^= 0xff;
    expect(await verify(keys.publicKey, bad, msg)).toBe(false);
  });

  it('rejects a signature from a different key', async () => {
    const alice = await generateSigningKeyPair();
    const mallory = await generateSigningKeyPair();
    const msg = new TextEncoder().encode('from alice');
    const sig = await sign(alice.privateKey, msg);

    expect(await verify(mallory.publicKey, sig, msg)).toBe(false);
  });

  it('round-trips a public key through raw export/import (32 bytes)', async () => {
    const keys = await generateSigningKeyPair();
    const raw = await exportSigningPublicKeyRaw(keys.publicKey);
    expect(raw.byteLength).toBe(32);

    const reimported = await importSigningPublicKeyRaw(raw);
    const msg = new TextEncoder().encode('verify with reimported key');
    const sig = await sign(keys.privateKey, msg);
    expect(await verify(reimported, sig, msg)).toBe(true);
  });
});
