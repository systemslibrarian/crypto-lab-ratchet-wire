/**
 * Tests for signed-prekey-checked X3DH session initialization.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import {
  createBobPrekeyBundle,
  initiateSessionX3DH,
  acceptSessionX3DH,
  createAliceRatchetState,
  createBobRatchetState,
  AliceSessionInitKeys,
  BobPreSessionKeys,
  BobPrekeyBundle,
} from '../crypto/session-init';
import { generateKeyPair, KeyPair } from '../crypto/x25519';
import { generateSigningKeyPair } from '../crypto/ed25519';
import { toHex } from './session-helper';

describe('Signed-prekey X3DH session initialization', () => {
  let aliceKeys: AliceSessionInitKeys;
  let bobKeys: BobPreSessionKeys;
  let bobBundle: BobPrekeyBundle;
  let aliceRatchet: KeyPair;

  beforeEach(async () => {
    aliceKeys = {
      identityKeyPair: await generateKeyPair(),
      ephemeralKeyPair: await generateKeyPair(),
    };
    bobKeys = {
      identityKeyPair: await generateKeyPair(),
      identitySigningKeyPair: await generateSigningKeyPair(),
      signedPreKeyPair: await generateKeyPair(),
      oneTimePreKeyPair: await generateKeyPair(),
    };
    bobBundle = await createBobPrekeyBundle(bobKeys);
    aliceRatchet = await generateKeyPair();
  });

  const aliceInitiate = () => initiateSessionX3DH(aliceKeys, bobBundle);
  const bobAccept = () =>
    acceptSessionX3DH(bobKeys, aliceKeys.identityKeyPair.publicKey, aliceKeys.ephemeralKeyPair.publicKey);

  it('should generate a 32-byte session root key', async () => {
    const session = await aliceInitiate();
    expect(session.rootKey).toBeInstanceOf(ArrayBuffer);
    expect(session.rootKey.byteLength).toBe(32);
  });

  it('should derive the SAME root key from Alice and Bob perspectives', async () => {
    const aliceSession = await aliceInitiate();
    const bobSession = await bobAccept();
    // X3DH must converge: each of the four DH terms commutes, so SK is identical.
    expect(toHex(aliceSession.rootKey)).toBe(toHex(bobSession.rootKey));
  });

  it('should produce different root keys for different ephemeral keys', async () => {
    const session1 = await aliceInitiate();
    aliceKeys = { ...aliceKeys, ephemeralKeyPair: await generateKeyPair() };
    const session2 = await aliceInitiate();
    expect(toHex(session1.rootKey)).not.toBe(toHex(session2.rootKey));
  });

  it('should produce different root keys for different one-time pre-keys (DH4 contributes)', async () => {
    const aliceSession1 = await aliceInitiate();
    const bobSession1 = await bobAccept();
    expect(toHex(aliceSession1.rootKey)).toBe(toHex(bobSession1.rootKey));

    // Swap only Bob's one-time pre-key; both sides must change and still agree.
    bobKeys = { ...bobKeys, oneTimePreKeyPair: await generateKeyPair() };
    bobBundle = await createBobPrekeyBundle(bobKeys);
    const aliceSession2 = await aliceInitiate();
    const bobSession2 = await bobAccept();

    expect(toHex(aliceSession2.rootKey)).toBe(toHex(bobSession2.rootKey));
    expect(toHex(aliceSession2.rootKey)).not.toBe(toHex(aliceSession1.rootKey));
  });

  it('SIGNED-PREKEY INTEGRITY: rejects an invalid signed pre-key signature', async () => {
    const forgedSig = bobBundle.signedPreKeySignature.slice(0);
    new Uint8Array(forgedSig)[0] ^= 0xff;
    const tampered: BobPrekeyBundle = { ...bobBundle, signedPreKeySignature: forgedSig };
    await expect(initiateSessionX3DH(aliceKeys, tampered)).rejects.toThrow(/signature|man-in-the-middle/i);
  });

  it('SIGNED-PREKEY INTEGRITY: rejects a changed pre-key under the original signature', async () => {
    // An attacker changes the pre-key but keeps the supplied identity key and
    // signature, so the signature no longer matches the pre-key.
    const attackerPreKey = await generateKeyPair();
    const tampered: BobPrekeyBundle = { ...bobBundle, signedPreKey: attackerPreKey.publicKey };
    await expect(initiateSessionX3DH(aliceKeys, tampered)).rejects.toThrow(/signature|man-in-the-middle/i);
  });

  it('SIGNED-PREKEY INTEGRITY: rejects a signature checked under a different supplied identity', async () => {
    const attackerIdentity = await generateSigningKeyPair();
    const tampered: BobPrekeyBundle = { ...bobBundle, identitySigningKey: attackerIdentity.publicKey };
    await expect(initiateSessionX3DH(aliceKeys, tampered)).rejects.toThrow(/signature|man-in-the-middle/i);
  });

  it('rejects malformed public bundle fields before signature or DH work', async () => {
    await expect(initiateSessionX3DH(aliceKeys, {
      ...bobBundle,
      signedPreKey: bobBundle.signedPreKey.slice(1),
    })).rejects.toThrow(/Malformed X3DH input.*32 bytes/);
    await expect(initiateSessionX3DH(aliceKeys, {
      ...bobBundle,
      signedPreKeySignature: new ArrayBuffer(63),
    })).rejects.toThrow(/Malformed X3DH input.*64 bytes/);
  });

  it('requires external identity verification: a fully substituted valid bundle is accepted', async () => {
    const attackerKeys: BobPreSessionKeys = {
      identityKeyPair: await generateKeyPair(),
      identitySigningKeyPair: await generateSigningKeyPair(),
      signedPreKeyPair: await generateKeyPair(),
      oneTimePreKeyPair: await generateKeyPair(),
    };
    const attackerBundle = await createBobPrekeyBundle(attackerKeys);

    expect(attackerBundle.identitySigningKey).not.toEqual(bobBundle.identitySigningKey);
    const aliceSession = await initiateSessionX3DH(aliceKeys, attackerBundle);
    const attackerSession = await acceptSessionX3DH(
      attackerKeys,
      aliceKeys.identityKeyPair.publicKey,
      aliceKeys.ephemeralKeyPair.publicKey,
    );
    expect(toHex(aliceSession.rootKey)).toBe(toHex(attackerSession.rootKey));
  });

  it('should initialize Alice as initiator (sending chain ready, no receiving chain)', async () => {
    const session = await aliceInitiate();
    const alice = await createAliceRatchetState(session, aliceRatchet, bobKeys.signedPreKeyPair.publicKey);

    expect(alice.sendingChain).not.toBeNull();
    expect(alice.sendingChain!.chainKey.byteLength).toBe(32);
    expect(alice.receivingChain).toBeNull();
    expect(alice.theirDHPublicKey).toBe(bobKeys.signedPreKeyPair.publicKey);
    expect(alice.dhRatchetCount).toBe(0);
  });

  it('should initialize Bob as responder (no chains, RK = SK, signed pre-key is his ratchet key)', async () => {
    const session = await bobAccept();
    const bob = createBobRatchetState(session, bobKeys.signedPreKeyPair);

    expect(bob.sendingChain).toBeNull();
    expect(bob.receivingChain).toBeNull();
    expect(bob.theirDHPublicKey).toBeNull();
    expect(toHex(bob.rootKey)).toBe(toHex(session.rootKey));
    expect(bob.myDHKeyPair).toBe(bobKeys.signedPreKeyPair);
  });

  it("Alice's initial sending chain differs from Bob's bare root key", async () => {
    const aliceSession = await aliceInitiate();
    const bobSession = await bobAccept();
    const alice = await createAliceRatchetState(aliceSession, aliceRatchet, bobKeys.signedPreKeyPair.publicKey);
    const bob = createBobRatchetState(bobSession, bobKeys.signedPreKeyPair);

    expect(toHex(alice.sendingChain!.chainKey)).not.toBe(toHex(bob.rootKey));
  });
});
