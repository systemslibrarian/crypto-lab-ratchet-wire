/**
 * Tests for authenticated X3DH Session Initialization.
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

describe('Authenticated X3DH Session Initialization', () => {
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

  it('AUTHENTICATION: rejects a bundle whose signed pre-key signature is invalid', async () => {
    const forgedSig = bobBundle.signedPreKeySignature.slice(0);
    new Uint8Array(forgedSig)[0] ^= 0xff;
    const tampered: BobPrekeyBundle = { ...bobBundle, signedPreKeySignature: forgedSig };
    await expect(initiateSessionX3DH(aliceKeys, tampered)).rejects.toThrow(/signature|man-in-the-middle/i);
  });

  it('AUTHENTICATION: rejects a bundle whose signed pre-key was swapped (MITM)', async () => {
    // A man-in-the-middle substitutes their own pre-key but keeps Bob's identity
    // key and signature — the signature no longer matches the new pre-key.
    const attackerPreKey = await generateKeyPair();
    const tampered: BobPrekeyBundle = { ...bobBundle, signedPreKey: attackerPreKey.publicKey };
    await expect(initiateSessionX3DH(aliceKeys, tampered)).rejects.toThrow(/signature|man-in-the-middle/i);
  });

  it('AUTHENTICATION: rejects a bundle signed by the wrong identity key', async () => {
    const attackerIdentity = await generateSigningKeyPair();
    const tampered: BobPrekeyBundle = { ...bobBundle, identitySigningKey: attackerIdentity.publicKey };
    await expect(initiateSessionX3DH(aliceKeys, tampered)).rejects.toThrow(/signature|man-in-the-middle/i);
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
