/**
 * Tests for Simplified X3DH Session Initialization
 */

import { describe, it, expect, beforeEach } from 'vitest';
import {
  initiateSessionX3DH,
  acceptSessionX3DH,
  createAliceRatchetState,
  createBobRatchetState,
  AliceSessionInitKeys,
  BobPreSessionKeys,
} from '../crypto/session-init';
import { generateKeyPair, KeyPair } from '../crypto/x25519';
import { toHex } from './session-helper';

describe('Simplified X3DH Session Initialization', () => {
  let aliceKeys: AliceSessionInitKeys;
  let bobKeys: BobPreSessionKeys;
  let aliceRatchet: KeyPair;
  let bobRatchet: KeyPair;

  beforeEach(async () => {
    aliceKeys = {
      identityKeyPair: await generateKeyPair(),
      ephemeralKeyPair: await generateKeyPair(),
    };
    bobKeys = {
      identityKeyPair: await generateKeyPair(),
      signedPreKeyPair: await generateKeyPair(),
    };
    aliceRatchet = await generateKeyPair();
    bobRatchet = await generateKeyPair();
  });

  const aliceInitiate = () =>
    initiateSessionX3DH(aliceKeys, bobKeys.identityKeyPair.publicKey, bobKeys.signedPreKeyPair.publicKey);
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
    // X3DH must converge: each DH term commutes, so SK is identical.
    expect(toHex(aliceSession.rootKey)).toBe(toHex(bobSession.rootKey));
  });

  it('should produce different root keys for different ephemeral keys', async () => {
    const session1 = await aliceInitiate();

    aliceKeys = { ...aliceKeys, ephemeralKeyPair: await generateKeyPair() };
    const session2 = await aliceInitiate();

    expect(toHex(session1.rootKey)).not.toBe(toHex(session2.rootKey));
  });

  it('should initialize Alice as initiator (sending chain ready, no receiving chain)', async () => {
    const session = await aliceInitiate();
    const alice = await createAliceRatchetState(session, aliceRatchet, bobRatchet.publicKey);

    expect(alice.sendingChain).not.toBeNull();
    expect(alice.sendingChain!.chainKey.byteLength).toBe(32);
    expect(alice.receivingChain).toBeNull();
    expect(alice.theirDHPublicKey).toBe(bobRatchet.publicKey);
    expect(alice.dhRatchetCount).toBe(0);
  });

  it('should initialize Bob as responder (no chains, RK = SK, no DHr)', async () => {
    const session = await bobAccept();
    const bob = createBobRatchetState(session, bobRatchet);

    expect(bob.sendingChain).toBeNull();
    expect(bob.receivingChain).toBeNull();
    expect(bob.theirDHPublicKey).toBeNull();
    expect(toHex(bob.rootKey)).toBe(toHex(session.rootKey));
    expect(bob.myDHKeyPair).toBe(bobRatchet);
  });

  it("Alice's initial sending chain differs from Bob's bare root key", async () => {
    // Alice does a sending-half DH ratchet at init; Bob has not ratcheted yet.
    const aliceSession = await aliceInitiate();
    const bobSession = await bobAccept();
    const alice = await createAliceRatchetState(aliceSession, aliceRatchet, bobRatchet.publicKey);
    const bob = createBobRatchetState(bobSession, bobRatchet);

    expect(toHex(alice.sendingChain!.chainKey)).not.toBe(toHex(bob.rootKey));
  });
});
