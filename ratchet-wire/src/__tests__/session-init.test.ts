/**
 * Tests for Simplified X3DH Session Initialization
 */

import { describe, it, expect } from 'vitest';
import {
  initiateSessionX3DH,
  acceptSessionX3DH,
  AliceSessionInitKeys,
  BobPreSessionKeys,
  createAliceRatchetState,
  createBobRatchetState,
} from '../crypto/session-init';
import { generateKeyPair } from '../crypto/x25519';

describe('Simplified X3DH Session Initialization', () => {
  let aliceSessionInitKeys: AliceSessionInitKeys;
  let bobPreSessionKeys: BobPreSessionKeys;
  let aliceDHKeyPair: { publicKey: CryptoKey; privateKey: CryptoKey };
  let bobDHKeyPair: { publicKey: CryptoKey; privateKey: CryptoKey };

  beforeEach(async () => {
    // Alice generates her keys
    aliceSessionInitKeys = {
      identityKeyPair: await generateKeyPair(),
      ephemeralKeyPair: await generateKeyPair(),
    };

    // Bob generates and publishes his keys
    bobPreSessionKeys = {
      identityKeyPair: await generateKeyPair(),
      signedPreKeyPair: await generateKeyPair(),
    };

    // Both generate their DH key pairs for the ratchet
    aliceDHKeyPair = await generateKeyPair();
    bobDHKeyPair = await generateKeyPair();
  });

  it('should generate a session root key', async () => {
    const sessionResult = await initiateSessionX3DH(
      aliceSessionInitKeys,
      bobPreSessionKeys.identityKeyPair.publicKey,
      bobPreSessionKeys.signedPreKeyPair.publicKey,
      aliceDHKeyPair,
      bobDHKeyPair
    );

    expect(sessionResult.rootKey).toBeInstanceOf(ArrayBuffer);
    expect(sessionResult.rootKey.byteLength).toBe(32);
  });

  it('should derive matching root key from Alice and Bob perspectives', async () => {
    // Alice initiates the session
    const aliceSessionResult = await initiateSessionX3DH(
      aliceSessionInitKeys,
      bobPreSessionKeys.identityKeyPair.publicKey,
      bobPreSessionKeys.signedPreKeyPair.publicKey,
      aliceDHKeyPair,
      bobDHKeyPair
    );

    // Bob accepts the session
    const bobSessionResult = await acceptSessionX3DH(
      bobPreSessionKeys,
      aliceSessionInitKeys.identityKeyPair.publicKey,
      aliceSessionInitKeys.ephemeralKeyPair.publicKey,
      aliceDHKeyPair,
      bobDHKeyPair
    );

    // Both should derive the same root key
    const aliceRootKeyArray = new Uint8Array(aliceSessionResult.rootKey);
    const bobRootKeyArray = new Uint8Array(bobSessionResult.rootKey);

    expect(aliceRootKeyArray).toEqual(bobRootKeyArray);
  });

  it('should create compatible Alice and Bob ratchet states', async () => {
    // Perform X3DH
    const sessionResult = await initiateSessionX3DH(
      aliceSessionInitKeys,
      bobPreSessionKeys.identityKeyPair.publicKey,
      bobPreSessionKeys.signedPreKeyPair.publicKey,
      aliceDHKeyPair,
      bobDHKeyPair
    );

    // Create ratchet states
    const aliceState = createAliceRatchetState(sessionResult);
    const bobState = createBobRatchetState(sessionResult);

    // Both should have the same root key
    expect(aliceState.rootKey).toEqual(bobState.rootKey);

    // Alice's sending chain should match Bob's receiving chain (for chain keys)
    expect(aliceState.initialChainKeyAlice).toEqual(bobState.initialChainKeyBob);
    // Bob's sending chain should match Alice's receiving chain
    expect(bobState.initialChainKeyBob).toEqual(aliceState.initialChainKeyAlice);
  });

  it('should produce different root keys for different ephemeral keys', async () => {
    // First session
    const session1 = await initiateSessionX3DH(
      aliceSessionInitKeys,
      bobPreSessionKeys.identityKeyPair.publicKey,
      bobPreSessionKeys.signedPreKeyPair.publicKey,
      aliceDHKeyPair,
      bobDHKeyPair
    );

    // Generate different ephemeral key
    const differentEphemeralKey = await generateKeyPair();
    const differentAliceSessionKeys: AliceSessionInitKeys = {
      identityKeyPair: aliceSessionInitKeys.identityKeyPair,
      ephemeralKeyPair: differentEphemeralKey,
    };

    // Second session with different ephemeral key
    const session2 = await initiateSessionX3DH(
      differentAliceSessionKeys,
      bobPreSessionKeys.identityKeyPair.publicKey,
      bobPreSessionKeys.signedPreKeyPair.publicKey,
      aliceDHKeyPair,
      bobDHKeyPair
    );

    const rootKey1 = new Uint8Array(session1.rootKey);
    const rootKey2 = new Uint8Array(session2.rootKey);

    // Different ephemeral keys should produce different root keys
    expect(rootKey1).not.toEqual(rootKey2);
  });

  it('should provide initial chain keys for both parties', async () => {
    const sessionResult = await initiateSessionX3DH(
      aliceSessionInitKeys,
      bobPreSessionKeys.identityKeyPair.publicKey,
      bobPreSessionKeys.signedPreKeyPair.publicKey,
      aliceDHKeyPair,
      bobDHKeyPair
    );

    // Both initial chain keys should be valid 32-byte values
    expect(sessionResult.initialChainKeyAlice).toBeInstanceOf(ArrayBuffer);
    expect(sessionResult.initialChainKeyAlice.byteLength).toBe(32);
    expect(sessionResult.initialChainKeyBob).toBeInstanceOf(ArrayBuffer);
    expect(sessionResult.initialChainKeyBob.byteLength).toBe(32);

    // They should be different
    const aliceChainKey = new Uint8Array(sessionResult.initialChainKeyAlice);
    const bobChainKey = new Uint8Array(sessionResult.initialChainKeyBob);
    expect(aliceChainKey).not.toEqual(bobChainKey);
  });
});
