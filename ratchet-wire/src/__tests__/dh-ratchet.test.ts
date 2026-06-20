/**
 * Tests for the DH Ratchet (root key chain)
 */

import { describe, it, expect } from 'vitest';
import { dhRatchet, RatchetState } from '../crypto/dh-ratchet';
import { generateKeyPair, deriveSharedSecret, KeyPair } from '../crypto/x25519';
import { kdfRk } from '../crypto/hkdf';
import { toHex } from './session-helper';

/** Build a minimal ratchet state with a fresh copy of the given root key. */
function stateWith(rootByte: number, myDHKeyPair: KeyPair, theirDHPublicKey: Uint8Array): RatchetState {
  return {
    rootKey: new Uint8Array(32).fill(rootByte).buffer,
    myDHKeyPair,
    theirDHPublicKey,
    sendingChain: { chainKey: new Uint8Array(32).fill(0x11).buffer, messageNumber: 3 },
    receivingChain: { chainKey: new Uint8Array(32).fill(0x22).buffer, messageNumber: 0 },
    previousSendingChainLength: 0,
    dhRatchetCount: 0,
  };
}

describe('DH Ratchet (root key chain)', () => {
  it('changes the root key and resets chains on a ratchet step', async () => {
    const myPair = await generateKeyPair();
    const theirPair = await generateKeyPair();
    const state = stateWith(0x42, myPair, theirPair.publicKey);
    const before = new Uint8Array(state.rootKey).join(',');

    const next = await dhRatchet(state, (await generateKeyPair()).publicKey);

    expect(new Uint8Array(next.rootKey).join(',')).not.toBe(before);
    expect(next.dhRatchetCount).toBe(1);
    expect(next.sendingChain!.messageNumber).toBe(0);
    expect(next.receivingChain!.messageNumber).toBe(0);
    // PN captured from the old sending chain.
    expect(next.previousSendingChainLength).toBe(3);
  });

  it('rotates to a fresh DH key pair on each step', async () => {
    const myPair = await generateKeyPair();
    const theirPair = await generateKeyPair();
    const state = stateWith(0x42, myPair, theirPair.publicKey);

    const next = await dhRatchet(state, (await generateKeyPair()).publicKey);
    expect(next.myDHKeyPair).not.toBe(myPair);
  });

  it('successive steps produce distinct root keys and increment the count', async () => {
    let state = stateWith(0x55, await generateKeyPair(), (await generateKeyPair()).publicKey);
    const seen = new Set<string>([toHex(state.rootKey)]);

    for (let i = 1; i <= 5; i++) {
      state = await dhRatchet(state, (await generateKeyPair()).publicKey);
      expect(seen.has(toHex(state.rootKey))).toBe(false);
      seen.add(toHex(state.rootKey));
      expect(state.dhRatchetCount).toBe(i);
    }
  });

  it('CONVERGES: receiver\'s new receiving chain equals sender\'s sending chain', async () => {
    // Both parties hold the same root key; Bob's current ratchet key is `bobPair`.
    const sharedRoot = new Uint8Array(32).fill(0x42).buffer;
    const aliceNewPair = await generateKeyPair(); // Alice's fresh ratchet key
    const bobPair = await generateKeyPair();

    // Sender side: Alice derives her new sending chain from DH(aliceNew, bobPub).
    const aliceSendChain = (
      await kdfRk(
        sharedRoot.slice(0),
        await deriveSharedSecret(aliceNewPair.privateKey, bobPair.publicKey)
      )
    ).chainKey;

    // Receiver side: Bob performs a full DH ratchet against Alice's new public key.
    const bob = stateWith(0x42, bobPair, (await generateKeyPair()).publicKey);
    const bobNext = await dhRatchet(bob, aliceNewPair.publicKey);

    // Bob's receiving half must reconstruct Alice's sending chain exactly
    // (X25519 commutes and both sides feed in the same root key).
    expect(toHex(bobNext.receivingChain!.chainKey)).toBe(toHex(aliceSendChain));
  });

  it('does not mutate the caller\'s input state (root key buffer is left intact)', async () => {
    const state = stateWith(0x42, await generateKeyPair(), (await generateKeyPair()).publicKey);
    const oldRootRef = state.rootKey;
    const before = new Uint8Array(oldRootRef).join(',');

    await dhRatchet(state, (await generateKeyPair()).publicKey);

    // The input buffer must be preserved: decrypt() relies on this so a forged
    // message that fails AEAD *after* triggering a ratchet cannot corrupt the
    // receiver's session by zeroing its root key.
    expect(new Uint8Array(oldRootRef).join(',')).toBe(before);
  });
});
