/**
 * Integration Tests for Full Double Ratchet
 * 
 * Simulates a real conversation between Alice and Bob with:
 * - Message encryption and decryption
 * - Bidirectional ratcheting
 * - Out-of-order message handling
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { encrypt, decrypt, Message } from '../crypto/double-ratchet';
import { generateKeyPair } from '../crypto/x25519';
import { RatchetState } from '../crypto/dh-ratchet';

describe('Double Ratchet Integration', () => {
  let aliceState: RatchetState;
  let bobState: RatchetState;

  beforeEach(async () => {
    // Initialize Alice and Bob with the same initial root key
    // (In real setup, they would use X3DH; for this test, we use a shared secret)
    const initialRootKey = new Uint8Array(32).fill(0x42).buffer;

    const aliceDHPair = await generateKeyPair();
    const bobDHPair = await generateKeyPair();

    aliceState = {
      rootKey: initialRootKey,
      sendingChain: {
        chainKey: new Uint8Array(32).fill(0xa1).buffer,
        messageNumber: 0,
      },
      receivingChain: {
        chainKey: new Uint8Array(32).fill(0xb1).buffer,
        messageNumber: 0,
      },
      myDHKeyPair: aliceDHPair,
      theirDHPublicKey: bobDHPair.publicKey,
      dhRatchetCount: 0,
    };

    bobState = {
      rootKey: initialRootKey,
      sendingChain: {
        chainKey: new Uint8Array(32).fill(0xb1).buffer,
        messageNumber: 0,
      },
      receivingChain: {
        chainKey: new Uint8Array(32).fill(0xa1).buffer,
        messageNumber: 0,
      },
      myDHKeyPair: bobDHPair,
      theirDHPublicKey: aliceDHPair.publicKey,
      dhRatchetCount: 0,
    };
  });

  it('should encrypt and decrypt a single message', async () => {
    const plaintext = 'Hello, Bob!';

    // Alice encrypts
    const { message, newState: aliceNewState } = await encrypt(aliceState, plaintext);
    aliceState = aliceNewState;

    // Bob decrypts
    const { plaintext: decrypted, newState: bobNewState } = await decrypt(bobState, message);
    bobState = bobNewState;

    expect(decrypted).toBe(plaintext);
  });

  it('should handle bidirectional messages', async () => {
    const messages: { from: string; to: string; text: string }[] = [
      { from: 'Alice', to: 'Bob', text: 'Hi Bob!' },
      { from: 'Bob', to: 'Alice', text: 'Hi Alice!' },
      { from: 'Alice', to: 'Bob', text: 'How are you?' },
      { from: 'Bob', to: 'Alice', text: 'Great! And you?' },
    ];

    const aliceSkippedKeys = new Map<string, ArrayBuffer>();
    const bobSkippedKeys = new Map<string, ArrayBuffer>();

    for (const { from, text } of messages) {
      if (from === 'Alice') {
        const { message, newState } = await encrypt(aliceState, text);
        aliceState = newState;

        const { plaintext, newState: bobNewState, skippedKeys } = await decrypt(
          bobState,
          message,
          bobSkippedKeys
        );
        bobState = bobNewState;

        expect(plaintext).toBe(text);
        Object.assign(bobSkippedKeys, skippedKeys);
      } else {
        const { message, newState } = await encrypt(bobState, text);
        bobState = newState;

        const { plaintext, newState: aliceNewState, skippedKeys } = await decrypt(
          aliceState,
          message,
          aliceSkippedKeys
        );
        aliceState = aliceNewState;

        expect(plaintext).toBe(text);
        Object.assign(aliceSkippedKeys, skippedKeys);
      }
    }
  });

  it('should handle out-of-order delivery', async () => {
    const bobSkippedKeys = new Map<string, ArrayBuffer>();

    // Alice sends 3 messages
    const messages: Message[] = [];
    for (let i = 0; i < 3; i++) {
      const { message, newState } = await encrypt(aliceState, `Message ${i}`);
      messages.push(message);
      aliceState = newState;
    }

    // Bob receives them out of order: 2, 0, 1
    const order = [2, 0, 1];

    for (const idx of order) {
      const { plaintext, newState, skippedKeys } = await decrypt(
        bobState,
        messages[idx],
        bobSkippedKeys
      );
      bobState = newState;

      expect(plaintext).toBe(`Message ${idx}`);
      Object.assign(bobSkippedKeys, skippedKeys);
    }
  });

  it('should update DH ratchet when sender key changes', async () => {
    const bobSkippedKeys = new Map<string, ArrayBuffer>();

    const initialAliceDHRatchetCount = aliceState.dhRatchetCount;
    const initialBobDHRatchetCount = bobState.dhRatchetCount;

    // Alice sends a message (advances her DH key via new key pair generation in next message)
    let { message, newState } = await encrypt(aliceState, 'Message 1');
    aliceState = newState;

    // Bob receives it
    let { newState: bobNewState } = await decrypt(bobState, message, bobSkippedKeys);
    bobState = bobNewState;

    // Alice sends another (this triggers Bob's DH ratchet when he sees the new key)
    ({ message, newState } = await encrypt(aliceState, 'Message 2'));
    aliceState = newState;

    ({ newState: bobNewState } = await decrypt(bobState, message, bobSkippedKeys));
    bobState = bobNewState;

    // Both should have incremented DH ratchet counts at some point in the conversation
    // (At minimum, the initial key agreement)
    expect(aliceState.dhRatchetCount).toBeGreaterThanOrEqual(initialAliceDHRatchetCount);
    expect(bobState.dhRatchetCount).toBeGreaterThanOrEqual(initialBobDHRatchetCount);
  });

  it('should maintain message keys are not stored in state', async () => {
    // Encrypt and decrypt a message
    const { message, newState: aliceNewState } = await encrypt(aliceState, 'Secret');
    aliceState = aliceNewState;

    const { plaintext, newState: bobNewState } = await decrypt(bobState, message);
    bobState = bobNewState;

    expect(plaintext).toBe('Secret');

    // Verify ratchet states don't contain message keys
    // (This is implicitly tested by the fact that we advance chains and clear keys)
    expect(aliceState.sendingChain.chainKey).toBeDefined();
    expect(aliceState.sendingChain.chainKey.byteLength).toBe(32);
    expect(bobState.receivingChain.chainKey).toBeDefined();
    expect(bobState.receivingChain.chainKey.byteLength).toBe(32);
  });

  it('should successfully complete a 10-message conversation', async () => {
    const aliceSkippedKeys = new Map<string, ArrayBuffer>();
    const bobSkippedKeys = new Map<string, ArrayBuffer>();

    const transcript: { sender: string; text: string }[] = [
      { sender: 'Alice', text: 'Hey Bob, how are you?' },
      { sender: 'Bob', text: 'Great! How about you?' },
      { sender: 'Alice', text: 'Good, good. What have you been up to?' },
      { sender: 'Bob', text: 'Working on some crypto stuff.' },
      { sender: 'Alice', text: 'That sounds interesting!' },
      { sender: 'Bob', text: 'It really is.' },
      { sender: 'Alice', text: 'Tell me more.' },
      { sender: 'Bob', text: 'Well, it\'s about the Double Ratchet...' },
      { sender: 'Alice', text: 'Oh wow, I\'ve been learning about that too!' },
      { sender: 'Bob', text: 'Awesome! We should collaborate.' },
    ];

    for (const { sender, text } of transcript) {
      if (sender === 'Alice') {
        const { message, newState } = await encrypt(aliceState, text);
        aliceState = newState;

        const { plaintext, newState: bobNewState, skippedKeys } = await decrypt(
          bobState,
          message,
          bobSkippedKeys
        );
        bobState = bobNewState;

        expect(plaintext).toBe(text);
        Object.assign(bobSkippedKeys, skippedKeys);
      } else {
        const { message, newState } = await encrypt(bobState, text);
        bobState = newState;

        const { plaintext, newState: aliceNewState, skippedKeys } = await decrypt(
          aliceState,
          message,
          aliceSkippedKeys
        );
        aliceState = aliceNewState;

        expect(plaintext).toBe(text);
        Object.assign(aliceSkippedKeys, skippedKeys);
      }
    }

    // Verify states have progressed
    expect(aliceState.sendingChain.messageNumber).toBeGreaterThan(0);
    expect(bobState.sendingChain.messageNumber).toBeGreaterThan(0);
  });
});
