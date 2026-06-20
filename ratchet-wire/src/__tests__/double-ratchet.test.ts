/**
 * Integration tests for the full Double Ratchet.
 *
 * Exercises a real conversation between Alice and Bob, started from the
 * simplified X3DH session setup, covering bidirectional ratcheting, out-of-order
 * delivery, header authentication, and break-in recovery.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { encrypt, decrypt, Message, SkippedKeys } from '../crypto/double-ratchet';
import { RatchetState } from '../crypto/dh-ratchet';
import { establishSession, toHex } from './session-helper';

describe('Double Ratchet Integration', () => {
  let alice: RatchetState;
  let bob: RatchetState;
  let aliceSkipped: SkippedKeys;
  let bobSkipped: SkippedKeys;

  beforeEach(async () => {
    ({ aliceState: alice, bobState: bob } = await establishSession());
    aliceSkipped = new Map();
    bobSkipped = new Map();
  });

  /** Alice -> Bob: encrypt, deliver, decrypt; updates both states + skip maps. */
  async function aliceToBob(text: string): Promise<string> {
    const { message, newState } = await encrypt(alice, text);
    alice = newState;
    const r = await decrypt(bob, message, bobSkipped);
    bob = r.newState;
    bobSkipped = r.skippedKeys;
    return r.plaintext;
  }

  /** Bob -> Alice. */
  async function bobToAlice(text: string): Promise<string> {
    const { message, newState } = await encrypt(bob, text);
    bob = newState;
    const r = await decrypt(alice, message, aliceSkipped);
    alice = r.newState;
    aliceSkipped = r.skippedKeys;
    return r.plaintext;
  }

  it('encrypts and decrypts a single message; first receive triggers a DH ratchet', async () => {
    expect(await aliceToBob('Hello, Bob!')).toBe('Hello, Bob!');
    // Bob had no DHr; receiving Alice's first message performs his first ratchet.
    expect(bob.dhRatchetCount).toBe(1);
    expect(bob.receivingChain).not.toBeNull();
    expect(bob.sendingChain).not.toBeNull(); // Bob can now reply.
  });

  it('ping-pong increments the DH ratchet on every direction change', async () => {
    await aliceToBob('a'); // bob ratchets -> 1
    await bobToAlice('b'); // alice ratchets -> 1
    await aliceToBob('c'); // bob ratchets -> 2
    await bobToAlice('d'); // alice ratchets -> 2

    expect(bob.dhRatchetCount).toBe(2);
    expect(alice.dhRatchetCount).toBe(2);
  });

  it('handles a multi-message same-direction run (one DH ratchet, symmetric steps)', async () => {
    await aliceToBob('1');
    expect(await aliceToBob('2')).toBe('2');
    expect(await aliceToBob('3')).toBe('3');
    // Alice never changed her ratchet key, so Bob ratcheted only once.
    expect(bob.dhRatchetCount).toBe(1);
    expect(bob.receivingChain!.messageNumber).toBe(3);
  });

  it('handles out-of-order delivery via skipped message keys', async () => {
    const messages: Message[] = [];
    for (let i = 0; i < 3; i++) {
      const { message, newState } = await encrypt(alice, `Message ${i}`);
      messages.push(message);
      alice = newState;
    }

    for (const idx of [2, 0, 1]) {
      const r = await decrypt(bob, messages[idx], bobSkipped);
      bob = r.newState;
      bobSkipped = r.skippedKeys;
      expect(r.plaintext).toBe(`Message ${idx}`);
    }
  });

  it('rejects a message whose header has been tampered with (AEAD binds the header)', async () => {
    const { message } = await encrypt(alice, 'authentic');
    const forged: Message = {
      ...message,
      header: { ...message.header, messageNumber: message.header.messageNumber + 7 },
    };
    await expect(decrypt(bob, forged, bobSkipped)).rejects.toBeDefined();
  });

  it('a failed (forged) message does not corrupt the receiver state', async () => {
    // Encrypt a genuine first message (which would trigger Bob's first DH
    // ratchet on receipt), then forge a copy whose header is tampered so AEAD
    // fails *after* the ratchet has run. Decrypt must leave Bob untouched, so
    // the genuine message still decrypts afterward.
    const { message } = await encrypt(alice, 'genuine');
    const forged: Message = {
      ...message,
      header: { ...message.header, messageNumber: message.header.messageNumber + 7 },
    };

    await expect(decrypt(bob, forged, bobSkipped)).rejects.toBeDefined();

    // Bob's state must be intact: the genuine message decrypts cleanly.
    const r = await decrypt(bob, message, bobSkipped);
    expect(r.plaintext).toBe('genuine');
  });

  it('refuses a header that would skip an excessive number of message keys (DoS guard)', async () => {
    // The header is not authenticated until AEAD runs at the target key, so a
    // forged, oversized messageNumber must be rejected up front rather than
    // driving thousands of KDF iterations.
    const { message } = await encrypt(alice, 'hi');
    const forged: Message = {
      ...message,
      header: { ...message.header, messageNumber: 50_000 },
    };
    await expect(decrypt(bob, forged, bobSkipped)).rejects.toThrow(/skip/i);
  });

  it('rejects a malformed header (negative / fractional / NaN message number)', async () => {
    const { message } = await encrypt(alice, 'hi');
    for (const bad of [-1, 1.5, NaN]) {
      const forged: Message = {
        ...message,
        header: { ...message.header, messageNumber: bad },
      };
      await expect(decrypt(bob, forged, bobSkipped)).rejects.toThrow(/header/i);
    }
  });

  it('skipped-key fast path does not zero a buffer the caller still holds', async () => {
    // Encrypt two messages; deliver the second first so Bob stores the first
    // message's key as a skipped key.
    const msgs: Message[] = [];
    for (let i = 0; i < 2; i++) {
      const { message, newState } = await encrypt(alice, `m${i}`);
      msgs.push(message);
      alice = newState;
    }
    let r = await decrypt(bob, msgs[1], bobSkipped);
    bob = r.newState;
    const retainedMap = r.skippedKeys; // caller keeps this reference
    const skippedId = [...retainedMap.keys()][0];
    const retainedBuf = retainedMap.get(skippedId)!;

    // Consume the straggler via the skipped key (returns a fresh map).
    r = await decrypt(bob, msgs[0], retainedMap);
    expect(r.plaintext).toBe('m0');

    // The retained map's buffer must NOT have been zeroed in place.
    expect(new Uint8Array(retainedBuf).some((b) => b !== 0)).toBe(true);
  });

  it('does not mutate the caller\'s state or skipped-key map', async () => {
    const { message } = await encrypt(alice, 'immutability');
    const bobBefore = bob;
    const skippedBefore = bobSkipped;

    const r = await decrypt(bob, message, bobSkipped);

    expect(bob).toBe(bobBefore); // same reference, untouched
    expect(bobSkipped).toBe(skippedBefore);
    expect(r.newState).not.toBe(bobBefore);
    expect(bob.receivingChain).toBeNull(); // original Bob still un-ratcheted
  });

  it('demonstrates genuine break-in recovery (root key changes to one the attacker cannot derive)', async () => {
    // Warm up so the last move was Bob -> Alice, leaving Alice with a fresh
    // ratchet key that Bob has not yet seen.
    await aliceToBob('hi');
    await bobToAlice('hey');

    // Attacker compromises Bob: snapshot his current root key + ratchet count.
    const compromisedRootKey = toHex(bob.rootKey);
    const compromisedCount = bob.dhRatchetCount;

    // The conversation simply continues: Alice sends, carrying her fresh key.
    // Bob's receipt performs a DH ratchet with key material generated after the
    // compromise, which the attacker (holding only the snapshot) cannot derive.
    expect(await aliceToBob('post-compromise message')).toBe('post-compromise message');

    expect(bob.dhRatchetCount).toBe(compromisedCount + 1);
    expect(toHex(bob.rootKey)).not.toBe(compromisedRootKey);
  });

  it('completes a 10-message bidirectional conversation', async () => {
    const transcript: { from: 'A' | 'B'; text: string }[] = [
      { from: 'A', text: 'Hey Bob, how are you?' },
      { from: 'B', text: 'Great! How about you?' },
      { from: 'A', text: 'Good. What have you been up to?' },
      { from: 'B', text: 'Working on some crypto stuff.' },
      { from: 'A', text: 'That sounds interesting!' },
      { from: 'B', text: 'It really is.' },
      { from: 'A', text: 'Tell me more.' },
      { from: 'B', text: "It's about the Double Ratchet..." },
      { from: 'A', text: "I've been learning about that too!" },
      { from: 'B', text: 'Awesome! We should collaborate.' },
    ];

    for (const { from, text } of transcript) {
      const got = from === 'A' ? await aliceToBob(text) : await bobToAlice(text);
      expect(got).toBe(text);
    }

    // Each direction change drives a DH ratchet; after a 10-message ping-pong
    // both sides have ratcheted several times. (messageNumber resets to 0 on
    // each ratchet, so it is not a meaningful end-state assertion here.)
    expect(alice.dhRatchetCount).toBeGreaterThan(0);
    expect(bob.dhRatchetCount).toBeGreaterThan(0);
    expect(alice.sendingChain).not.toBeNull();
    expect(bob.sendingChain).not.toBeNull();
  });
});
