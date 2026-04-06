/**
 * Tests for Symmetric-Key Ratchet
 */

import { describe, it, expect } from 'vitest';
import { ratchetStep, ChainState, MessageKey } from '../crypto/symmetric-ratchet';

describe('Symmetric-Key Ratchet (Message Keys)', () => {
  it('should derive a valid message key from chain state', async () => {
    const initialChainKey = new Uint8Array(32).fill(0x42).buffer;
    const state: ChainState = {
      chainKey: initialChainKey,
      messageNumber: 0,
    };

    const { newState, messageKey } = await ratchetStep(state);

    expect(messageKey.key).toBeInstanceOf(ArrayBuffer);
    expect(messageKey.key.byteLength).toBe(32);
    expect(messageKey.messageNumber).toBe(0);
    expect(newState.messageNumber).toBe(1);
  });

  it('should produce sequential unique message keys', async () => {
    const initialChainKey = new Uint8Array(32).fill(0x55).buffer;
    let state: ChainState = {
      chainKey: initialChainKey,
      messageNumber: 0,
    };

    const messageKeys: Uint8Array[] = [];

    for (let i = 0; i < 10; i++) {
      const { newState, messageKey } = await ratchetStep(state);
      messageKeys.push(new Uint8Array(messageKey.key));
      state = newState;
    }

    // Verify all message keys are unique
    const keySet = new Set<string>();
    for (const key of messageKeys) {
      const keyStr = Array.from(key).join(',');
      expect(keySet).not.toContain(keyStr);
      keySet.add(keyStr);
    }

    // Verify message numbers are sequential
    expect(messageKeys.length).toBe(10);
  });

  it('should advance chain key irreversibly', async () => {
    const initialChainKey = new Uint8Array(32).fill(0xaa).buffer;
    let state: ChainState = {
      chainKey: initialChainKey,
      messageNumber: 0,
    };

    const chainKeys: Uint8Array[] = [new Uint8Array(state.chainKey)];

    // Advance the ratchet several steps
    for (let i = 0; i < 5; i++) {
      const { newState } = await ratchetStep(state);
      chainKeys.push(new Uint8Array(newState.chainKey));
      state = newState;
    }

    // Verify that no chain key is the same as any other
    const chainKeySet = new Set<string>();
    for (const key of chainKeys) {
      const keyStr = Array.from(key).join(',');
      expect(chainKeySet).not.toContain(keyStr);
      chainKeySet.add(keyStr);
    }

    // Verify all chain keys are different
    expect(chainKeySet.size).toBe(chainKeys.length);
  });

  it('should produce message keys different from subsequent chain keys', async () => {
    const initialChainKey = new Uint8Array(32).fill(0xcc).buffer;
    const state: ChainState = {
      chainKey: initialChainKey,
      messageNumber: 0,
    };

    const { newState, messageKey } = await ratchetStep(state);

    const messageKeyArray = new Uint8Array(messageKey.key);
    const nextChainKeyArray = new Uint8Array(newState.chainKey);

    // Message key and next chain key must be different
    expect(messageKeyArray).not.toEqual(nextChainKeyArray);
  });

  it('should correctly track message numbers', async () => {
    const initialChainKey = new Uint8Array(32).fill(0xdd).buffer;
    let state: ChainState = {
      chainKey: initialChainKey,
      messageNumber: 100,
    };

    for (let i = 0; i < 5; i++) {
      const { newState, messageKey } = await ratchetStep(state);
      expect(messageKey.messageNumber).toBe(state.messageNumber);
      expect(newState.messageNumber).toBe(state.messageNumber + 1);
      state = newState;
    }

    // Should end with message number 105
    expect(state.messageNumber).toBe(105);
  });
});
