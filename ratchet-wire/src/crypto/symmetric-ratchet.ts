/**
 * Symmetric-key Ratchet (Message Keys and Chain Keys)
 * 
 * Reference: Signal Double Ratchet Specification, Section 2
 * https://signal.org/docs/specifications/doubleratchet/
 * 
 * The symmetric ratchet derives a sequence of unique message keys from a chain key,
 * using HKDF with domain-separated labels. Each message key is independent, enabling
 * recovery from key compromise (forward secrecy).
 */

import { hkdf, DOMAIN_LABELS } from './hkdf';

/**
 * Represents the state of a symmetric ratchet chain (KDF chain).
 * A chain key is advanced forward to derive message keys.
 */
export interface ChainState {
  // Current chain key (32 bytes)
  chainKey: ArrayBuffer;
  // Count of messages derived from this chain
  messageNumber: number;
}

/**
 * A derived message key with its sequence number.
 * MessageKey is intentionally ephemeral - the caller is responsible for
 * deleting it after use (e.g., for encryption). It must not be stored
 * in ChainState to maintain forward secrecy.
 */
export interface MessageKey {
  // Derived key (32 bytes) for encrypting a message
  key: ArrayBuffer;
  // The message sequence number this key encrypts
  messageNumber: number;
}

/**
 * Perform one step of the symmetric ratchet.
 * 
 * From the current chain key, derive:
 * 1. A message key for encrypting the current message
 * 2. A new chain key for advancing the ratchet
 * 
 * The returned message key is ephemeral and MUST be deleted after use.
 * The returned ChainState has the new chain key and incremented message number.
 * 
 * @param state - Current chain state
 * @returns Object containing new chain state and ephemeral message key
 * 
 * @example
 * const state = { chainKey, messageNumber: 0 };
 * const { newState, messageKey } = await ratchetStep(state);
 * // Use messageKey for encryption here
 * // Then securely delete messageKey.key (it's out of scope)
 * state = newState; // Advance chain
 */
export async function ratchetStep(state: ChainState): Promise<{
  newState: ChainState;
  messageKey: MessageKey;
}> {
  // Using fixed salts for domain separation within the ratchet
  // Salt 0x01 for message keys, 0x02 for chain keys
  const messageSalt = new Uint8Array([0x01]).buffer;
  const chainSalt = new Uint8Array([0x02]).buffer;

  // Derive message key from current chain key
  const derivedMessageKey = await hkdf(
    state.chainKey,
    messageSalt,
    DOMAIN_LABELS.MESSAGE,
    32
  );

  // Derive next chain key from current chain key
  const derivedChainKey = await hkdf(
    state.chainKey,
    chainSalt,
    DOMAIN_LABELS.CHAIN,
    32
  );

  return {
    newState: {
      chainKey: derivedChainKey,
      messageNumber: state.messageNumber + 1,
    },
    messageKey: {
      key: derivedMessageKey,
      messageNumber: state.messageNumber,
    },
  };
}

/**
 * Securely clear key material from memory.
 * 
 * This is a helper for consuming code to explicitly clear sensitive key material.
 * JavaScript's garbage collection cannot guarantee immediate memory release,
 * but overwriting with zeros helps when sensitive keys are held in heap buffers.
 * 
 * @param buffer - ArrayBuffer to clear (fills with zeros)
 */
export function clearKey(buffer: ArrayBuffer): void {
  const view = new Uint8Array(buffer);
  view.fill(0);
}
