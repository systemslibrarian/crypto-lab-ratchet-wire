/**
 * Symmetric-key Ratchet (Chain Keys -> Message Keys)
 *
 * Reference: Signal Double Ratchet Specification
 * https://signal.org/docs/specifications/doubleratchet/
 * §2.2 ("Symmetric-key ratchet") describes the idea; KDF_CK itself is defined
 * in §3.1 ("External functions") and instantiated in §7.2 ("Recommended
 * cryptographic algorithms"). This header previously attributed KDF_CK to
 * §2.2, which never names it.
 *
 * The symmetric ratchet turns a chain key into a sequence of unique message
 * keys. Each step derives:
 *   - a message key (used once to encrypt/decrypt a single message), and
 *   - the next chain key (which replaces the current one).
 *
 * Because the step is one-way (HKDF/HMAC cannot be inverted), deleting a message
 * key after use means a later state compromise cannot recover earlier message
 * keys — this is forward secrecy.
 */

import { hkdf, DOMAIN_LABELS } from './hkdf';

/**
 * State of a single symmetric (KDF) chain.
 * The chain key is advanced forward to derive message keys.
 */
export interface ChainState {
  /** Current chain key (32 bytes). */
  chainKey: ArrayBuffer;
  /** Number of message keys already derived from this chain. */
  messageNumber: number;
}

/**
 * A derived message key with its sequence number.
 *
 * A MessageKey is ephemeral: the caller uses it once and MUST clear it (see
 * {@link clearKey}). It is never stored in {@link ChainState}, which is what
 * preserves forward secrecy.
 */
export interface MessageKey {
  /** Derived key (32 bytes) for one message. */
  key: ArrayBuffer;
  /** The message sequence number this key corresponds to. */
  messageNumber: number;
}

// Single-byte domain separators, 0x01 for the message key and 0x02 for the
// next chain key — the same two constants §7.2 recommends. The roles are
// swapped relative to the spec, though: §7.2 keys an HMAC with ck and feeds
// the constant as the *input*, whereas this demo runs HKDF with ck as the
// input key material and the constant as the *salt*. Both are one-way and
// domain-separated, but the outputs are not the same bytes, which is one more
// reason nothing here interoperates with libsignal.
const MESSAGE_KEY_SALT = new Uint8Array([0x01]).buffer;
const CHAIN_KEY_SALT = new Uint8Array([0x02]).buffer;

/**
 * Perform one symmetric-ratchet step (KDF_CK).
 *
 * From the current chain key, derives the message key for the current message
 * and the next chain key. Domain-separated salts/labels guarantee the message
 * key and the next chain key are independent.
 *
 * The returned message key is ephemeral and MUST be cleared after use. The
 * returned state holds the next chain key and an incremented message number.
 *
 * @param state - Current chain state
 * @returns The advanced chain state and the ephemeral message key
 */
export async function ratchetStep(state: ChainState): Promise<{
  newState: ChainState;
  messageKey: MessageKey;
}> {
  const derivedMessageKey = await hkdf(
    state.chainKey,
    MESSAGE_KEY_SALT,
    DOMAIN_LABELS.MESSAGE,
    32
  );

  const derivedChainKey = await hkdf(
    state.chainKey,
    CHAIN_KEY_SALT,
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
 * Overwrite key material with zeros.
 *
 * JavaScript's garbage collector cannot guarantee prompt release of heap
 * buffers, so we zero sensitive material explicitly once it is no longer
 * needed. This is best-effort, not a hard guarantee.
 *
 * @param buffer - Buffer to clear
 */
export function clearKey(buffer: ArrayBuffer): void {
  new Uint8Array(buffer).fill(0);
}
