/**
 * Diffie-Hellman Ratchet (Root Key Chain)
 *
 * Reference: Signal Double Ratchet Specification
 * https://signal.org/docs/specifications/doubleratchet/
 * The DHRatchet pseudocode this mirrors is in §3.5 ("Decrypting messages"),
 * where RatchetDecrypt calls it; §3.3 is "Initialization", which this file's
 * header used to cite by mistake. KDF_RK's contract is §3.1 ("External
 * functions") and its HKDF instantiation is §7.2 ("Recommended cryptographic
 * algorithms") in the current revision — §5.2 before the Sparse PQ Ratchet and
 * Triple Ratchet sections were inserted ahead of it.
 *
 * The DH ratchet advances the root key whenever the conversation changes
 * direction. It is what gives the protocol break-in recovery (a.k.a.
 * post-compromise security): each step mixes in a fresh X25519 key pair, so an
 * attacker who has captured the old state cannot compute the new root key
 * without the new private keys.
 */

import { generateKeyPair, deriveSharedSecret, KeyPair } from './x25519';
import { kdfRk } from './hkdf';
import { ChainState, clearKey } from './symmetric-ratchet';

/**
 * Complete Double Ratchet state for one party.
 *
 * Field names follow the Signal specification:
 *   - rootKey                  = RK
 *   - myDHKeyPair              = DHs  (our current ratchet key pair)
 *   - theirDHPublicKey         = DHr  (their current ratchet public key)
 *   - sendingChain             = CKs / Ns
 *   - receivingChain           = CKr / Nr
 *   - previousSendingChainLength = PN
 *
 * `sendingChain` and `receivingChain` are nullable because a party may not have
 * a given chain yet. In particular the responder (Bob) has no chains until he
 * receives the initiator's first message and performs his first DH ratchet.
 */
export interface RatchetState {
  rootKey: ArrayBuffer;
  /** Session identity binding, preserved across DH steps and skipped messages. */
  associatedData?: ArrayBuffer;
  myDHKeyPair: KeyPair;
  theirDHPublicKey: Uint8Array | null;
  sendingChain: ChainState | null;
  receivingChain: ChainState | null;
  /** Number of messages sent in the previous sending chain (header field PN). */
  previousSendingChainLength: number;
  /** Number of DH ratchet steps performed (for the visualization/diagnostics). */
  dhRatchetCount: number;
}

/**
 * Perform a full DH ratchet step (Signal's DHRatchet), run by the receiver when
 * it sees a message carrying a new DHr.
 *
 * Steps:
 *   1. PN = length of our current sending chain; reset Ns/Nr.
 *   2. DHr = theirNewPublicKey.
 *   3. (RK, CKr) = KDF_RK(RK, DH(DHs, DHr))     -- receiving half
 *   4. DHs = generate a fresh key pair.
 *   5. (RK, CKs) = KDF_RK(RK, DH(DHs, DHr))     -- sending half
 *
 * Convergence: the sender produced its sending chain from the SAME (RK, DH)
 * pair we use in step 3, because X25519 commutes — so our new receiving chain
 * equals the sender's sending chain.
 *
 * @param state - Current ratchet state
 * @param theirNewPublicKey - The peer's new ratchet public key (from the header)
 * @returns A new ratchet state (the input state is not mutated)
 */
export async function dhRatchet(
  state: RatchetState,
  theirNewPublicKey: Uint8Array
): Promise<RatchetState> {
  const previousSendingChainLength = state.sendingChain?.messageNumber ?? 0;
  let dhReceive: ArrayBuffer | undefined;
  let dhSend: ArrayBuffer | undefined;
  let recv: Awaited<ReturnType<typeof kdfRk>> | undefined;
  let newDHKeyPair: KeyPair | undefined;
  let completed = false;

  try {
    // Receiving half: derive the chain that decrypts the incoming message.
    dhReceive = await deriveSharedSecret(state.myDHKeyPair.privateKey, theirNewPublicKey);
    recv = await kdfRk(state.rootKey, dhReceive);

    // Generate a fresh ratchet key pair for ourselves.
    newDHKeyPair = await generateKeyPair();

    // Sending half: derive the chain we will use for our replies.
    dhSend = await deriveSharedSecret(newDHKeyPair.privateKey, theirNewPublicKey);
    const send = await kdfRk(recv.rootKey, dhSend);
    const result: RatchetState = {
      rootKey: send.rootKey,
      associatedData: state.associatedData,
      myDHKeyPair: newDHKeyPair,
      theirDHPublicKey: theirNewPublicKey,
      sendingChain: { chainKey: send.chainKey, messageNumber: 0 },
      receivingChain: { chainKey: recv.chainKey, messageNumber: 0 },
      previousSendingChainLength,
      dhRatchetCount: state.dhRatchetCount + 1,
    };
    completed = true;
    return result;
  } finally {
    // Best-effort wipe of secrets this function owns. We deliberately do NOT
    // wipe the caller's root key because a forged message must leave the input
    // state usable. Returned keys remain live only on a completed ratchet.
    if (dhReceive) clearKey(dhReceive);
    if (dhSend) clearKey(dhSend);
    if (recv) {
      clearKey(recv.rootKey);
      if (!completed) clearKey(recv.chainKey);
    }
    if (!completed && newDHKeyPair) newDHKeyPair.privateKey.fill(0);
  }
}
