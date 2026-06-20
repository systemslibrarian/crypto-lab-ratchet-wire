/**
 * Diffie-Hellman Ratchet (Root Key Chain)
 *
 * Reference: Signal Double Ratchet Specification, Section 3.3 (DHRatchet)
 * https://signal.org/docs/specifications/doubleratchet/
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
  myDHKeyPair: KeyPair;
  theirDHPublicKey: CryptoKey | null;
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
  theirNewPublicKey: CryptoKey
): Promise<RatchetState> {
  const previousSendingChainLength = state.sendingChain?.messageNumber ?? 0;

  // Receiving half: derive the chain that decrypts the incoming message.
  const dhReceive = await deriveSharedSecret(
    state.myDHKeyPair.privateKey,
    theirNewPublicKey
  );
  const recv = await kdfRk(state.rootKey, dhReceive);

  // Generate a fresh ratchet key pair for ourselves.
  const newDHKeyPair = await generateKeyPair();

  // Sending half: derive the chain we will use for our replies.
  const dhSend = await deriveSharedSecret(
    newDHKeyPair.privateKey,
    theirNewPublicKey
  );
  const send = await kdfRk(recv.rootKey, dhSend);

  // Best-effort wipe of secrets this function owns. We deliberately do NOT wipe
  // the input `state.rootKey`: this function is non-mutating (callers, including
  // decrypt(), treat the input state as immutable and may still hold it after a
  // failed/forged message). Zeroing the caller's buffer here would corrupt the
  // session if AEAD authentication later fails. The superseded root key is
  // released by the old, discarded state and reclaimed by the GC.
  clearKey(recv.rootKey);
  clearKey(dhReceive);
  clearKey(dhSend);

  return {
    rootKey: send.rootKey,
    myDHKeyPair: newDHKeyPair,
    theirDHPublicKey: theirNewPublicKey,
    sendingChain: { chainKey: send.chainKey, messageNumber: 0 },
    receivingChain: { chainKey: recv.chainKey, messageNumber: 0 },
    previousSendingChainLength,
    dhRatchetCount: state.dhRatchetCount + 1,
  };
}
