/**
 * Diffie-Hellman Ratchet (Root Key Chain)
 * 
 * Reference: Signal Double Ratchet Specification, Section 3
 * https://signal.org/docs/specifications/doubleratchet/
 * 
 * The DH ratchet updates the root key by performing X25519 key agreements.
 * It serves two purposes:
 * 1. Break-in recovery: A new root key is computed from fresh ephemeral keys,
 *    making it impossible for an attacker holding the old root to compute the new one.
 * 2. Authentication: Each party confirms they control the DH keys they published.
 */

import { generateKeyPair, deriveSharedSecret } from './x25519';
import { hkdf, DOMAIN_LABELS } from './hkdf';
import { ChainState } from './symmetric-ratchet';

/**
 * Complete ratchet state including both root key and sending/receiving chain keys.
 */
export interface RatchetState {
  // Root key from which chain keys are derived
  rootKey: ArrayBuffer;
  // Sending chain (for messages we encrypt)
  sendingChain: ChainState;
  // Receiving chain (for messages we decrypt)
  receivingChain: ChainState;
  // Our current DH key pair
  myDHKeyPair: {
    publicKey: CryptoKey;
    privateKey: CryptoKey;
  };
  // Peer's current DH public key
  theirDHPublicKey: CryptoKey;
  // Count of DH ratchet steps (for diagnostics)
  dhRatchetCount: number;
}

/**
 * Perform one DH ratchet step.
 * 
 * Steps:
 * 1. Compute DH shared secret with current keys
 * 2. Derive new root key and receiving chain key from shared secret
 * 3. Generate new ephemeral DH key pair
 * 4. Compute new DH shared secret with the new private key
 * 5. Derive new root key and sending chain key from the new shared secret
 * 6. Delete old key material
 * 7. Return updated ratchet state
 * 
 * @param state - Current ratchet state (with old root key, old DH key pair)
 * @param theirNewPublicKey - Their new DH public key (triggers the ratchet)
 * @returns Updated ratchet state with new root key, DH key pair, and chain keys
 * 
 * This operation is triggered when:
 * - Alice sends a message (she creates new ephemeral key)
 * - Bob receives it (Bob recognizes a new pubkey in the header and ratchets forward)
 */
export async function dhRatchetStep(
  state: RatchetState,
  theirNewPublicKey: CryptoKey
): Promise<RatchetState> {
  // Step 1: Compute first DH shared secret
  // This derives the new root key and receiving chain key
  const dh = await deriveSharedSecret(state.myDHKeyPair.privateKey, theirNewPublicKey);

  // Step 2: Derive root and receiving chain keys from first DH
  const rootAndReceivingChainMaterial = await hkdf(
    state.rootKey,
    dh,
    DOMAIN_LABELS.ROOT,
    64 // 32 bytes root + 32 bytes chain key
  );

  const newRootKeyBuffer = rootAndReceivingChainMaterial.slice(0, 32);
  const receivingChainKeyBuffer = rootAndReceivingChainMaterial.slice(32, 64);

  // Step 3: Generate fresh DH key pair for ourselves
  const newMyDHKeyPair = await generateKeyPair();

  // Step 4: Compute second DH shared secret with new key pair
  const dh2 = await deriveSharedSecret(newMyDHKeyPair.privateKey, theirNewPublicKey);

  // Step 5: Derive root and sending chain keys from second DH
  const rootAndSendingChainMaterial = await hkdf(
    newRootKeyBuffer,
    dh2,
    DOMAIN_LABELS.ROOT,
    64 // 32 bytes root + 32 bytes chain key
  );

  const finalRootKeyBuffer = rootAndSendingChainMaterial.slice(0, 32);
  const sendingChainKeyBuffer = rootAndSendingChainMaterial.slice(32, 64);

  // Step 6: Clear sensitive old key material from memory
  clearKeyMaterial(state.rootKey);
  clearKeyMaterial(dh);
  clearKeyMaterial(dh2);

  return {
    rootKey: finalRootKeyBuffer,
    sendingChain: {
      chainKey: sendingChainKeyBuffer,
      messageNumber: 0,
    },
    receivingChain: {
      chainKey: receivingChainKeyBuffer,
      messageNumber: 0,
    },
    myDHKeyPair: newMyDHKeyPair,
    theirDHPublicKey: theirNewPublicKey,
    dhRatchetCount: state.dhRatchetCount + 1,
  };
}

/**
 * Securely clear key material from memory.
 * Overwrites the buffer with zeros to prevent unintended retention in memory.
 * 
 * @param buffer - ArrayBuffer to clear
 */
function clearKeyMaterial(buffer: ArrayBuffer): void {
  const view = new Uint8Array(buffer);
  view.fill(0);
}
