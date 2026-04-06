/**
 * Double Ratchet Algorithm - Full Implementation
 * 
 * Reference: Signal Double Ratchet Specification
 * https://signal.org/docs/specifications/doubleratchet/
 * 
 * Combines DH ratchet (for break-in recovery) and symmetric ratchet (for forward secrecy).
 * Handles encryption, decryption, and out-of-order message delivery.
 */

import { ratchetStep, ChainState, clearKey } from './symmetric-ratchet';
import { dhRatchetStep, RatchetState } from './dh-ratchet';
import { exportPublicKeyRaw, importPublicKeyRaw } from './x25519';

/**
 * Message structure for transmission.
 * Contains a header with the sender's DH public key and message metadata,
 * plus the AES-GCM encrypted ciphertext.
 */
export interface Message {
  // Header data
  header: {
    // Sender's current DH public key (base64)
    dhPublicKey: string;
    // Sequence number within the current sending chain
    messageNumber: number;
    // Count of messages in the previous sending chain (for skip detection)
    previousChainLength: number;
  };
  // Encrypted plaintext (base64)
  ciphertext: string;
  // Initialization vector for AES-GCM (base64)
  iv: string;
}

/**
 * Encrypt a plaintext message.
 * 
 * - Advances the sending chain forward
 * - Uses the derived message key with AES-256-GCM
 * - Returns the encrypted message and updated ratchet state
 * - The message key is immediately deleted after use
 * 
 * @param state - Current ratchet state
 * @param plaintext - Message to encrypt
 * @returns Encrypted message and new ratchet state
 */
export async function encrypt(
  state: RatchetState,
  plaintext: string
): Promise<{ message: Message; newState: RatchetState }> {
  // Advance the sending chain
  const { newState: advancedState, messageKey } = await ratchetStep(
    state.sendingChain
  );

  // Export our current DH public key for the header
  const myDHPublicKeyRaw = await exportPublicKeyRaw(state.myDHKeyPair.publicKey);
  const dhPublicKeyB64 = arrayBufferToBase64(myDHPublicKeyRaw);

  // Encrypt the plaintext
  const { ciphertext, iv } = await encryptAESGCM(plaintext, messageKey.key);

  // Create the message
  const message: Message = {
    header: {
      dhPublicKey: dhPublicKeyB64,
      messageNumber: messageKey.messageNumber,
      previousChainLength: state.sendingChain.messageNumber,
    },
    ciphertext,
    iv,
  };

  // Clear the ephemeral message key
  clearKey(messageKey.key);

  return {
    message,
    newState: {
      ...state,
      sendingChain: advancedState,
    },
  };
}

/**
 * Decrypt a received message.
 * 
 * - If the sender's DH public key differs, performs a DH ratchet step
 * - Derives the message key from the receiving chain
 * - Handles out-of-order delivery via skipped key storage
 * - Decrypts and returns the plaintext
 * 
 * @param state - Current ratchet state
 * @param message - Encrypted message to decrypt
 * @param skippedKeys - Map of skipped message keys from previous chains
 * @returns Decrypted plaintext and new ratchet state
 */
export async function decrypt(
  state: RatchetState,
  message: Message,
  skippedKeys: Map<string, ArrayBuffer> = new Map()
): Promise<{
  plaintext: string;
  newState: RatchetState;
  skippedKeys: Map<string, ArrayBuffer>;
}> {
  // Import the sender's DH public key from the header
  const senderDHPublicKeyRaw = base64ToArrayBuffer(message.header.dhPublicKey);
  const senderDHPublicKey = await importPublicKeyRaw(senderDHPublicKeyRaw);

  let newState = state;

  // Check if we need to perform a DH ratchet step (direction change)
  const senderPublicKeyStr = message.header.dhPublicKey;
  const currentTheirPublicKeyRaw = await exportPublicKeyRaw(state.theirDHPublicKey);
  const currentTheirPublicKeyB64 = arrayBufferToBase64(currentTheirPublicKeyRaw);

  if (senderPublicKeyStr !== currentTheirPublicKeyB64) {
    // Sender has a different DH public key - we need to ratchet forward
    // Skip any messages from the old chain
    await skipMessageKeys(
      newState.receivingChain,
      message.header.previousChainLength,
      senderPublicKeyStr,
      skippedKeys
    );

    // Perform DH ratchet step
    newState = await dhRatchetStep(newState, senderDHPublicKey);
  }

  // Try to derive the message key from the receiving chain
  const skippedKeyKey = `${senderPublicKeyStr}:${message.header.messageNumber}`;
  const derivedMessageKey = skippedKeys.get(skippedKeyKey);

  let messageKeyBuffer: ArrayBuffer;

  if (derivedMessageKey) {
    // We already have this skipped key
    messageKeyBuffer = derivedMessageKey;
    skippedKeys.delete(skippedKeyKey);
  } else {
    // Skip forward to the target message number
    let currentChain = newState.receivingChain;

    while (currentChain.messageNumber < message.header.messageNumber) {
      const { newState: advanced, messageKey } = await ratchetStep(currentChain);

      // Store this skipped message key
      const skippedKeyStr = `${senderPublicKeyStr}:${messageKey.messageNumber}`;
      skippedKeys.set(skippedKeyStr, messageKey.key);

      // Cap skipped key storage
      if (skippedKeys.size > 1000) {
        const firstKey = skippedKeys.keys().next().value!;
        skippedKeys.delete(firstKey);
      }

      currentChain = advanced;
    }

    // Now currentChain.messageNumber === message.header.messageNumber
    const { messageKey } = await ratchetStep(currentChain);
    messageKeyBuffer = messageKey.key;
    newState.receivingChain = currentChain;
  }

  // Decrypt the ciphertext
  const plaintext = await decryptAESGCM(
    message.ciphertext,
    message.iv,
    messageKeyBuffer
  );

  // Clear the ephemeral message key
  clearKey(messageKeyBuffer);

  return {
    plaintext,
    newState,
    skippedKeys,
  };
}

/**
 * Skip ahead in a chain to avoid message delivery reordering issues.
 * Stores the skipped message keys for later use.
 */
async function skipMessageKeys(
  chain: ChainState,
  targetMessageNumber: number,
  senderPublicKeyStr: string,
  skippedKeys: Map<string, ArrayBuffer>
): Promise<void> {
  let currentChain = chain;

  while (currentChain.messageNumber < targetMessageNumber) {
    const { newState, messageKey } = await ratchetStep(currentChain);
    const skippedKeyStr = `${senderPublicKeyStr}:${messageKey.messageNumber}`;
    skippedKeys.set(skippedKeyStr, messageKey.key);

    // Prevent unbounded memory growth
    if (skippedKeys.size > 1000) {
      const firstKey = skippedKeys.keys().next().value!;
      skippedKeys.delete(firstKey);
    }

    currentChain = newState;
  }
}

/**
 * Encrypt a plaintext using AES-256-GCM.
 * 
 * @param plaintext - Message to encrypt
 * @param keyMaterial - 32-byte key
 * @returns Base64-encoded ciphertext and IV
 */
async function encryptAESGCM(
  plaintext: string,
  keyMaterial: ArrayBuffer
): Promise<{ ciphertext: string; iv: string }> {
  // Import the key for AES-GCM
  const key = await crypto.subtle.importKey(
    'raw',
    keyMaterial,
    { name: 'AES-GCM' },
    false,
    ['encrypt']
  );

  // Generate a random 12-byte IV for GCM
  const iv = crypto.getRandomValues(new Uint8Array(12));

  // Encrypt the plaintext
  const plainTextBuffer = new TextEncoder().encode(plaintext);
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    plainTextBuffer
  );

  return {
    ciphertext: arrayBufferToBase64(ciphertext),
    iv: arrayBufferToBase64(iv.buffer),
  };
}

/**
 * Decrypt a ciphertext using AES-256-GCM.
 * 
 * @param ciphertextB64 - Base64-encoded ciphertext
 * @param ivB64 - Base64-encoded IV
 * @param keyMaterial - 32-byte key
 * @returns Decrypted plaintext
 */
async function decryptAESGCM(
  ciphertextB64: string,
  ivB64: string,
  keyMaterial: ArrayBuffer
): Promise<string> {
  // Import the key for AES-GCM
  const key = await crypto.subtle.importKey(
    'raw',
    keyMaterial,
    { name: 'AES-GCM' },
    false,
    ['decrypt']
  );

  const ciphertext = base64ToArrayBuffer(ciphertextB64);
  const iv = base64ToArrayBuffer(ivB64);

  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    key,
    ciphertext
  );

  return new TextDecoder().decode(plaintext);
}

/**
 * Convert ArrayBuffer to base64 string.
 */
function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/**
 * Convert base64 string to ArrayBuffer.
 */
function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}
