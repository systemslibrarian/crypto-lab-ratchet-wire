/**
 * Simplified X3DH - Session Initialization
 * 
 * Reference: Signal X3DH Specification
 * https://signal.org/docs/specifications/x3dh/
 * 
 * SIMPLIFIED IMPLEMENTATION:
 * - Does NOT implement one-time pre-keys (full X3DH uses these)
 * - Does NOT implement cryptographic signatures (for simplicity in the demo)
 * - Focuses on the key agreement phase to establish an initial root key
 * - In production, see the full X3DH spec for complete security
 * 
 * This allows Alice and Bob to establish an initial shared secret from scratch,
 * which becomes the root key for the Double Ratchet Algorithm.
 */

import { generateKeyPair, deriveSharedSecret, exportPublicKeyRaw, importPublicKeyRaw } from './x25519';
import { hkdf, DOMAIN_LABELS } from './hkdf';
import { RatchetState } from './dh-ratchet';

/**
 * Alice's initial setup keys for session initialization.
 * In practice, these would be generated once and reused.
 */
export interface AliceSessionInitKeys {
  identityKeyPair: { publicKey: CryptoKey; privateKey: CryptoKey };
  ephemeralKeyPair: { publicKey: CryptoKey; privateKey: CryptoKey };
}

/**
 * Bob's published pre-session keys.
 * Bob publishes IK and SPK publicly for others to initiate sessions with him.
 */
export interface BobPreSessionKeys {
  identityKeyPair: { publicKey: CryptoKey; privateKey: CryptoKey };
  signedPreKeyPair: { publicKey: CryptoKey; privateKey: CryptoKey };
}

/**
 * Session parameters after X3DH key agreement.
 * These become the initial state for the Double Ratchet.
 */
export interface SessionInitResult {
  // Shared root key derived from key agreement
  rootKey: ArrayBuffer;
  // Alice's initial DH key pair
  aliceDHKeyPair: { publicKey: CryptoKey; privateKey: CryptoKey };
  // Bob's initial DH key pair
  bobDHKeyPair: { publicKey: CryptoKey; privateKey: CryptoKey };
  // Initial chain keys
  initialChainKeyAlice: ArrayBuffer;
  initialChainKeyBob: ArrayBuffer;
}

/**
 * Simplified X3DH: Alice receives Bob's published keys and initiates a session.
 * 
 * Alice computes the shared secret as:
 * SK = HKDF(DH(IK_A, SPK_B) || DH(EK_A, IK_B) || DH(EK_A, SPK_B))
 * 
 * @param aliceKeys - Alice's identity and ephemeral keys
 * @param bobPublicIK - Bob's published identity public key
 * @param bobPublicSPK - Bob's published signed pre-key public key
 * @param aliceDHKeyPair - Alice's DH key pair for the ratchet
 * @param bobDHKeyPair - Bob's DH key pair for the ratchet
 * @returns Root key and initial session state
 */
export async function initiateSessionX3DH(
  aliceKeys: AliceSessionInitKeys,
  bobPublicIK: CryptoKey,
  bobPublicSPK: CryptoKey,
  aliceDHKeyPair: { publicKey: CryptoKey; privateKey: CryptoKey },
  bobDHKeyPair: { publicKey: CryptoKey; privateKey: CryptoKey }
): Promise<SessionInitResult> {
  // Compute three DH shared secrets
  const dh1 = await deriveSharedSecret(aliceKeys.identityKeyPair.privateKey, bobPublicSPK);
  const dh2 = await deriveSharedSecret(aliceKeys.ephemeralKeyPair.privateKey, bobPublicIK);
  const dh3 = await deriveSharedSecret(aliceKeys.ephemeralKeyPair.privateKey, bobPublicSPK);

  // Concatenate all three shared secrets
  const concatenated = concatenateBuffers([dh1, dh2, dh3]);

  // Derive the shared root key using HKDF
  const saltForInit = new Uint8Array(32).fill(0).buffer; // Zero salt for initial setup
  const rootKey = await hkdf(
    concatenated,
    saltForInit,
    DOMAIN_LABELS.ROOT,
    32
  );

  // Also derive initial chain keys for both sides
  const chainKeyMaterial = await hkdf(
    rootKey,
    new Uint8Array([0xff]).buffer,
    DOMAIN_LABELS.CHAIN,
    64 // 32 bytes for each side
  );

  const initialChainKeyAlice = chainKeyMaterial.slice(0, 32);
  const initialChainKeyBob = chainKeyMaterial.slice(32, 64);

  // Clear sensitive DH outputs
  clearBuffer(dh1);
  clearBuffer(dh2);
  clearBuffer(dh3);
  clearBuffer(concatenated);

  return {
    rootKey,
    aliceDHKeyPair,
    bobDHKeyPair,
    initialChainKeyAlice,
    initialChainKeyBob,
  };
}

/**
 * Bob's perspective: Respond to Alice's X3DH initiation.
 * 
 * Bob receives Alice's ephemeral and identity keys and derives the same shared secret.
 * 
 * SK = HKDF(DH(SPK_B, IK_A) || DH(IK_B, EK_A) || DH(SPK_B, EK_A))
 * 
 * @param bobKeys - Bob's identity and signed pre-key pair
 * @param alicePublicIK - Alice's published identity public key
 * @param alicePublicEK - Alice's ephemeral public key (from message header)
 * @param aliceDHKeyPair - Alice's DH key pair for the ratchet
 * @param bobDHKeyPair - Bob's DH key pair for the ratchet
 * @returns Root key and initial session state (should match Alice's)
 */
export async function acceptSessionX3DH(
  bobKeys: BobPreSessionKeys,
  alicePublicIK: CryptoKey,
  alicePublicEK: CryptoKey,
  aliceDHKeyPair: { publicKey: CryptoKey; privateKey: CryptoKey },
  bobDHKeyPair: { publicKey: CryptoKey; privateKey: CryptoKey }
): Promise<SessionInitResult> {
  // Compute the same three DH shared secrets (commutative property)
  const dh1 = await deriveSharedSecret(bobKeys.signedPreKeyPair.privateKey, alicePublicIK);
  const dh2 = await deriveSharedSecret(bobKeys.identityKeyPair.privateKey, alicePublicEK);
  const dh3 = await deriveSharedSecret(bobKeys.signedPreKeyPair.privateKey, alicePublicEK);

  // Concatenate (order matches Alice's perspective)
  const concatenated = concatenateBuffers([dh1, dh2, dh3]);

  // Derive the shared root key
  const saltForInit = new Uint8Array(32).fill(0).buffer;
  const rootKey = await hkdf(
    concatenated,
    saltForInit,
    DOMAIN_LABELS.ROOT,
    32
  );

  // Derive initial chain keys (same as Alice would)
  const chainKeyMaterial = await hkdf(
    rootKey,
    new Uint8Array([0xff]).buffer,
    DOMAIN_LABELS.CHAIN,
    64
  );

  const initialChainKeyAlice = chainKeyMaterial.slice(0, 32);
  const initialChainKeyBob = chainKeyMaterial.slice(32, 64);

  // Clear sensitive DH outputs
  clearBuffer(dh1);
  clearBuffer(dh2);
  clearBuffer(dh3);
  clearBuffer(concatenated);

  return {
    rootKey,
    aliceDHKeyPair,
    bobDHKeyPair,
    initialChainKeyAlice,
    initialChainKeyBob,
  };
}

/**
 * Create the initial RatchetState for Alice after X3DH.
 */
export function createAliceRatchetState(
  sessionResult: SessionInitResult
): RatchetState {
  return {
    rootKey: sessionResult.rootKey,
    sendingChain: {
      chainKey: sessionResult.initialChainKeyAlice,
      messageNumber: 0,
    },
    receivingChain: {
      chainKey: sessionResult.initialChainKeyBob,
      messageNumber: 0,
    },
    myDHKeyPair: sessionResult.aliceDHKeyPair,
    theirDHPublicKey: sessionResult.bobDHKeyPair.publicKey,
    dhRatchetCount: 0,
  };
}

/**
 * Create the initial RatchetState for Bob after X3DH.
 */
export function createBobRatchetState(
  sessionResult: SessionInitResult
): RatchetState {
  return {
    rootKey: sessionResult.rootKey,
    sendingChain: {
      chainKey: sessionResult.initialChainKeyBob,
      messageNumber: 0,
    },
    receivingChain: {
      chainKey: sessionResult.initialChainKeyAlice,
      messageNumber: 0,
    },
    myDHKeyPair: sessionResult.bobDHKeyPair,
    theirDHPublicKey: sessionResult.aliceDHKeyPair.publicKey,
    dhRatchetCount: 0,
  };
}

/**
 * Helper: Concatenate multiple ArrayBuffers into a single buffer.
 */
function concatenateBuffers(buffers: ArrayBuffer[]): ArrayBuffer {
  const totalLength = buffers.reduce((sum, buf) => sum + buf.byteLength, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;

  for (const buf of buffers) {
    result.set(new Uint8Array(buf), offset);
    offset += buf.byteLength;
  }

  return result.buffer;
}

/**
 * Helper: Clear an ArrayBuffer by overwriting with zeros.
 */
function clearBuffer(buffer: ArrayBuffer): void {
  const view = new Uint8Array(buffer);
  view.fill(0);
}
