/**
 * Simplified X3DH — Session Initialization
 *
 * Reference: Signal X3DH Specification
 * https://signal.org/docs/specifications/x3dh/
 *
 * SIMPLIFIED IMPLEMENTATION:
 * - Does NOT implement one-time pre-keys (full X3DH uses these)
 * - Does NOT verify the signature on the signed pre-key
 * - Focuses on the key-agreement phase that produces the initial root key
 *
 * X3DH lets Alice (initiator) and Bob (responder) agree on a shared secret SK
 * from Bob's published pre-keys plus Alice's identity/ephemeral keys. SK becomes
 * the initial root key of the Double Ratchet. The two parties then initialize
 * the ratchet ASYMMETRICALLY (see {@link createAliceRatchetState} /
 * {@link createBobRatchetState}), which is what allows the DH ratchet to engage
 * on the first exchange.
 */

import { deriveSharedSecret, KeyPair } from './x25519';
import { hkdf, DOMAIN_LABELS, kdfRk } from './hkdf';
import { RatchetState } from './dh-ratchet';

/** Alice's keys for initiating a session. */
export interface AliceSessionInitKeys {
  identityKeyPair: KeyPair;
  ephemeralKeyPair: KeyPair;
}

/** Bob's published pre-session keys (IK + signed pre-key). */
export interface BobPreSessionKeys {
  identityKeyPair: KeyPair;
  signedPreKeyPair: KeyPair;
}

/** Result of X3DH key agreement: the shared root key (SK). */
export interface SessionInitResult {
  rootKey: ArrayBuffer;
}

// X3DH uses a zero-filled salt for the initial KDF (no prior secret to mix in).
const X3DH_SALT = new Uint8Array(32).buffer;

/**
 * Simplified X3DH from Alice's (initiator) perspective.
 *
 *   SK = HKDF( DH(IK_A, SPK_B) || DH(EK_A, IK_B) || DH(EK_A, SPK_B) )
 *
 * @param aliceKeys - Alice's identity and ephemeral key pairs
 * @param bobPublicIK - Bob's published identity public key
 * @param bobPublicSPK - Bob's published signed pre-key public key
 * @returns The shared root key SK
 */
export async function initiateSessionX3DH(
  aliceKeys: AliceSessionInitKeys,
  bobPublicIK: CryptoKey,
  bobPublicSPK: CryptoKey
): Promise<SessionInitResult> {
  const dh1 = await deriveSharedSecret(aliceKeys.identityKeyPair.privateKey, bobPublicSPK);
  const dh2 = await deriveSharedSecret(aliceKeys.ephemeralKeyPair.privateKey, bobPublicIK);
  const dh3 = await deriveSharedSecret(aliceKeys.ephemeralKeyPair.privateKey, bobPublicSPK);

  const rootKey = await deriveRootKey(dh1, dh2, dh3);

  clearBuffer(dh1);
  clearBuffer(dh2);
  clearBuffer(dh3);

  return { rootKey };
}

/**
 * Simplified X3DH from Bob's (responder) perspective. Produces the same SK as
 * Alice because each DH term commutes.
 *
 *   SK = HKDF( DH(SPK_B, IK_A) || DH(IK_B, EK_A) || DH(SPK_B, EK_A) )
 *
 * @param bobKeys - Bob's identity and signed pre-key pairs
 * @param alicePublicIK - Alice's published identity public key
 * @param alicePublicEK - Alice's ephemeral public key (from the initial message)
 * @returns The shared root key SK (matches Alice's)
 */
export async function acceptSessionX3DH(
  bobKeys: BobPreSessionKeys,
  alicePublicIK: CryptoKey,
  alicePublicEK: CryptoKey
): Promise<SessionInitResult> {
  const dh1 = await deriveSharedSecret(bobKeys.signedPreKeyPair.privateKey, alicePublicIK);
  const dh2 = await deriveSharedSecret(bobKeys.identityKeyPair.privateKey, alicePublicEK);
  const dh3 = await deriveSharedSecret(bobKeys.signedPreKeyPair.privateKey, alicePublicEK);

  const rootKey = await deriveRootKey(dh1, dh2, dh3);

  clearBuffer(dh1);
  clearBuffer(dh2);
  clearBuffer(dh3);

  return { rootKey };
}

/**
 * Initialize Alice's ratchet (Signal's RatchetInitAlice).
 *
 * Alice is the initiator: she already knows Bob's ratchet public key (his
 * published pre-key), so she performs the SENDING half of a DH ratchet
 * immediately and can send the first message.
 *
 *   DHs = aliceRatchetKeyPair;  DHr = bobRatchetPublicKey
 *   (RK, CKs) = KDF_RK(SK, DH(DHs, DHr));  CKr = none
 *
 * @param session - X3DH result (SK)
 * @param aliceRatchetKeyPair - Alice's initial ratchet key pair (DHs)
 * @param bobRatchetPublicKey - Bob's published ratchet public key (DHr)
 */
export async function createAliceRatchetState(
  session: SessionInitResult,
  aliceRatchetKeyPair: KeyPair,
  bobRatchetPublicKey: CryptoKey
): Promise<RatchetState> {
  const dh = await deriveSharedSecret(aliceRatchetKeyPair.privateKey, bobRatchetPublicKey);
  const { rootKey, chainKey } = await kdfRk(session.rootKey, dh);
  clearBuffer(dh);

  return {
    rootKey,
    myDHKeyPair: aliceRatchetKeyPair,
    theirDHPublicKey: bobRatchetPublicKey,
    sendingChain: { chainKey, messageNumber: 0 },
    receivingChain: null,
    previousSendingChainLength: 0,
    dhRatchetCount: 0,
  };
}

/**
 * Initialize Bob's ratchet (Signal's RatchetInitBob).
 *
 * Bob is the responder: he keeps his ratchet key pair and waits. He has no
 * chains and no DHr yet; both are established when he receives Alice's first
 * message and performs his first DH ratchet.
 *
 *   DHs = bobRatchetKeyPair;  DHr = none;  RK = SK;  CKs = CKr = none
 *
 * @param session - X3DH result (SK)
 * @param bobRatchetKeyPair - Bob's published ratchet key pair (DHs)
 */
export function createBobRatchetState(
  session: SessionInitResult,
  bobRatchetKeyPair: KeyPair
): RatchetState {
  return {
    rootKey: session.rootKey,
    myDHKeyPair: bobRatchetKeyPair,
    theirDHPublicKey: null,
    sendingChain: null,
    receivingChain: null,
    previousSendingChainLength: 0,
    dhRatchetCount: 0,
  };
}

/** Concatenate the three DH outputs and derive SK via HKDF. */
async function deriveRootKey(
  dh1: ArrayBuffer,
  dh2: ArrayBuffer,
  dh3: ArrayBuffer
): Promise<ArrayBuffer> {
  const concatenated = concatenateBuffers([dh1, dh2, dh3]);
  const rootKey = await hkdf(concatenated, X3DH_SALT, DOMAIN_LABELS.ROOT, 32);
  clearBuffer(concatenated);
  return rootKey;
}

/** Concatenate multiple ArrayBuffers into one. */
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

/** Overwrite a buffer with zeros. */
function clearBuffer(buffer: ArrayBuffer): void {
  new Uint8Array(buffer).fill(0);
}
