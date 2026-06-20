/**
 * X3DH — Authenticated Session Initialization
 *
 * Reference: Signal X3DH Specification
 * https://signal.org/docs/specifications/x3dh/
 *
 * X3DH ("Extended Triple Diffie-Hellman") lets Alice (initiator) and Bob
 * (responder) agree on a shared secret SK from Bob's published pre-key bundle
 * plus Alice's identity/ephemeral keys, WITHOUT an interactive round trip. SK
 * becomes the initial root key of the Double Ratchet.
 *
 * This implementation is faithful to the spec's security-relevant steps:
 *   - Bob signs his signed pre-key (SPK) with his long-term identity key, and
 *     Alice VERIFIES that signature before using the bundle. This authenticates
 *     the handshake and defeats a man-in-the-middle who would substitute their
 *     own pre-key.
 *   - A one-time pre-key (OPK) contributes a fourth DH, giving the session
 *     forward secrecy against later compromise of Bob's long-term keys.
 *
 *   SK = HKDF( DH1 || DH2 || DH3 || DH4 )
 *
 * After X3DH the two parties initialize the ratchet ASYMMETRICALLY (see
 * {@link createAliceRatchetState} / {@link createBobRatchetState}); Bob's signed
 * pre-key doubles as his initial ratchet public key, exactly as in Signal.
 *
 * Simplification vs. production: identity keys are modeled as a separate X25519
 * key (for DH) plus an Ed25519 key (for signatures), because the Web Crypto API
 * does not expose Signal's XEdDSA (which uses one key for both). The pre-key
 * server, prekey rotation, and OPK exhaustion handling are out of scope.
 */

import { deriveSharedSecret, exportPublicKeyRaw, KeyPair } from './x25519';
import { SigningKeyPair, sign, verify } from './ed25519';
import { hkdf, DOMAIN_LABELS, kdfRk } from './hkdf';
import { RatchetState } from './dh-ratchet';

/** Alice's secret keys for initiating a session (both X25519). */
export interface AliceSessionInitKeys {
  identityKeyPair: KeyPair;
  ephemeralKeyPair: KeyPair;
}

/**
 * Bob's full set of secret pre-session keys.
 *
 *   - identityKeyPair        X25519 — used in the DH terms (IK_B)
 *   - identitySigningKeyPair Ed25519 — signs the SPK; pins Bob's identity
 *   - signedPreKeyPair       X25519 — SPK_B; also Bob's initial ratchet key
 *   - oneTimePreKeyPair      X25519 — OPK_B; single-use, adds the 4th DH
 */
export interface BobPreSessionKeys {
  identityKeyPair: KeyPair;
  identitySigningKeyPair: SigningKeyPair;
  signedPreKeyPair: KeyPair;
  oneTimePreKeyPair: KeyPair;
}

/**
 * Bob's PUBLIC pre-key bundle, as it would be fetched from a server. The signed
 * pre-key carries a signature by Bob's identity key so the initiator can verify
 * it was not substituted in transit.
 */
export interface BobPrekeyBundle {
  identityKey: CryptoKey;
  identitySigningKey: CryptoKey;
  signedPreKey: CryptoKey;
  /** Ed25519 signature over the raw bytes of `signedPreKey`. */
  signedPreKeySignature: ArrayBuffer;
  oneTimePreKey: CryptoKey;
}

/** Result of X3DH key agreement: the shared root key (SK). */
export interface SessionInitResult {
  rootKey: ArrayBuffer;
}

// X3DH uses a zero-filled salt for the initial KDF (no prior secret to mix in).
const X3DH_SALT = new Uint8Array(32).buffer;

/**
 * Build Bob's public pre-key bundle, signing the signed pre-key with his
 * Ed25519 identity key. This is what Bob would upload to the pre-key server.
 *
 * @param bobKeys - Bob's secret pre-session keys
 * @returns The public bundle an initiator can verify and consume
 */
export async function createBobPrekeyBundle(
  bobKeys: BobPreSessionKeys
): Promise<BobPrekeyBundle> {
  const signedPreKeyRaw = await exportPublicKeyRaw(bobKeys.signedPreKeyPair.publicKey);
  const signedPreKeySignature = await sign(
    bobKeys.identitySigningKeyPair.privateKey,
    signedPreKeyRaw
  );

  return {
    identityKey: bobKeys.identityKeyPair.publicKey,
    identitySigningKey: bobKeys.identitySigningKeyPair.publicKey,
    signedPreKey: bobKeys.signedPreKeyPair.publicKey,
    signedPreKeySignature,
    oneTimePreKey: bobKeys.oneTimePreKeyPair.publicKey,
  };
}

/**
 * X3DH from Alice's (initiator) perspective.
 *
 * First verifies the signed pre-key's signature against Bob's identity key —
 * aborting if it does not check out — then derives SK from four DH terms:
 *
 *   DH1 = DH(IK_A, SPK_B)    DH2 = DH(EK_A, IK_B)
 *   DH3 = DH(EK_A, SPK_B)    DH4 = DH(EK_A, OPK_B)
 *   SK  = HKDF(DH1 || DH2 || DH3 || DH4)
 *
 * @param aliceKeys - Alice's identity and ephemeral key pairs
 * @param bob - Bob's public pre-key bundle (from {@link createBobPrekeyBundle})
 * @returns The shared root key SK
 * @throws Error if the signed pre-key signature is invalid (possible MITM)
 */
export async function initiateSessionX3DH(
  aliceKeys: AliceSessionInitKeys,
  bob: BobPrekeyBundle
): Promise<SessionInitResult> {
  const signedPreKeyRaw = await exportPublicKeyRaw(bob.signedPreKey);
  const signatureValid = await verify(
    bob.identitySigningKey,
    bob.signedPreKeySignature,
    signedPreKeyRaw
  );
  if (!signatureValid) {
    throw new Error(
      'X3DH aborted: the signed pre-key signature is invalid. ' +
        "Bob's identity could not be authenticated (possible man-in-the-middle)."
    );
  }

  const dh1 = await deriveSharedSecret(aliceKeys.identityKeyPair.privateKey, bob.signedPreKey);
  const dh2 = await deriveSharedSecret(aliceKeys.ephemeralKeyPair.privateKey, bob.identityKey);
  const dh3 = await deriveSharedSecret(aliceKeys.ephemeralKeyPair.privateKey, bob.signedPreKey);
  const dh4 = await deriveSharedSecret(aliceKeys.ephemeralKeyPair.privateKey, bob.oneTimePreKey);

  const rootKey = await deriveRootKey([dh1, dh2, dh3, dh4]);
  [dh1, dh2, dh3, dh4].forEach(clearBuffer);
  return { rootKey };
}

/**
 * X3DH from Bob's (responder) perspective. Produces the same SK as Alice
 * because each DH term commutes.
 *
 *   DH1 = DH(SPK_B, IK_A)    DH2 = DH(IK_B, EK_A)
 *   DH3 = DH(SPK_B, EK_A)    DH4 = DH(OPK_B, EK_A)
 *
 * @param bobKeys - Bob's secret pre-session keys
 * @param alicePublicIK - Alice's identity public key (X25519)
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
  const dh4 = await deriveSharedSecret(bobKeys.oneTimePreKeyPair.privateKey, alicePublicEK);

  const rootKey = await deriveRootKey([dh1, dh2, dh3, dh4]);
  [dh1, dh2, dh3, dh4].forEach(clearBuffer);
  return { rootKey };
}

/**
 * Initialize Alice's ratchet (Signal's RatchetInitAlice).
 *
 * Alice is the initiator: she already knows Bob's ratchet public key (his signed
 * pre-key), so she performs the SENDING half of a DH ratchet immediately with a
 * fresh ratchet key pair and can send the first message.
 *
 *   DHs = aliceRatchetKeyPair;  DHr = bobSignedPreKeyPublic
 *   (RK, CKs) = KDF_RK(SK, DH(DHs, DHr));  CKr = none
 *
 * @param session - X3DH result (SK)
 * @param aliceRatchetKeyPair - Alice's initial ratchet key pair (DHs)
 * @param bobSignedPreKeyPublic - Bob's signed pre-key, used as the initial DHr
 */
export async function createAliceRatchetState(
  session: SessionInitResult,
  aliceRatchetKeyPair: KeyPair,
  bobSignedPreKeyPublic: CryptoKey
): Promise<RatchetState> {
  const dh = await deriveSharedSecret(aliceRatchetKeyPair.privateKey, bobSignedPreKeyPublic);
  const { rootKey, chainKey } = await kdfRk(session.rootKey, dh);
  clearBuffer(dh);

  return {
    rootKey,
    myDHKeyPair: aliceRatchetKeyPair,
    theirDHPublicKey: bobSignedPreKeyPublic,
    sendingChain: { chainKey, messageNumber: 0 },
    receivingChain: null,
    previousSendingChainLength: 0,
    dhRatchetCount: 0,
  };
}

/**
 * Initialize Bob's ratchet (Signal's RatchetInitBob).
 *
 * Bob is the responder: his signed pre-key pair IS his initial ratchet key pair.
 * He has no chains and no DHr yet; both are established when he receives Alice's
 * first message and performs his first DH ratchet.
 *
 *   DHs = bobSignedPreKeyPair;  DHr = none;  RK = SK;  CKs = CKr = none
 *
 * @param session - X3DH result (SK)
 * @param bobSignedPreKeyPair - Bob's signed pre-key pair (DHs)
 */
export function createBobRatchetState(
  session: SessionInitResult,
  bobSignedPreKeyPair: KeyPair
): RatchetState {
  return {
    rootKey: session.rootKey,
    myDHKeyPair: bobSignedPreKeyPair,
    theirDHPublicKey: null,
    sendingChain: null,
    receivingChain: null,
    previousSendingChainLength: 0,
    dhRatchetCount: 0,
  };
}

/** Concatenate the DH outputs and derive SK via HKDF. */
async function deriveRootKey(dhOutputs: ArrayBuffer[]): Promise<ArrayBuffer> {
  const concatenated = concatenateBuffers(dhOutputs);
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
