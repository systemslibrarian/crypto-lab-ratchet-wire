/**
 * PQXDH-style educational setup, composed with the existing Double Ratchet.
 * Signal PQXDH rev. 3 §§2.1–2.2, 3.3–3.4; Double Ratchet rev. 4 §7.1.
 * https://signal.org/docs/specifications/pqxdh/
 *
 * Real X25519 + ML-KEM-1024 + HKDF-SHA256 + AES-256-GCM. This is NOT
 * libsignal-compatible: separate Ed25519/X25519 identities, lab encodings and
 * application labels, ML-KEM rather than the older Kyber wire format. It adds
 * a handshake, NOT SPQR / ML-KEM Braid / the Triple Ratchet.
 */
import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import { deriveSharedSecret } from './x25519';
import { sign, verify } from './ed25519';
import { hkdf } from './hkdf';
import { toArrayBuffer } from './bytes';
import type { AliceSessionInitKeys, BobPreSessionKeys, SessionInitResult, X3DHBreakdown } from './session-init';

export const HYBRID_INFO = 'RatchetWire-v1_CURVE25519_SHA-256_ML-KEM-1024';
type PrekeyKind = 'one-time' | 'last-resort';
export interface HybridBobKeys {
  curve: BobPreSessionKeys;
  kem: { publicKey: Uint8Array; secretKey: Uint8Array };
  kind: PrekeyKind;
  curveConsumed: boolean;
  kemConsumed: boolean;
}
export interface HybridBundle {
  identityKey: Uint8Array;
  identitySigningKey: Uint8Array;
  signedPreKey: Uint8Array;
  signedPreKeySignature: ArrayBuffer;
  oneTimePreKey: Uint8Array | null;
  kemPublicKey: Uint8Array;
  kemSignature: ArrayBuffer;
  kemId: string;
  kemKind: PrekeyKind;
}
export interface HybridInitialMessage {
  aliceIdentity: Uint8Array;
  aliceEphemeral: Uint8Array;
  kemId: string;
  kemKind: PrekeyKind;
  usesCurveOneTime: boolean;
  kemCiphertext: Uint8Array;
  nonce: Uint8Array;
  ciphertext: ArrayBuffer;
}
export interface HybridSessionResult extends SessionInitResult {
  associatedData: ArrayBuffer;
}
export interface HybridTrace extends X3DHBreakdown {
  kemSecretFingerprint: string;
  kemPublicBytes: number;
  kemCiphertextBytes: number;
  kemKind: PrekeyKind;
  usesCurveOneTime: boolean;
}

function concat(...parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const part of parts) { out.set(part, offset); offset += part.length; }
  return out;
}
// Lab-specific, disjoint type encodings: curve / KEM / Ed25519 signing key.
const encode = (tag: number, key: Uint8Array) => concat(Uint8Array.of(tag), key);
const fp = (b: Uint8Array) => Array.from(b.slice(0, 8), x => x.toString(16).padStart(2, '0')).join('').toUpperCase() + '…';
async function id(key: Uint8Array): Promise<string> {
  return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', toArrayBuffer(key))), x => x.toString(16).padStart(2, '0')).join('');
}
function associatedData(alice: Uint8Array, bob: Uint8Array, signing: Uint8Array, kem: Uint8Array): ArrayBuffer {
  // PQXDH identity AD plus additional model identity and KEM binding.
  return toArrayBuffer(concat(encode(5, alice), encode(5, bob), encode(7, signing), encode(6, kem)));
}

/** F prefix and parameter-specific info are included; legacy X3DH is unchanged. */
export async function deriveHybridRoot(terms: ArrayBuffer[], ss: Uint8Array): Promise<ArrayBuffer> {
  if ((terms.length !== 3 && terms.length !== 4) || terms.some(t => t.byteLength !== 32) || ss.length !== 32) {
    throw new Error('Hybrid KDF requires three or four 32-byte DH terms and a 32-byte KEM secret.');
  }
  const ikm = concat(new Uint8Array(32).fill(0xff), ...terms.map(t => new Uint8Array(t)), ss);
  try { return await hkdf(toArrayBuffer(ikm), new Uint8Array(32).buffer, HYBRID_INFO, 32); }
  finally { ikm.fill(0); }
}

export function createHybridBobKeys(curve: BobPreSessionKeys, kind: PrekeyKind = 'one-time'): HybridBobKeys {
  if (kind !== 'one-time' && kind !== 'last-resort') throw new Error('Unknown KEM prekey kind.');
  return { curve, kem: ml_kem1024.keygen(), kind, curveConsumed: false, kemConsumed: false };
}

export async function createHybridBundle(keys: HybridBobKeys, includeCurveOneTime = true): Promise<HybridBundle> {
  if (keys.kemConsumed || (includeCurveOneTime && keys.curveConsumed)) throw new Error('One-time prekey already consumed.');
  const b = keys.curve;
  return {
    identityKey: b.identityKeyPair.publicKey.slice(),
    identitySigningKey: b.identitySigningKeyPair.publicKey.slice(),
    signedPreKey: b.signedPreKeyPair.publicKey.slice(),
    signedPreKeySignature: await sign(b.identitySigningKeyPair.privateKey, encode(5, b.signedPreKeyPair.publicKey)),
    oneTimePreKey: includeCurveOneTime ? b.oneTimePreKeyPair.publicKey.slice() : null,
    kemPublicKey: keys.kem.publicKey.slice(),
    kemSignature: await sign(b.identitySigningKeyPair.privateKey, encode(6, keys.kem.publicKey)),
    kemId: await id(keys.kem.publicKey),
    kemKind: keys.kind,
  };
}

export async function initiateHybridSession(alice: AliceSessionInitKeys, bob: HybridBundle): Promise<{
  session: HybridSessionResult; initial: HybridInitialMessage; trace: HybridTrace;
}> {
  if (bob.kemKind !== 'one-time' && bob.kemKind !== 'last-resort') throw new Error('Unknown KEM prekey kind.');
  if (!(await verify(bob.identitySigningKey, bob.signedPreKeySignature, encode(5, bob.signedPreKey)))) {
    throw new Error('Hybrid setup aborted: signed curve prekey signature is invalid.');
  }
  if (!(await verify(bob.identitySigningKey, bob.kemSignature, encode(6, bob.kemPublicKey)))) {
    throw new Error('Hybrid setup aborted: signed ML-KEM prekey signature is invalid.');
  }
  if (bob.kemId !== await id(bob.kemPublicKey)) throw new Error('KEM prekey identifier does not match its public key.');
  const terms: ArrayBuffer[] = [];
  let ss: Uint8Array | undefined;
  let root: ArrayBuffer | undefined;
  try {
    terms.push(await deriveSharedSecret(alice.identityKeyPair.privateKey, bob.signedPreKey));
    terms.push(await deriveSharedSecret(alice.ephemeralKeyPair.privateKey, bob.identityKey));
    terms.push(await deriveSharedSecret(alice.ephemeralKeyPair.privateKey, bob.signedPreKey));
    if (bob.oneTimePreKey) terms.push(await deriveSharedSecret(alice.ephemeralKeyPair.privateKey, bob.oneTimePreKey));
    const encapsulated = ml_kem1024.encapsulate(bob.kemPublicKey);
    ss = encapsulated.sharedSecret;
    root = await deriveHybridRoot(terms, ss);
    const ad = associatedData(alice.identityKeyPair.publicKey, bob.identityKey, bob.identitySigningKey, bob.kemPublicKey);
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const key = await crypto.subtle.importKey('raw', root, 'AES-GCM', false, ['encrypt']);
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: ad }, key,
      new TextEncoder().encode('Ratchet Wire hybrid session confirmation'));
    const formulas = ['DH(IK_A, SPK_B)', 'DH(EK_A, IK_B)', 'DH(EK_A, SPK_B)', 'DH(EK_A, OPK_B)'];
    return {
      session: { rootKey: root, associatedData: ad },
      initial: { aliceIdentity: alice.identityKeyPair.publicKey.slice(), aliceEphemeral: alice.ephemeralKeyPair.publicKey.slice(),
        kemId: bob.kemId, kemKind: bob.kemKind, usesCurveOneTime: !!bob.oneTimePreKey,
        kemCiphertext: encapsulated.cipherText, nonce, ciphertext },
      trace: { signatureVerified: true, terms: terms.map((t, i) => ({ name: `DH${i + 1}`, formula: formulas[i], value: fp(new Uint8Array(t)) })),
        rootKey: fp(new Uint8Array(root)), kemSecretFingerprint: fp(ss), kemPublicBytes: bob.kemPublicKey.length,
        kemCiphertextBytes: encapsulated.cipherText.length, kemKind: bob.kemKind, usesCurveOneTime: !!bob.oneTimePreKey },
    };
  } catch (error) { if (root) new Uint8Array(root).fill(0); throw error; }
  finally { for (const t of terms) new Uint8Array(t).fill(0); ss?.fill(0); }
}

/** Only consume one-time keys after the initial AEAD authenticates successfully. */
export async function acceptHybridSession(keys: HybridBobKeys, initial: HybridInitialMessage): Promise<HybridSessionResult> {
  if (keys.kemConsumed || (initial.usesCurveOneTime && keys.curveConsumed)) throw new Error('One-time prekey already consumed.');
  if (initial.kemKind !== keys.kind || initial.kemId !== await id(keys.kem.publicKey)) throw new Error('Unknown KEM prekey identifier or kind.');
  if (initial.kemCiphertext.length !== ml_kem1024.lengths.cipherText || initial.nonce.length !== 12) throw new Error('Malformed hybrid initial message.');
  const b = keys.curve;
  const terms: ArrayBuffer[] = [];
  let ss: Uint8Array | undefined;
  let root: ArrayBuffer | undefined;
  try {
    terms.push(await deriveSharedSecret(b.signedPreKeyPair.privateKey, initial.aliceIdentity));
    terms.push(await deriveSharedSecret(b.identityKeyPair.privateKey, initial.aliceEphemeral));
    terms.push(await deriveSharedSecret(b.signedPreKeyPair.privateKey, initial.aliceEphemeral));
    if (initial.usesCurveOneTime) terms.push(await deriveSharedSecret(b.oneTimePreKeyPair.privateKey, initial.aliceEphemeral));
    ss = ml_kem1024.decapsulate(initial.kemCiphertext, keys.kem.secretKey);
    root = await deriveHybridRoot(terms, ss);
    const ad = associatedData(initial.aliceIdentity, b.identityKeyPair.publicKey, b.identitySigningKeyPair.publicKey, keys.kem.publicKey);
    const key = await crypto.subtle.importKey('raw', root, 'AES-GCM', false, ['decrypt']);
    const confirmation = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: toArrayBuffer(initial.nonce), additionalData: ad }, key, initial.ciphertext);
    new Uint8Array(confirmation).fill(0);
    if (initial.usesCurveOneTime) { b.oneTimePreKeyPair.privateKey.fill(0); keys.curveConsumed = true; }
    if (keys.kind === 'one-time') { keys.kem.secretKey.fill(0); keys.kemConsumed = true; }
    return { rootKey: root, associatedData: ad };
  } catch (error) { if (root) new Uint8Array(root).fill(0); throw error; }
  finally { for (const t of terms) new Uint8Array(t).fill(0); ss?.fill(0); }
}
