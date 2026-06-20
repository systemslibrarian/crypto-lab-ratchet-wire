/**
 * Shared test helper: establish a synced Alice/Bob Double Ratchet session via
 * the authenticated X3DH handshake, exactly as the application does at startup.
 *
 * (Not a test file — excluded by Vitest's default `*.test.ts` include glob.)
 */

import { generateKeyPair, KeyPair } from '../crypto/x25519';
import { generateSigningKeyPair } from '../crypto/ed25519';
import {
  createBobPrekeyBundle,
  initiateSessionX3DH,
  acceptSessionX3DH,
  createAliceRatchetState,
  createBobRatchetState,
  BobPreSessionKeys,
} from '../crypto/session-init';
import { RatchetState } from '../crypto/dh-ratchet';

export interface Session {
  aliceState: RatchetState;
  bobState: RatchetState;
}

/** Run authenticated X3DH from both perspectives and initialize both ratchets. */
export async function establishSession(): Promise<Session> {
  const aliceIK = await generateKeyPair();
  const aliceEK = await generateKeyPair();
  const aliceRatchet: KeyPair = await generateKeyPair();

  const bobKeys: BobPreSessionKeys = {
    identityKeyPair: await generateKeyPair(),
    identitySigningKeyPair: await generateSigningKeyPair(),
    signedPreKeyPair: await generateKeyPair(),
    oneTimePreKeyPair: await generateKeyPair(),
  };
  const bobBundle = await createBobPrekeyBundle(bobKeys);

  const aliceSession = await initiateSessionX3DH(
    { identityKeyPair: aliceIK, ephemeralKeyPair: aliceEK },
    bobBundle
  );
  const bobSession = await acceptSessionX3DH(bobKeys, aliceIK.publicKey, aliceEK.publicKey);

  // Bob's signed pre-key doubles as his initial ratchet key.
  const aliceState = await createAliceRatchetState(
    aliceSession,
    aliceRatchet,
    bobKeys.signedPreKeyPair.publicKey
  );
  const bobState = createBobRatchetState(bobSession, bobKeys.signedPreKeyPair);

  return { aliceState, bobState };
}

/** Hex-encode the first `n` bytes of a buffer (for comparisons in assertions). */
export function toHex(buffer: ArrayBuffer, n = 32): string {
  return Array.from(new Uint8Array(buffer).slice(0, n))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}
