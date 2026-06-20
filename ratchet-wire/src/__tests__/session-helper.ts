/**
 * Shared test helper: establish a synced Alice/Bob Double Ratchet session via
 * the simplified X3DH, exactly as the application does at startup.
 *
 * (Not a test file — excluded by Vitest's default `*.test.ts` include glob.)
 */

import { generateKeyPair, KeyPair } from '../crypto/x25519';
import {
  initiateSessionX3DH,
  acceptSessionX3DH,
  createAliceRatchetState,
  createBobRatchetState,
} from '../crypto/session-init';
import { RatchetState } from '../crypto/dh-ratchet';

export interface Session {
  aliceState: RatchetState;
  bobState: RatchetState;
}

/** Run X3DH from both perspectives and initialize both ratchets. */
export async function establishSession(): Promise<Session> {
  const aliceIK = await generateKeyPair();
  const aliceEK = await generateKeyPair();
  const bobIK = await generateKeyPair();
  const bobSPK = await generateKeyPair();
  const aliceRatchet: KeyPair = await generateKeyPair();
  const bobRatchet: KeyPair = await generateKeyPair();

  const aliceSession = await initiateSessionX3DH(
    { identityKeyPair: aliceIK, ephemeralKeyPair: aliceEK },
    bobIK.publicKey,
    bobSPK.publicKey
  );
  const bobSession = await acceptSessionX3DH(
    { identityKeyPair: bobIK, signedPreKeyPair: bobSPK },
    aliceIK.publicKey,
    aliceEK.publicKey
  );

  const aliceState = await createAliceRatchetState(
    aliceSession,
    aliceRatchet,
    bobRatchet.publicKey
  );
  const bobState = createBobRatchetState(bobSession, bobRatchet);

  return { aliceState, bobState };
}

/** Hex-encode the first `n` bytes of a buffer (for comparisons in assertions). */
export function toHex(buffer: ArrayBuffer, n = 32): string {
  return Array.from(new Uint8Array(buffer).slice(0, n))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}
