import { describe, it, expect } from 'vitest';
import { hkdfSync } from 'node:crypto';
import { generateKeyPair } from '../crypto/x25519';
import { generateSigningKeyPair } from '../crypto/ed25519';
import { createAliceRatchetState, createBobRatchetState } from '../crypto/session-init';
import { encrypt, decrypt, type SkippedKeys } from '../crypto/double-ratchet';
import { createHybridBobKeys, createHybridBundle, initiateHybridSession, acceptHybridSession, deriveHybridRoot, HYBRID_INFO } from '../crypto/hybrid-session';

async function fixture(kind: 'one-time' | 'last-resort' = 'one-time', curveOneTime = true) {
  const curve = { identityKeyPair: await generateKeyPair(), identitySigningKeyPair: await generateSigningKeyPair(),
    signedPreKeyPair: await generateKeyPair(), oneTimePreKeyPair: await generateKeyPair() };
  const keys = createHybridBobKeys(curve, kind);
  const bundle = await createHybridBundle(keys, curveOneTime);
  const alice = { identityKeyPair: await generateKeyPair(), ephemeralKeyPair: await generateKeyPair() };
  return { keys, bundle, alice };
}

describe('real PQXDH-style hybrid setup', () => {
  it('matches an independent Node HKDF reference including F, ordered DH terms, SS and parameters', async () => {
    const terms = [1, 2, 3, 4].map(n => new Uint8Array(32).fill(n).buffer);
    const ss = new Uint8Array(32).fill(5);
    const ikm = Buffer.concat([Buffer.alloc(32, 255), ...terms.map(t => Buffer.from(t)), Buffer.from(ss)]);
    const expected = hkdfSync('sha256', ikm, Buffer.alloc(32), HYBRID_INFO, 32);
    expect(new Uint8Array(await deriveHybridRoot(terms, ss))).toEqual(new Uint8Array(expected));
    const unprefixed = hkdfSync('sha256', ikm.subarray(32), Buffer.alloc(32), HYBRID_INFO, 32);
    expect(new Uint8Array(expected)).not.toEqual(new Uint8Array(unprefixed));
    expect(new Uint8Array(await deriveHybridRoot(terms, new Uint8Array(32).fill(6)))).not.toEqual(new Uint8Array(expected));
    await expect(deriveHybridRoot(terms.slice(0, 2), ss)).rejects.toThrow('three or four');
    await expect(deriveHybridRoot(terms, new Uint8Array(31))).rejects.toThrow('32-byte');
  });

  for (const kind of ['one-time', 'last-resort'] as const) {
    for (const curveOneTime of [true, false]) {
      it(`independently agrees and authenticates with ${kind} KEM and curve OPK=${curveOneTime}`, async () => {
        const { keys, bundle, alice } = await fixture(kind, curveOneTime);
        const a = await initiateHybridSession(alice, bundle);
        const b = await acceptHybridSession(keys, a.initial);
        expect(new Uint8Array(b.rootKey)).toEqual(new Uint8Array(a.session.rootKey));
        expect(new Uint8Array(b.associatedData)).toEqual(new Uint8Array(a.session.associatedData));
        expect(a.trace.terms).toHaveLength(curveOneTime ? 4 : 3);
        expect(a.trace.kemPublicBytes).toBe(1568);
        expect(a.initial.kemCiphertext.length).toBe(1568);
        expect(keys.kemConsumed).toBe(kind === 'one-time');
        expect(keys.curveConsumed).toBe(curveOneTime);
        if (kind === 'one-time') expect(keys.kem.secretKey.every(x => x === 0)).toBe(true);
        else expect(keys.kem.secretKey.some(x => x !== 0)).toBe(true);
        if (curveOneTime) expect(keys.curve.oneTimePreKeyPair.privateKey.every(x => x === 0)).toBe(true);
        if (kind === 'one-time' || curveOneTime) {
          await expect(acceptHybridSession(keys, a.initial)).rejects.toThrow('already consumed');
          await expect(createHybridBundle(keys, curveOneTime)).rejects.toThrow('already consumed');
        }
      });
    }
  }

  for (const field of ['signedPreKeySignature', 'kemSignature'] as const) {
    it(`rejects a bad ${field} before ML-KEM encapsulation`, async () => {
      const { keys, bundle, alice } = await fixture();
      const signature = bundle[field].slice(0);
      new Uint8Array(signature)[0] ^= 1;
      // A different correctly sized KEM key would be accepted by encapsulate.
      // Signature rejection must happen before that operation.
      await expect(initiateHybridSession(alice, {
        ...bundle,
        [field]: signature,
        kemPublicKey: new Uint8Array(bundle.kemPublicKey.length),
      })).rejects.toThrow('signature is invalid');
      expect(keys.kemConsumed).toBe(false);
    });
  }

  for (const field of ['kemCiphertext', 'ciphertext', 'aliceIdentity', 'nonce'] as const) {
    it(`rejects altered ${field} without consuming private prekeys, then accepts the authentic retry`, async () => {
      const { keys, bundle, alice } = await fixture();
      const a = await initiateHybridSession(alice, bundle);
      const originalKem = keys.kem.secretKey.slice();
      const originalCurve = keys.curve.oneTimePreKeyPair.privateKey.slice();
      const bad = a.initial[field].slice(0);
      if (bad instanceof Uint8Array) bad[0] ^= 1;
      else new Uint8Array(bad)[0] ^= 1;
      await expect(acceptHybridSession(keys, { ...a.initial, [field]: bad })).rejects.toThrow();
      expect(keys.kem.secretKey).toEqual(originalKem);
      expect(keys.curve.oneTimePreKeyPair.privateKey).toEqual(originalCurve);
      expect(keys.kemConsumed).toBe(false);
      expect(keys.curveConsumed).toBe(false);
      expect(new Uint8Array((await acceptHybridSession(keys, a.initial)).rootKey)).toEqual(new Uint8Array(a.session.rootKey));
    });
  }

  it('refuses unknown prekey IDs, kinds, and malformed KEM ciphertext lengths', async () => {
    const { keys, bundle, alice } = await fixture();
    const a = await initiateHybridSession(alice, bundle);
    await expect(acceptHybridSession(keys, { ...a.initial, kemId: 'unknown' })).rejects.toThrow('identifier');
    await expect(acceptHybridSession(keys, { ...a.initial, kemKind: 'last-resort' })).rejects.toThrow('identifier or kind');
    await expect(acceptHybridSession(keys, { ...a.initial, kemCiphertext: a.initial.kemCiphertext.slice(1) })).rejects.toThrow('Malformed');
    await expect(initiateHybridSession(alice, { ...bundle, kemId: 'unknown' })).rejects.toThrow('identifier');
    expect(keys.kemConsumed).toBe(false);
  });

  it('rejects malformed runtime fields before KEM or DH work and retains prekeys', async () => {
    const { keys, bundle, alice } = await fixture();
    await expect(initiateHybridSession(alice, {
      ...bundle,
      kemPublicKey: new Uint8Array(bundle.kemPublicKey.length - 1),
    })).rejects.toThrow(/Malformed hybrid message/);

    const a = await initiateHybridSession(alice, bundle);
    await expect(acceptHybridSession(keys, {
      ...a.initial,
      aliceIdentity: new Uint8Array(31),
    })).rejects.toThrow(/Malformed hybrid message/);
    await expect(acceptHybridSession(keys, {
      ...a.initial,
      usesCurveOneTime: 'yes' as unknown as boolean,
    })).rejects.toThrow(/Malformed hybrid message/);
    await expect(acceptHybridSession(keys, {
      ...a.initial,
      ciphertext: new ArrayBuffer(a.initial.ciphertext.byteLength + 1),
    })).rejects.toThrow(/Malformed hybrid message/);
    expect(keys.kemConsumed).toBe(false);
    expect(keys.curveConsumed).toBe(false);
  });

  it('binds both the curve and the KEM prekey: swapping either without a new signature aborts', async () => {
    const f = await fixture();
    const other = await fixture();
    await expect(initiateHybridSession(f.alice, { ...f.bundle, kemPublicKey: other.bundle.kemPublicKey })).rejects.toThrow('signature is invalid');
    await expect(initiateHybridSession(f.alice, { ...f.bundle, signedPreKey: other.bundle.signedPreKey })).rejects.toThrow('signature is invalid');
  });

  it('requires external identity verification: an entirely substituted valid bundle is not detected by signatures alone', async () => {
    const intended = await fixture();
    const substituted = await fixture();
    expect(substituted.bundle.identitySigningKey).not.toEqual(intended.bundle.identitySigningKey);
    const a = await initiateHybridSession(intended.alice, substituted.bundle);
    expect(new Uint8Array((await acceptHybridSession(substituted.keys, a.initial)).rootKey)).toEqual(new Uint8Array(a.session.rootKey));
  });

  it('supports real two-way ratcheting and skipped messages, and rejects altered session identity AD transactionally', async () => {
    const { keys, bundle, alice } = await fixture();
    const a = await initiateHybridSession(alice, bundle);
    const b = await acceptHybridSession(keys, a.initial);
    let aliceState = await createAliceRatchetState(a.session, await generateKeyPair(), bundle.signedPreKey);
    let bobState = createBobRatchetState(b, keys.curve.signedPreKeyPair);
    let skipped: SkippedKeys = new Map();
    const pending = [];
    for (let i = 0; i < 3; i++) {
      const sent = await encrypt(aliceState, `message ${i}`);
      aliceState = sent.newState;
      pending.push(sent.message);
    }
    const badAd = b.associatedData.slice(0);
    new Uint8Array(badAd)[0] ^= 1;
    const beforeRoot = bobState.rootKey.slice(0);
    await expect(decrypt({ ...bobState, associatedData: badAd }, pending[2], skipped)).rejects.toThrow();
    expect(new Uint8Array(bobState.rootKey)).toEqual(new Uint8Array(beforeRoot));
    expect(skipped.size).toBe(0);
    for (const i of [2, 0, 1]) {
      const r = await decrypt(bobState, pending[i], skipped);
      expect(r.plaintext).toBe(`message ${i}`);
      bobState = r.newState; skipped = r.skippedKeys;
      expect(new Uint8Array(bobState.associatedData!)).toEqual(new Uint8Array(b.associatedData));
    }
    expect(skipped.size).toBe(0);
    const reply = await encrypt(bobState, 'reply from Bob');
    const r = await decrypt(aliceState, reply.message);
    expect(r.plaintext).toBe('reply from Bob');
    expect(new Uint8Array(r.newState.associatedData!)).toEqual(new Uint8Array(a.session.associatedData));
  });
});
