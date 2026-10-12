import { readFileSync } from 'node:fs';
import { describe, it, expect } from 'vitest';
import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js';

// Independently published NIST ACVP inputs/expected outputs, not values generated
// by this library. The fixture pins the upstream commit, blob and corpus hash.
const vectors = JSON.parse(readFileSync(new URL('./fixtures/mlkem1024-acvp.json', import.meta.url), 'utf8'));
const bytes = (hex: string) => Uint8Array.from(Buffer.from(hex, 'hex'));

describe('ML-KEM-1024 independent NIST reference', () => {
  it('matches ACVP group 3 case 51 encapsulation ciphertext and shared secret', () => {
    const v = vectors.encapsulation;
    const result = ml_kem1024.encapsulate(bytes(v.ek), bytes(v.m));
    expect(result.cipherText).toEqual(bytes(v.c));
    expect(result.sharedSecret).toEqual(bytes(v.k));
    expect(ml_kem1024.decapsulate(bytes(v.c), bytes(v.dk))).toEqual(bytes(v.k));
  });

  it('matches ACVP group 6 case 96 decapsulation, including implicit rejection', () => {
    const v = vectors.decapsulation;
    expect(ml_kem1024.decapsulate(bytes(v.c), bytes(v.dk))).toEqual(bytes(v.k));
  });
});
