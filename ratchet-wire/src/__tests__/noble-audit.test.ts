/* What "audited" covers for the @noble/curves this lab ships.
 *
 * src/crypto/x25519.ts and src/crypto/ed25519.ts both introduced the library as
 * "the audited `@noble/curves`", and the integration test's header called the
 * crypto path "the audited pure-JS @noble code" — none with a version. The
 * library records its latest independent audit as "at version 2.3.0, in Aug
 * 2026, by [Trail of Bits]", scope "everything", and this lab pins ^2.4.0.
 *
 * Both sides are read: the three lab files, and the installed library's own
 * README, so an upgrade that changes the audit record fails here.
 */
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const read = (rel: string) => readFileSync(new URL(rel, import.meta.url), 'utf8');
const flat = (text: string) => text.replace(/\n\s*\*\s?/g, ' ').replace(/\s+/g, ' ');

const nobleReadme = read('../../node_modules/@noble/curves/README.md');
const pkg = JSON.parse(read('../../package.json'));

describe('the @noble/curves audit claim', () => {
  it('pins a version later than the latest audit the library records', () => {
    expect(pkg.dependencies['@noble/curves']).toBe('^2.4.0');
    expect(nobleReadme).toContain('The library has been audited');
    expect(nobleReadme).toMatch(/at version 2\.3\.0, in Aug 2026, by \[Trail of Bits\]/);
    expect(nobleReadme).not.toMatch(/at version 2\.4\.\d+, in [A-Z]/);
  });

  it('no longer calls the shipped library simply "audited"', () => {
    for (const rel of [
      '../crypto/x25519.ts',
      '../crypto/ed25519.ts',
      './app.integration.test.ts',
    ]) {
      const text = flat(read(rel));
      expect(text, rel).not.toContain('the audited, pure-JavaScript `@noble/curves`');
      expect(text, rel).not.toContain('the audited `@noble/curves`');
      expect(text, rel).not.toContain('the audited pure-JS @noble code');
    }
  });

  it('states the audited version where the library is introduced', () => {
    const text = flat(read('../crypto/x25519.ts'));
    expect(text).toContain('at version 2.3.0, in Aug 2026, by [Trail of Bits]');
    expect(text).toContain('This lab pins ^2.4.0');
  });
});
