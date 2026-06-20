// @vitest-environment happy-dom
/**
 * End-to-end DOM smoke test: boot the real application (the same RatchetWireApp
 * the browser runs) against the real index.html, and verify the user-visible
 * flow actually works — authenticated handshake banner, sending a message, and
 * the man-in-the-middle demonstration.
 *
 * This is the closest proxy to "does it work in a browser?" available without a
 * live browser: the crypto path is the audited pure-JS @noble code (identical in
 * Node and the browser), and the DOM is driven through the same elements and
 * event handlers the page wires up.
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { webcrypto } from 'node:crypto';
import { describe, it, expect, beforeEach } from 'vitest';

// Some happy-dom builds expose `crypto` without a full SubtleCrypto; make sure
// the Web Crypto used for HKDF/AES-GCM/SHA-256 is Node's complete implementation.
if (!globalThis.crypto?.subtle) {
  Object.defineProperty(globalThis, 'crypto', { value: webcrypto, configurable: true });
}

const here = dirname(fileURLToPath(import.meta.url));
const indexHtml = readFileSync(resolve(here, '../../index.html'), 'utf8');
const bodyInner = (indexHtml.match(/<body>([\s\S]*?)<\/body>/)?.[1] ?? '')
  .replace(/<script[\s\S]*?<\/script>/g, '');

/** Poll until `predicate()` is truthy or the timeout elapses. */
async function waitFor(predicate: () => boolean, timeoutMs = 4000): Promise<void> {
  const start = Date.now();
  while (!predicate()) {
    if (Date.now() - start > timeoutMs) throw new Error('waitFor: timed out');
    await new Promise((r) => setTimeout(r, 5));
  }
}

describe('App integration (DOM smoke test)', () => {
  beforeEach(() => {
    document.documentElement.setAttribute('data-theme', 'dark');
    document.body.innerHTML = bodyInner;
  });

  it('boots, shows a verified handshake with a fingerprint', async () => {
    const { RatchetWireApp } = await import('../main');
    await new RatchetWireApp().init();

    const badge = document.getElementById('handshake-badge')!;
    const detail = document.getElementById('handshake-detail')!;
    expect(badge.textContent).toContain('Identity verified');
    // Fingerprint is rendered as space-separated hex byte pairs.
    expect(detail.textContent).toMatch(/[0-9A-F]{2}( [0-9A-F]{2}){7}/);
  });

  it('renders the X3DH handshake breakdown (4 DH terms + SK)', async () => {
    const { RatchetWireApp } = await import('../main');
    await new RatchetWireApp().init();

    const breakdown = document.getElementById('x3dh-breakdown')!;
    const formulas = Array.from(breakdown.querySelectorAll('.x3dh-formula')).map((n) => n.textContent);
    expect(formulas).toEqual([
      'DH1 = DH(IK_A, SPK_B)',
      'DH2 = DH(EK_A, IK_B)',
      'DH3 = DH(EK_A, SPK_B)',
      'DH4 = DH(EK_A, OPK_B)',
    ]);
    expect(breakdown.querySelector('.x3dh-ok')).not.toBeNull(); // signature verified
    expect(breakdown.querySelector('.x3dh-sk')!.textContent).toContain('SK = HKDF');
  });

  it('encrypts, delivers, and renders a sent message', async () => {
    const { RatchetWireApp } = await import('../main');
    await new RatchetWireApp().init();

    const input = document.getElementById('message-input') as HTMLInputElement;
    input.value = 'hello from the browser';
    document.getElementById('message-form')!.dispatchEvent(
      new Event('submit', { bubbles: true, cancelable: true })
    );

    await waitFor(() => !!document.querySelector('#messages .message-bubble'));
    expect(document.querySelector('#messages .message-bubble')!.textContent).toBe(
      'hello from the browser'
    );

    // The per-message wire inspector teaches the header format.
    const wire = document.querySelector('#messages .wire-detail .wire-fields');
    expect(wire).not.toBeNull();
    expect(wire!.textContent).toContain('header.messageNumber');
    expect(wire!.textContent).toContain('header.dhPublicKey');

    // The live message-key timeline records the derivation.
    const row = document.querySelector('#mk-timeline .mk-row');
    expect(row).not.toBeNull();
    expect(row!.querySelector('.mk-derivation')!.textContent).toContain('MK[0]');
    expect(row!.querySelector('.mk-fate')!.textContent).toMatch(/deleted/);
  });

  it('out-of-order demo: delivering m2 first stores skipped keys for m0 and m1', async () => {
    const { RatchetWireApp } = await import('../main');
    await new RatchetWireApp().init();

    (document.getElementById('ooo-generate') as HTMLButtonElement).click();
    await waitFor(() => document.querySelectorAll('#ooo-pending .ooo-deliver').length === 5);

    // Deliver m2 first (the third Deliver button).
    const deliverButtons = document.querySelectorAll<HTMLButtonElement>('#ooo-pending .ooo-deliver');
    deliverButtons[2].click();

    await waitFor(() => document.querySelectorAll('#ooo-store-keys .ooo-key-chip').length === 2);
    const chips = Array.from(document.querySelectorAll('#ooo-store-keys .ooo-key-chip')).map(
      (c) => c.textContent
    );
    expect(chips).toEqual(['m0', 'm1']);
    expect(document.getElementById('ooo-store-count')!.textContent).toBe('2 keys held');

    // Now deliver m0 — it should consume the stored key, leaving only m1.
    document.querySelector<HTMLButtonElement>('#ooo-pending .ooo-deliver')!.click();
    await waitFor(() => document.querySelectorAll('#ooo-store-keys .ooo-key-chip').length === 1);
    expect(document.querySelector('#ooo-store-keys .ooo-key-chip')!.textContent).toBe('m1');
  });

  it('forward-secrecy demo: a stolen chain key exposes future messages, not past ones', async () => {
    const { RatchetWireApp } = await import('../main');
    await new RatchetWireApp().init();

    (document.getElementById('fs-run') as HTMLButtonElement).click();
    await waitFor(() => document.querySelectorAll('#fs-table .fs-row').length === 6);

    // Default compromise point is 3: m0–m2 safe, m3–m5 exposed.
    const rows = Array.from(document.querySelectorAll('#fs-table .fs-row'));
    expect(rows.filter((r) => r.classList.contains('safe')).length).toBe(3);
    expect(rows.filter((r) => r.classList.contains('exposed')).length).toBe(3);
    expect(document.querySelector('#fs-table .fs-steal')).not.toBeNull();

    // Move the compromise point to 1 → only m0 stays safe.
    const points = document.querySelectorAll<HTMLButtonElement>('#fs-compromise .fs-point');
    points[1].click();
    await waitFor(
      () => document.querySelectorAll('#fs-table .fs-row.safe').length === 1
    );
    expect(document.querySelectorAll('#fs-table .fs-row.exposed').length).toBe(5);
  });

  it('demonstrates the MITM defense: a tampered pre-key is blocked', async () => {
    const { RatchetWireApp } = await import('../main');
    await new RatchetWireApp().init();

    (document.getElementById('mitm-demo-btn') as HTMLButtonElement).click();

    const result = document.getElementById('mitm-result')!;
    await waitFor(() => !result.hasAttribute('hidden') && /Blocked/i.test(result.textContent ?? ''));
    expect(result.textContent).toMatch(/Blocked/i);
    expect(result.classList.contains('mitm-blocked')).toBe(true);
  });
});
