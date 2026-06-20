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
