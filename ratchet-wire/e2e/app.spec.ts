import { test, expect } from '@playwright/test';

/**
 * Real-browser smoke test of the production build. Mirrors the happy-dom
 * integration suite, but in actual Chromium/Firefox/WebKit — the definitive
 * "it works in a browser" check (catches real Web Crypto + CSS behavior that a
 * DOM simulation cannot).
 */

test.beforeEach(async ({ page }) => {
  await page.goto('/');
});

test('the guided tour advances step-by-step and drives the tabs', async ({ page }) => {
  await expect(page.locator('#guide-panel')).toBeVisible();
  await expect(page.locator('#guide-step')).toHaveText('Step 1 of 7');

  await page.click('#guide-next');
  await expect(page.locator('#guide-step')).toHaveText('Step 2 of 7');
  await expect(page.locator('#tab-x3dh')).toHaveAttribute('aria-selected', 'true');

  await page.click('#guide-dismiss');
  await expect(page.locator('#guide-panel')).toBeHidden();
  await expect(page.locator('#guide-reopen')).toBeVisible();
});

test('boots with an authenticated handshake', async ({ page }) => {
  await expect(page.locator('#handshake-badge')).toContainText('Identity verified');
  await expect(page.locator('#handshake-detail')).toContainText(/[0-9A-F]{2}( [0-9A-F]{2}){7}/);
});

test('the sample button sends and renders a message with its wire inspector', async ({ page }) => {
  await page.getByRole('button', { name: /Send a sample message/i }).click();
  await expect(page.locator('#messages .message-bubble').first()).toContainText('Hi Bob');
  await expect(page.locator('#messages .wire-detail .wire-fields').first()).toContainText(
    'header.messageNumber'
  );
});

test('the coach narrates the event and guides the next step', async ({ page }) => {
  await page.getByRole('button', { name: /Send a sample message/i }).click();
  await expect(page.locator('#coach')).toBeVisible();
  await expect(page.locator('#coach-what')).toContainText(/DH ratchet/i);

  // Follow the suggested action; it switches the composer to Bob.
  await page.locator('#coach-next .coach-action').click();
  await expect(page.locator('input[name="sender"][value="bob"]')).toBeChecked();

  // A same-direction follow-up is narrated as a symmetric-only step.
  await page.fill('#message-input', 'reply one');
  await page.click('#send-btn');
  await page.fill('#message-input', 'reply two');
  await page.click('#send-btn');
  await expect(page.locator('#coach-what')).toContainText(/symmetric ratchet/i);
});

test('free-form send works too', async ({ page }) => {
  await page.fill('#message-input', 'hello from a real browser');
  await page.click('#send-btn');
  await expect(page.locator('#messages .message-bubble').first()).toHaveText(
    'hello from a real browser'
  );
});

test('X3DH tab shows the four DH terms and the derived root key', async ({ page }) => {
  await page.click('#tab-x3dh');
  await expect(page.locator('#x3dh-breakdown .x3dh-formula')).toHaveCount(4);
  await expect(page.locator('#x3dh-breakdown .x3dh-sk')).toContainText('SK = HKDF');
});

test('forward-secrecy demo splits past (safe) from future (exposed)', async ({ page }) => {
  await page.click('#tab-fs');
  await page.click('#fs-run');
  await expect(page.locator('#fs-table .fs-row')).toHaveCount(6);
  await expect(page.locator('#fs-table .fs-row.safe')).toHaveCount(3);
  await expect(page.locator('#fs-table .fs-row.exposed')).toHaveCount(3);

  // Move the compromise point earlier → fewer past, more exposed.
  await page.locator('#fs-compromise .fs-point').nth(1).click();
  await expect(page.locator('#fs-table .fs-row.safe')).toHaveCount(1);
  await expect(page.locator('#fs-table .fs-row.exposed')).toHaveCount(5);
});

test('out-of-order demo stores skipped keys then drains them', async ({ page }) => {
  await page.click('#tab-ooo');
  await page.click('#ooo-generate');
  await expect(page.locator('#ooo-pending .ooo-deliver')).toHaveCount(5);

  // Deliver m2 first → keys for m0, m1 are stored.
  await page.locator('#ooo-pending .ooo-deliver').nth(2).click();
  await expect(page.locator('#ooo-store-keys .ooo-key-chip')).toHaveText(['m0', 'm1']);

  // Deliver m0 → its stored key is consumed.
  await page.locator('#ooo-pending .ooo-deliver').first().click();
  await expect(page.locator('#ooo-store-keys .ooo-key-chip')).toHaveText(['m1']);
});

test('the MITM demo rejects a tampered pre-key', async ({ page }) => {
  await page.getByRole('button', { name: /Simulate a tampered pre-key/i }).click();
  await expect(page.locator('#mitm-result')).toContainText(/Blocked/i);
});
