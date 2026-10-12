import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

test.beforeEach(async ({ page }) => {
  await page.goto('.');
  await expect(page.locator('#setup-status')).toContainText('Active: simplified classical');
});

test('a real hybrid setup seeds two-way messaging and authenticates prekeys and the initial ciphertext', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.getByRole('button', { name: /Send a sample message/ }).click();
  await expect(page.locator('#messages .message-bubble')).toHaveCount(1);
  await page.selectOption('#session-mode', 'hybrid');
  // Selecting a draft option must not change the already-running session.
  await expect(page.locator('#setup-status')).toContainText('Active: simplified classical');
  await page.click('#apply-session');
  await expect(page.locator('#setup-status')).toContainText('Active: PQXDH-style ML-KEM-1024');
  await expect(page.locator('#messages .message-bubble')).toHaveCount(0);
  await expect(page.locator('#handshake-detail')).toContainText('Identity not pinned');
  await page.click('#tab-x3dh');
  await expect(page.locator('#x3dh-breakdown')).toContainText('1568-byte ciphertext');
  await expect(page.locator('#x3dh-breakdown')).toContainText('F ‖ DH1 ‖ DH2 ‖ DH3 ‖ DH4 ‖ SS');
  await expect(page.locator('#x3dh-breakdown')).toContainText('authenticated Alice');
  await expect(page.locator('#x3dh-breakdown')).toContainText('One-time curve and KEM private prekeys consumed');
  await page.click('#kem-tamper-btn');
  await expect(page.locator('#kem-tamper-result')).toContainText('authentication failed');
  await expect(page.locator('#kem-tamper-result')).toContainText('prekeys were retained');
  await page.click('#tab-conversation');
  await page.click('#mitm-demo-btn');
  await expect(page.locator('#mitm-result')).toContainText('signed ML-KEM prekey signature is invalid');
  await page.fill('#message-input', 'hybrid Alice message');
  await page.click('#send-btn');
  await expect(page.locator('#messages .message-bubble')).toContainText(['hybrid Alice message']);
  await page.locator('input[name="sender"][value="bob"]').check();
  await page.fill('#message-input', 'hybrid Bob reply');
  await page.click('#send-btn');
  await expect(page.locator('#messages .message-bubble')).toContainText(['hybrid Alice message', 'hybrid Bob reply']);
  await expect(page.locator('#converge-b2a')).toHaveClass(/match/);
  await page.click('#tab-ooo');
  await page.click('#ooo-generate');
  await expect(page.locator('#ooo-pending .ooo-deliver')).toHaveCount(5);
  await page.locator('#ooo-pending .ooo-deliver').nth(2).click();
  await expect(page.locator('#ooo-store-keys .ooo-key-chip')).toHaveText(['m0', 'm1']);
  await page.locator('#ooo-pending .ooo-deliver').first().click();
  await expect(page.locator('#ooo-store-keys .ooo-key-chip')).toHaveText(['m1']);
  await page.selectOption('#session-mode', 'classical');
  await page.click('#apply-session');
  await expect(page.locator('#setup-status')).toContainText('Active: simplified classical');
  await expect(page.locator('#messages .message-bubble')).toHaveCount(0);
  await expect(page.locator('#setup-error')).toBeHidden();
  expect(errors).toEqual([]);
});

test('fallback setup retains its selected mode on restart and exposes the continuing-ratchet limitation', async ({ page }) => {
  await page.selectOption('#session-mode', 'hybrid');
  await page.selectOption('#kem-kind', 'last-resort');
  await page.click('#apply-session');
  await expect(page.locator('#setup-status')).toContainText('last-resort KEM prekey');
  await page.click('#tab-x3dh');
  await expect(page.locator('#x3dh-breakdown')).toContainText('last-resort KEM prekey is reusable and requires rotation');
  await page.click('#reset-btn');
  await expect(page.locator('#setup-status')).toContainText('last-resort KEM prekey');
  await page.click('#tab-about');
  await expect(page.locator('#signal-today')).toContainText('classical DH recovery only');
  await expect(page.locator('#signal-today')).toContainText('does not implement them');
  await expect(page.locator('#signal-today a[href="https://signal.org/docs/specifications/pqxdh/"]')).toBeVisible();
  await expect(page.locator('#signal-today a[href="https://signal.org/docs/specifications/doubleratchet/"]')).toBeVisible();
});

test('hybrid panels remain readable and accessible at phone and desktop widths', async ({ page }) => {
  await page.selectOption('#session-mode', 'hybrid');
  await page.click('#apply-session');
  await expect(page.locator('#setup-status')).toContainText('Initial AEAD accepted');
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  for (const width of [380, 1280]) {
    await page.setViewportSize({ width, height: 844 });
    for (const tab of ['x3dh', 'about']) {
      await page.click(`#tab-${tab}`);
      await expect(page.locator(`#${tab}`)).toBeVisible();
      await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth - innerWidth)).toBeLessThanOrEqual(1);
      const results = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa']).analyze();
      expect(results.violations).toEqual([]);
    }
  }
});
