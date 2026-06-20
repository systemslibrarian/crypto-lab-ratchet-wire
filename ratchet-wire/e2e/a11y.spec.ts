import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

/**
 * Automated accessibility checks with axe-core, in both themes and across the
 * content-heavy tabs. Fails on any serious/critical WCAG 2.1 A/AA violation
 * (which includes colour-contrast — the thing most likely to regress with the
 * red/green demo styling).
 */

const TABS = ['conversation', 'x3dh', 'ooo', 'fs', 'state', 'compromise', 'about'] as const;

async function analyze(page: import('@playwright/test').Page) {
  const { violations } = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa']).analyze();
  return violations.filter((v) => v.impact === 'serious' || v.impact === 'critical');
}

for (const theme of ['dark', 'light'] as const) {
  test(`no serious/critical a11y violations across tabs (${theme})`, async ({ page }) => {
    // Running axe across seven tabs is heavy (especially on Firefox/WebKit), so
    // give these checks plenty of headroom over the default per-test timeout.
    test.setTimeout(120_000);
    await page.goto('/');
    // Kill animations outright so axe never samples an element mid-fade (which
    // would read theme colours at partial opacity and report false contrast
    // failures). The app's real reduced-motion support is unaffected.
    await page.addStyleTag({
      content: '*,*::before,*::after{animation:none!important;transition:none!important}',
    });
    if (theme === 'light') await page.click('#theme-toggle');

    // Populate the data-driven demos so axe sees their rendered output.
    await page.getByRole('button', { name: /Send a sample message/i }).click();
    await page.click('#tab-fs');
    await page.click('#fs-run');
    await page.click('#tab-ooo');
    await page.click('#ooo-generate');

    for (const tab of TABS) {
      await page.click(`#tab-${tab}`);
      const violations = await analyze(page);
      expect(
        violations,
        `${theme}/${tab}: ` + JSON.stringify(violations.map((v) => ({ id: v.id, nodes: v.nodes.length })))
      ).toEqual([]);
    }
  });
}
