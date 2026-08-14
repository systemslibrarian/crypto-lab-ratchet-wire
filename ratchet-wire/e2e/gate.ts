import AxeBuilder from '@axe-core/playwright'
import { expect, type Page } from '@playwright/test'
import { auditContrast, formatContrastFailures } from './contrast'
import { auditNonText } from './nontext'
import { NONTEXT_BASELINE } from './nontext-baseline'

export const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa']

/** A phone-width viewport, for the WCAG 1.4.10 reflow half of the gate. */
export const NARROW = { width: 380, height: 800 }

/**
 * Shared machinery for the WCAG gate.
 *
 * Five rules govern everything here, and each one corrects a specific thing the
 * gate this replaces did:
 *
 *  1. NOTHING IS INJECTED INTO THE PAGE BEFORE A SCAN. The old spec pushed
 *     `*,*::before,*::after{animation:none!important;transition:none!important}`
 *     through `addStyleTag`, with a comment saying "the app's real
 *     reduced-motion support is unaffected". That is exactly the problem: the
 *     injection BYPASSED `style.css`'s own
 *     `@media (prefers-reduced-motion: reduce)` block instead of exercising it,
 *     so the block was never once measured. This gate sets the real preference
 *     with `emulateMedia` and asserts from inside the page that it took effect.
 *     Both of this lab's reduced-motion blocks were then read declaration by
 *     declaration: each sets only `animation-duration`, `animation-iteration-count`,
 *     `transition-duration` and `scroll-behavior`, so no element's route to its
 *     visible state is cancelled. `expectNotBlank` measures that in every state
 *     rather than trusting it — this lab's two `@keyframes` (`fadeIn` on
 *     `.tab-content`, `slideUp` on a new `.message`) both animate FROM
 *     `opacity: 0`, which is precisely the shape that strands an element
 *     invisible if a reduced-motion block ever cancels them outright.
 *
 *  2. IT NEVER LOOKED AT MOST OF THE LAB. The old spec clicked seven controls
 *     and then walked the eight tabs, scanning each — which sounds thorough and
 *     is not: it scanned each tab in whatever state the page happened to be in
 *     at the end of that one sequence. The guided tour was never advanced, so
 *     six of its seven steps were never rendered; `#coach`, `#mitm-result`,
 *     `#composer-hint`, `#quiz-retry` and all three `.sim-state` blocks on the
 *     Break-In Recovery tab ship behind the `hidden` attribute and none of them
 *     was ever un-hidden; the entire Break-In Recovery sequence — the one place
 *     in the lab with a LOCKED control that unlocks in stages — was never
 *     touched at all. This drive names every control it touches, waits on a real
 *     completion signal after each, and scans after every step.
 *
 *  3. IT FILTERED THE VIOLATIONS. `analyze()`'s results were passed through
 *     `.filter(v => v.impact === 'serious' || v.impact === 'critical')`, so
 *     every moderate and minor finding — which is where most landmark, ARIA and
 *     name-role-value failures land — was discarded before the assertion. And it
 *     asked for `['wcag2a', 'wcag2aa']` only, dropping the WCAG 2.1 additions
 *     (1.4.10 Reflow, 1.4.11 Non-text Contrast, 1.4.13, 2.5.x) that this lab is
 *     most at risk from.
 *
 *  4. `violations` IS NOT THE WHOLE ORACLE. See `scan`. This lab's two verdict
 *     surfaces — `.converge-row.match` and `.fs-steal` — are
 *     `color-mix(in srgb, …)`, and axe files a `color-mix()` backdrop under
 *     `incomplete` rather than judging it. So does an `aria-label` on a
 *     role-less element. The old spec read neither bucket.
 *
 *  5. IT HAD NO REFLOW AND NO NON-TEXT-CONTRAST ORACLE, and this repo shipped no
 *     separate check for either. `nontext.ts` supplies 1.4.11 and
 *     `expectNoHorizontalOverflow` supplies 1.4.10.
 *
 * WHAT THE FIRST HONEST DRIVE FOUND, all of it fixed rather than baselined:
 *
 *   - eleven control boundaries under 3:1 (SC 1.4.11) — nine of this lab's own
 *     controls at 1.36:1–1.55:1, plus the two top-bar buttons at 2.45:1. See
 *     `nontext-baseline.ts`, which is empty because of it.
 *   - five footer links at 2.95:1 in the light theme (SC 1.4.3), where an
 *     `opacity: 0.7` on the footer faded the ink and not its backdrop.
 *   - a complementary landmark nested inside another landmark: the hero's
 *     `<aside class="cl-hero-why">` inside `<header role="region">`.
 *   - three scrolling regions with no keyboard route (SC 2.1.1) — two `<pre>`
 *     code blocks that overflow at 380px, and `#mk-timeline`, a `role="log"`
 *     that only begins to overflow once real traffic has run, which is a state
 *     only a drive this long ever reaches.
 *   - an `aria-label` on `.message-bubble`, a roleless <div>, where ARIA
 *     prohibits it — so the sender attribution silently did not exist for the
 *     readers it was written for. It is real off-screen text now.
 *
 * Two of those were reachable only because the gate's own blindfolds came off
 * first: `body { overflow-x: hidden }` had made 1.4.10 unmeasurable by
 * construction, and this file's `boot()` asserted BOTH convergence rows read
 * "no sending chain", which is a page where X3DH never ran.
 */

/**
 * Wait for every running animation and transition to drain.
 *
 * Transitions drain in waves, not in one batch, so a poll for "nothing running
 * right now" can exit through a gap between waves. Require quiescence to hold
 * for several consecutive frames instead.
 */
export async function settle(page: Page): Promise<void> {
  await page.waitForFunction(
    () => {
      const w = window as unknown as { __quietFrames?: number }
      const running = document.getAnimations().filter((a) => a.playState === 'running')
      w.__quietFrames = running.length === 0 ? (w.__quietFrames ?? 0) + 1 : 0
      return w.__quietFrames >= 6
    },
    undefined,
    { timeout: 20_000, polling: 'raf' },
  )
}

/**
 * Assert that reduced motion left the page visible, not merely un-animated.
 *
 * The failure mode this guards against is an element whose only route to its
 * visible state is an animation, in a stylesheet whose reduced-motion block
 * cancels that animation without restoring its end state — the element then
 * renders at `opacity: 0` for every reader with the preference set.
 *
 * This lab is one keyword away from that shape, which is why the check runs in
 * every state rather than once. `style.css` declares two `@keyframes`, `fadeIn`
 * and `slideUp`, and BOTH start at `opacity: 0`: `.tab-content` uses `fadeIn` on
 * every tab switch and `.message` uses `slideUp` on every send. Its two
 * reduced-motion blocks collapse `animation-duration` to `0.01ms` rather than
 * setting `animation: none`, so the animation still runs and still lands on its
 * end state — every panel and every message bubble stays visible. Write
 * `animation: none` there instead and all eight tabs would render blank for a
 * reader with the preference set, while an axe run stayed green. That is the
 * distance between this stylesheet and the defect, and it is why the assertion
 * exists.
 *
 * `aria-hidden` subtrees are excluded; see the note on `ariaHidden` in
 * `contrast.ts` for what this lab hides and why each one was checked by hand.
 */
async function expectNotBlank(page: Page, label: string): Promise<void> {
  const invisible = await page.evaluate(() => {
    const out: string[] = []
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const own = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? '')
        .join('')
        .trim()
      if (!own) continue
      // Deliberately hidden subtrees are not "blank", they are closed.
      if (!(el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true })) continue
      if (el.closest('[aria-hidden="true"]')) continue
      let effective = 1
      let node: Element | null = el
      while (node) {
        effective *= parseFloat(getComputedStyle(node).opacity)
        node = node.parentElement
      }
      if (effective === 0) {
        out.push(`${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}`)
      }
    }
    return Array.from(new Set(out))
  })
  expect(invisible, `no visible text may render at opacity 0 in state: ${label}`).toEqual([])
}

/**
 * Uncaught page errors and console errors, collected from the moment the page is
 * created.
 *
 * This matters more here than in most labs, because every send goes through
 * `sendMessage()`'s `try/catch`, whose failure branch calls
 * `showComposerHint('Encryption error: …')` and returns. A genuinely broken
 * ratchet would therefore leave a tidy, plausible page with a friendly message
 * on it — and a gate with no error watch would scan that and report green.
 * Attach before `boot`, assert after the drive.
 */
export function watchPageErrors(page: Page): string[] {
  const errors: string[] = []
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`))
  page.on('console', (m) => {
    if (m.type() === 'error') errors.push(`console.error: ${m.text()}`)
  })
  return errors
}

/**
 * Exactly one banner landmark.
 *
 * This page ships TWO `<header>` elements: the shared Crypto Lab top bar, which
 * declares `role="banner"` explicitly, and the lab's own `<header class="header">`
 * inside `<div id="app">`. The second carries `role="region"`, which is what
 * keeps it out of the banner role — an explicit non-banner role wins over the
 * implicit mapping. `index.html` also runs a `dedupeBanner()` IIFE that demotes
 * any surplus banner to `role="group"`. Asserting the OUTCOME rather than either
 * mechanism is what catches a change to the markup or to the script.
 */
export async function assertSingleBanner(page: Page): Promise<void> {
  const banners = await page.evaluate(() => {
    const scoped = new Set(['MAIN', 'ARTICLE', 'ASIDE', 'NAV', 'SECTION'])
    const isBanner = (el: Element): boolean => {
      if (el.getAttribute('role') === 'banner') return true
      if (el.tagName !== 'HEADER') return false
      if (el.getAttribute('role')) return false // explicit non-banner role wins
      for (let p = el.parentElement; p; p = p.parentElement) if (scoped.has(p.tagName)) return false
      return true
    }
    return [...document.querySelectorAll('header,[role="banner"]')].filter(isBanner).length
  })
  expect(banners, 'exactly one banner landmark').toBe(1)
}

/**
 * An explicit role on a list REPLACES its implicit `list` role, orphaning every
 * `<li>` inside it — axe then fires `listitem` once per child. A source grep
 * cannot see this reliably when the role is assigned from script, so the DOM is
 * asked instead. `role="list"` is the one benign case (redundant, not
 * destructive), though a redundant `role="list"` makes axe apply
 * `aria-required-children`, which fails whenever the list is empty.
 */
export async function assertListSemantics(page: Page): Promise<void> {
  const broken = await page.$$eval('ul[role], ol[role]', (els) =>
    els
      .filter((e) => e.getAttribute('role') !== 'list')
      .map((e) => `${e.tagName.toLowerCase()}[role=${e.getAttribute('role')}] with ${e.children.length} children`),
  )
  expect(broken, 'an explicit role on a list deletes its list semantics').toEqual([])
}

/**
 * Load the page in a known theme with reduced motion actually in effect, and
 * assert the content every scan relies on is really on the page — including the
 * lab's DEFAULTS, which are never assumed.
 *
 * The theme is seeded through `localStorage` rather than by clicking the toggle,
 * which pins down a real failure mode as a side effect: `index.html`'s
 * anti-flash script reads `localStorage.getItem('theme')`, the shared bar's
 * toggle writes `localStorage.setItem('theme', …)`, and `main.ts` writes
 * `THEME_STORAGE_KEY`, which is also `'theme'`. All three agree; if any of them
 * ever drifts, this boot fails on `data-theme` rather than quietly scanning dark
 * twice. (The old spec reached light by CLICKING `#cl-theme-toggle`, so it could
 * not have noticed a persistence break at all.)
 *
 * The defaults are asserted at length because this page builds a real X3DH
 * session and both Double Ratchet states at load, asynchronously, before it
 * renders anything. A navigation that resolves proves nothing: if
 * `buildSession()` rejected, the handshake banner would stay empty and the tabs
 * would render their empty states — and an empty page is exactly what a scan
 * reports as perfectly accessible.
 */
export async function boot(page: Page, theme: 'dark' | 'light'): Promise<void> {
  // A click on a control that never becomes actionable otherwise burns the whole
  // test timeout and reports nothing useful. 20s turns that silent hang into a
  // named failure naming the locator.
  page.setDefaultTimeout(20_000)
  await page.emulateMedia({ reducedMotion: 'reduce' })
  await page.addInitScript((t) => localStorage.setItem('theme', t), theme)
  await page.goto('.')
  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
    'reduced-motion emulation must actually be in effect',
  ).toBe(true)
  await expect(page.locator('html')).toHaveAttribute('data-theme', theme)
  await assertSingleBanner(page)
  await assertListSemantics(page)

  // The `hidden` attribute really removes an element. `[hidden]` has specificity
  // (0,1,0) — identical to a class — so any later `.foo { display: … }` beats it
  // and the attribute silently does nothing. This lab hides seven of its eight
  // tab panels that way, plus `#guide-reopen`, `#mitm-result`, `#coach`,
  // `#quiz-retry` and the three `.sim-state` blocks. Measured from a live
  // element rather than inferred from the CSS.
  expect(
    await page.evaluate(() => {
      const probe = document.createElement('div')
      probe.hidden = true
      document.body.appendChild(probe)
      const display = getComputedStyle(probe).display
      probe.remove()
      return display
    }),
    'the hidden attribute must actually hide (it is how seven of the eight tab panels are hidden)',
  ).toBe('none')

  // Both skip links point at ids that exist. axe's skip-link rule is
  // best-practice, not WCAG-tagged, so `withTags` never runs it — a skip link
  // aimed at a missing element is exactly the kind of thing a green axe run says
  // nothing about, and this page has TWO of them: the shared bar's and the lab's.
  await expect(page.locator('a.cl-skip-link')).toHaveAttribute('href', '#app')
  await expect(page.locator('a.skip-link')).toHaveAttribute('href', '#main-content')
  await expect(page.locator('#app')).toHaveCount(1)
  await expect(page.locator('main#main-content')).toHaveCount(1)

  // ── The session is real and both ratchets initialised ───────────────────
  await expect(page.locator('#handshake-badge')).toContainText('Identity verified')
  await expect(page.locator('#handshake-detail')).toContainText(/[0-9A-F]{2}( [0-9A-F]{2}){7}/)
  await expect(page.locator('#x3dh-breakdown .x3dh-formula')).toHaveCount(4)
  await expect(page.locator('#x3dh-breakdown .x3dh-sk')).toContainText('SK = HKDF')
  await expect(page.locator('#ratchet-teeth .tooth')).toHaveCount(10)

  // ── The guided tour is at step 1 of 7, un-dismissed ─────────────────────
  // The old spec never advanced it, so six of these seven steps had never been
  // rendered in a scan.
  await expect(page.locator('#guide-panel')).toBeVisible()
  await expect(page.locator('#guide-step')).toHaveText('Step 1 of 7')
  await expect(page.locator('#guide-back')).toBeDisabled()
  await expect(page.locator('#guide-next')).toHaveText('Next →')
  await expect(page.locator('#guide-reopen')).toBeHidden()

  // ── Every shipped control default ───────────────────────────────────────
  await expect(page.locator('#tab-conversation')).toHaveAttribute('aria-selected', 'true')
  await expect(page.locator('.tab-btn[aria-selected="true"]')).toHaveCount(1)
  await expect(page.locator('#messages .message-bubble')).toHaveCount(0)
  await expect(page.locator('#intro-cta')).toBeVisible()
  await expect(page.locator('#message-input')).toHaveValue('')
  await expect(page.locator('input[name="sender"][value="alice"]')).toBeChecked()
  await expect(page.locator('#coach')).toBeHidden()
  await expect(page.locator('#mitm-result')).toBeHidden()
  await expect(page.locator('#quiz-retry')).toBeHidden()

  // The empty states, which are real renderings a visitor sees first and which
  // the old spec overwrote before it looked at them.
  await expect(page.locator('#ooo-pending .empty-state')).toHaveText('Generate a batch to begin.')
  await expect(page.locator('#ooo-store-count')).toHaveText('0 keys held')
  await expect(page.locator('#fs-table .empty-state')).toBeAttached()
  // The two convergence rows arrive in DIFFERENT states, and asserting that is
  // what proves the handshake ran on one side only — which is what X3DH does.
  // `session-init.ts` hands Alice, the initiator, a `sendingChain` at init and
  // leaves both of Bob's chains null, so the a2b row arrives already in its
  // "ratcheted ahead" form (Alice can send; Bob has nothing to receive with
  // yet), while only b2a reports no sending chain at all. Asserting "no sending
  // chain" on both, as this first did, describes a handshake that never ran.
  await expect(page.locator('#converge-a2b')).toContainText(/ratcheted ahead/i)
  await expect(page.locator('#converge-b2a')).toContainText(/no sending chain/i)

  // ── The Break-In Recovery tab ships with two of its three steps LOCKED ──
  // This is the only prerequisite chain in the lab, and it had never been
  // scanned in either its locked or its unlocked form.
  await expect(page.locator('#compromise-btn')).toBeEnabled()
  await expect(page.locator('#recovery-send-btn')).toBeDisabled()
  await expect(page.locator('#recovery-complete-btn')).toBeDisabled()
  await expect(page.locator('#compromise-status')).toBeHidden()
  await expect(page.locator('#recovery-status')).toBeHidden()
  await expect(page.locator('#recovery-complete-status')).toBeHidden()

  // ── The quiz is unanswered ──────────────────────────────────────────────
  await expect(page.locator('#quiz-body .quiz-question')).toHaveCount(7)
  await expect(page.locator('#quiz-body .quiz-option')).toHaveCount(28)
  await expect(page.locator('#quiz-body .quiz-feedback')).toHaveCount(0)
  await expect(page.locator('#quiz-score')).toHaveText('')

  await settle(page)
  await expectNotBlank(page, `${theme} first paint`)
}

/**
 * Assert the page does not require horizontal scrolling.
 *
 * WCAG 1.4.10 (Reflow, AA). axe has no rule for this at all, and this lab had
 * made the question unanswerable: `body { overflow-x: hidden }` propagates to
 * the viewport, so `documentElement.scrollWidth` can never exceed
 * `clientWidth` and this check — and any other — is guaranteed to pass whatever
 * the page does. It was removed rather than worked around; see the commit.
 *
 * The shapes at risk here are the two `.comparison-table` wrappers on the About
 * tab, the `.stats` grid at `repeat(2, 1fr)` (each track takes its min-content
 * as its automatic minimum), the `.ooo-layout` and `.x3dh-terms` grids, the
 * 16-hex `.state-value` and `.fs-mk` runs, and the eight-button `.tabs` row,
 * which is `overflow-x: auto` and genuinely scrolls at 380px.
 */
export async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement
    if (doc.scrollWidth <= doc.clientWidth) return null

    // Only elements that actually push the DOCUMENT sideways are culprits. A
    // wide box inside an `overflow: auto` wrapper has a huge bounding rect but
    // is clipped by its scroller and contributes nothing to the document's
    // scroll width — naming it sends you off fixing the wrong element. Both
    // `.comparison-table` wrappers and the `.tabs` strip are such decoys here.
    const clipped = (el: Element): boolean => {
      let n = el.parentElement
      while (n && n !== doc) {
        const ox = getComputedStyle(n).overflowX
        if (ox === 'auto' || ox === 'scroll' || ox === 'hidden' || ox === 'clip') return true
        n = n.parentElement
      }
      return false
    }

    const over = Array.from(document.querySelectorAll('body *'))
      .map((el) => ({ el, r: el.getBoundingClientRect() }))
      .filter((x) => x.r.width > 0 && x.r.right > doc.clientWidth + 1)
      .sort((a, b) => b.r.right - a.r.right)
    const widest = over.filter((x) => !clipped(x.el))[0] ?? over[0]
    return {
      scrollWidth: doc.scrollWidth,
      clientWidth: doc.clientWidth,
      widest: widest
        ? `${clipped(widest.el) ? '[clipped] ' : ''}${widest.el.tagName.toLowerCase()}${widest.el.id ? '#' + widest.el.id : ''}` +
          `${widest.el.getAttribute('class') ? '.' + widest.el.getAttribute('class')!.trim().split(/\s+/).join('.') : ''}` +
          ` @${Math.round(widest.r.width)}px right=${Math.round(widest.r.right)}`
        : '(none identified)',
    }
  })
  expect(overflow, `page must not scroll horizontally in state: ${label}`).toBeNull()
}

/**
 * Every scrolling container must be operable from the keyboard (WCAG 2.1.1). If
 * it holds no focusable content it needs `tabindex="0"`, so it becomes a focus
 * target arrow keys can then scroll.
 *
 * This lab already handles the two cases it knew about: both `.comparison-table`
 * wrappers on the About tab carry `tabindex="0"`, `role="region"` and an
 * `aria-label`, and so does the `.state-panel`. The assertion stays because a
 * convention is not an enforcement, and because the set of things that actually
 * scroll changes with the viewport — `#messages` and `#mk-timeline` are
 * `role="log"` regions that do not overflow at the shipped default and only
 * begin to once enough messages have been sent, which is a state this drive
 * builds on purpose.
 */
export async function expectScrollersReachable(page: Page, label: string): Promise<void> {
  const unreachable = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,[tabindex]:not([tabindex="-1"])'
    return Array.from(document.querySelectorAll<HTMLElement>('body *'))
      .filter((el) => el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1)
      .filter((el) => {
        const cs = getComputedStyle(el)
        return ['auto', 'scroll'].includes(cs.overflowX) || ['auto', 'scroll'].includes(cs.overflowY)
      })
      .filter((el) => el.tabIndex < 0 && !el.querySelector(FOCUSABLE))
      .map(
        (el) =>
          `${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}` +
          ` (${el.scrollWidth}x${el.scrollHeight} in ${el.clientWidth}x${el.clientHeight})`,
      )
  })
  expect(
    Array.from(new Set(unreachable)),
    `scrolling regions with no keyboard route in state: ${label}`,
  ).toEqual([])
}

/**
 * When `A11Y_COLLECT` is set, `scan` records failures instead of throwing.
 *
 * A strict gate reports the first failing assertion in the first failing state
 * and stops, so a page with defects in several states needs one full run per
 * defect to enumerate them. The collection pass turns that into a single run. It
 * is a debugging aid only: `A11Y_COLLECT` is never set in CI or in the committed
 * workflow, and a run with it set prints every finding as it happens and then
 * fails at the end, so a green collection run cannot be mistaken for a green
 * gate.
 */
const COLLECTING = !!process.env.A11Y_COLLECT
const collected: string[] = []

function record(entry: string): void {
  collected.push(entry)
  // Printed as it happens, not only at the end: a hard assertion later in the
  // drive would otherwise abort the test before anything collected so far was
  // ever shown.
  console.log(`\n[A11Y_COLLECT #${collected.length}] ${entry}`)
}

export function softExpect(actual: unknown, message: string, expected: unknown): void {
  if (!COLLECTING) {
    expect(actual, message).toEqual(expected)
    return
  }
  try {
    expect(actual, message).toEqual(expected)
  } catch {
    record(`${message}\n  ${JSON.stringify(actual, null, 2)}`)
  }
}

/**
 * Fail the test if the collection pass recorded anything. Without this a
 * collection run would end green, and a green collection run is
 * indistinguishable from a green gate — which is the exact confusion the whole
 * exercise exists to remove.
 */
export function reportCollected(): void {
  if (!COLLECTING) return
  expect(collected, `A11Y_COLLECT recorded ${collected.length} failure(s)`).toEqual([])
}

async function expectScrollersReachableSoft(page: Page, label: string): Promise<void> {
  if (!COLLECTING) return expectScrollersReachable(page, label)
  try {
    await expectScrollersReachable(page, label)
  } catch (e) {
    record(String(e).slice(0, 900))
  }
}

/**
 * The 1.4.11 ratchet, soft-wrapped the same way as every other oracle here.
 *
 * The wrapper is written out longhand rather than folded into a neighbour
 * because of how this oracle died elsewhere in this fleet:
 * `expectNoNewNonTextFailures` had been called from inside
 * `expectScrollersReachableSoft`, AFTER that function's `if (!COLLECTING) return`
 * guard, so in a strict run — which is every run in CI and every run anyone reads
 * as a pass — the guard returned first and `nontext.ts` never executed at all.
 * It is called from `scan()` here, at every driven state, and this repo's
 * baseline was captured by that live path.
 */
async function expectNoNewNonTextFailuresSoft(page: Page, label: string): Promise<void> {
  if (!COLLECTING) return expectNoNewNonTextFailures(page, label)
  try {
    await expectNoNewNonTextFailures(page, label)
  } catch (e) {
    record(String(e).slice(0, 900))
  }
}

async function expectNoHorizontalOverflowSoft(page: Page, label: string): Promise<void> {
  if (!COLLECTING) return expectNoHorizontalOverflow(page, label)
  try {
    await expectNoHorizontalOverflow(page, label)
  } catch (e) {
    record(String(e).slice(0, 900))
  }
}

/**
 * WCAG 1.4.11 and generated content, ratcheted against a per-repo baseline.
 *
 * Neither class has ANY other oracle: axe has no rule for non-text contrast, and
 * the arithmetic text walk cannot reach a control's boundary or a `::before`
 * glyph, because a pseudo-element is not an element and owns no text node.
 *
 * The control-boundary half found ELEVEN real failures in this repo on its first
 * strict run. Nine were this lab's own controls at 1.36:1–1.55:1, all with the
 * same root cause — one `--color-border` token doing both the surface-divider
 * job and the control-boundary job — and are fixed with a dedicated
 * `--color-control-border` in `src/style.css`, not baselined. The other two were
 * the top bar's `a.cl-btn` and `#cl-theme-toggle` at 2.45:1, fixed in this lab's
 * own copy of the bar in `index.html`; per CLAUDE.md each lab owns its header,
 * so that is a local fix and not a fleet push. The generated-content half finds
 * nothing here, because `style.css` declares no `content` on any pseudo-element;
 * it runs anyway, so the first decorative glyph anyone adds is measured rather
 * than assumed.
 *
 * Nothing remains, which is why `nontext-baseline.ts` is `{}` — an emptiness
 * captured through this same path rather than asserted. A check that merely logs
 * is not a gate, though, so it ratchets: anything NOT in the
 * baseline fails, anything in the baseline that got WORSE fails, and anything in
 * the baseline that has been FIXED fails until its entry is deleted. That last
 * rule is what stops the allowlist becoming a permanent exemption.
 */
const nonTextSeen = new Set<string>()

export async function expectNoNewNonTextFailures(page: Page, label: string): Promise<void> {
  const found = await auditNonText(page)
  // Capture mode: emit every finding and assert nothing, so a baseline can be
  // generated by the SAME path that checks it.
  if (process.env.NT_BASELINE_CAPTURE) {
    for (const f of found) {
      console.log(`NTCAP|${f.kind}|${f.selector}|${f.ratio}|${f.required}|${/POSITIONED/.test(f.detail)}`)
    }
    return
  }
  const problems: string[] = []
  for (const f of found) {
    const key = `${f.kind}|${f.selector}`
    nonTextSeen.add(key)
    const base = NONTEXT_BASELINE[key]
    if (!base) {
      problems.push(`NEW ${f.ratio}:1 (needs ${f.required}:1) [${f.kind}] ${f.selector} — ${f.detail}`)
    } else if (f.ratio < base.ratio - 0.01) {
      problems.push(`WORSE ${f.selector}: ${f.ratio}:1, baseline recorded ${base.ratio}:1`)
    }
  }
  expect(problems, `new or worsened non-text contrast in state: ${label}`).toEqual([])
}

/**
 * Fail if a baselined finding never appeared during the whole drive.
 *
 * It has either been fixed — in which case delete the entry, which is the point
 * — or the drive stopped reaching the state that shows it, which is a coverage
 * regression worth knowing about. Call once, after `driveAllStates`.
 */
export function expectBaselineNotStale(): void {
  const unseen = Object.keys(NONTEXT_BASELINE).filter((k) => !nonTextSeen.has(k))
  expect(
    unseen,
    'baselined non-text findings that no longer appear — delete them from nontext-baseline.ts (or restore the drive state that showed them)',
  ).toEqual([])
}

/**
 * Scan the page as it currently stands.
 *
 * Seven assertions, because axe's `violations` array alone is not a complete
 * oracle:
 *
 *  - reduced-motion end state — see `expectNotBlank`.
 *  - `violations` — the usual WCAG A/AA rule failures, plus four landmark
 *    best-practice rules `withTags` does not run on its own. NOT filtered by
 *    impact: the old spec kept only `serious` and `critical`, which discards
 *    every moderate finding, and moderate is where most landmark and ARIA
 *    failures land.
 *  - `incomplete` — axe's "could not decide" bucket, which never reaches the
 *    violations array. The one rule id allowed to remain incomplete is
 *    `color-contrast`, and only because the next assertion computes those ratios
 *    arithmetically. Everything else in that bucket is a real result axe simply
 *    could not finish — including `aria-prohibited-attr`, which is where an
 *    `aria-label` on a role-less element hides, a defect that never reaches the
 *    violations array at all. This page depends on getting that right in a dozen
 *    places: `#messages` and `#mk-timeline` pair their labels with `role="log"`,
 *    `#ratchet-teeth` and `#chain-visual` with `role="img"`, both
 *    `.comparison-table` wrappers and `.state-panel` with `role="region"`,
 *    `#fs-compromise` and each `.quiz-options` with `role="group"`. Drop any of
 *    those roles and the label is silently discarded.
 *  - arithmetic contrast — composite-aware WCAG 1.4.3 over every text node.
 *  - non-text contrast and generated content — SC 1.4.11, ratcheted; see
 *    `expectNoNewNonTextFailures`. This is the only oracle that judges a
 *    control's boundary against the surface OUTSIDE it, and this repo shipped
 *    nothing of the kind.
 *  - keyboard reachability of scrolling regions — WCAG 2.1.1.
 *  - reflow — WCAG 1.4.10, which axe has no rule for at all.
 */
export async function scan(page: Page, label: string): Promise<void> {
  await settle(page)
  await expectNotBlank(page, label)
  // TWO axe runs, deliberately, and this is not a style choice.
  //
  // `AxeBuilder.withTags()` and `AxeBuilder.withRules()` both write the same
  // `options.runOnly` field, so the second call SILENTLY REPLACES the first —
  // the axe-core/playwright source says so in as many words on `withRules`
  // ("Cannot be used with AxeBuilder#withTags"). Chained as
  // `.withTags(TAGS).withRules([...4 landmark rules])`, axe runs those FOUR
  // best-practice rules and NOT ONE WCAG RULE, while a green result reads exactly
  // like a full A/AA pass. For scale, `withTags(TAGS)` selects 69 of axe-core
  // 4.12's 105 rule definitions; the chained form executes 4.
  //
  // Confirmed here by experiment rather than by reading: `<html lang="en">` was
  // changed to `<html>` in `index.html` and the full drive re-run against the
  // identical page. The merged form below failed on `html-has-lang` (SC 3.1.1,
  // tagged `wcag2a`) at the very first state. See the commit message for the
  // measured before/after.
  //
  // The landmark four are still wanted because they are best-practice rather than
  // WCAG-tagged, so `withTags` alone does not reach them — and this page has the
  // shape they catch: a sticky `<header role="banner">` above a `<div id="app">`
  // that contains a second `<header>`, a `<main id="main-content">` and an
  // `<aside role="complementary">` in the hero.
  const wcag = await new AxeBuilder({ page }).withTags(TAGS).analyze()
  const landmarks = await new AxeBuilder({ page })
    .withRules([
      'landmark-no-duplicate-banner',
      'landmark-unique',
      'landmark-one-main',
      'landmark-complementary-is-top-level',
    ])
    .analyze()
  const results = {
    violations: [...wcag.violations, ...landmarks.violations],
    incomplete: [...wcag.incomplete, ...landmarks.incomplete],
  }

  const violations = results.violations.map((v) => ({
    state: label,
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
  }))
  softExpect(violations, `axe violations in state: ${label}`, [])

  const unexplainedIncomplete = results.incomplete
    .filter((v) => v.id !== 'color-contrast')
    .map((v) => ({
      state: label,
      id: v.id,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
    }))
  softExpect(unexplainedIncomplete, `axe incomplete results in state: ${label}`, [])

  const contrast = Array.from(new Set(formatContrastFailures(await auditContrast(page))))
  softExpect(contrast, `measured contrast failures in state: ${label}`, [])

  await expectNoNewNonTextFailuresSoft(page, label)
  await expectScrollersReachableSoft(page, label)
  await expectNoHorizontalOverflowSoft(page, label)
}

// ── The drive ───────────────────────────────────────────────────────────────

/** The eight tabs, in the order the tablist renders them. */
const TABS = ['conversation', 'x3dh', 'ooo', 'state', 'fs', 'compromise', 'about', 'quiz'] as const

/** Each guided-tour step's title and the tab it drives, asserted rather than assumed. */
const GUIDE_STEPS: ReadonlyArray<{ title: string; tab: string }> = [
  { title: 'Welcome', tab: 'conversation' },
  { title: 'Step 1 — The handshake (X3DH)', tab: 'x3dh' },
  { title: 'Step 2 — Send a message', tab: 'conversation' },
  { title: 'Step 3 — The DH ratchet (break-in recovery)', tab: 'conversation' },
  { title: 'Step 4 — The symmetric ratchet (forward secrecy)', tab: 'conversation' },
  { title: 'Step 5 — Attack forward secrecy', tab: 'fs' },
  { title: 'Step 6 — Explore on your own', tab: 'conversation' },
]

/**
 * Drive the lab through the states that render content, scanning each.
 *
 * Seven things shape this drive:
 *
 *  - EVERY TAB IS SCANNED EMPTY BEFORE IT IS SCANNED FULL. The out-of-order
 *    queue, the forward-secrecy table and the message-key timeline all ship an
 *    `.empty-state` paragraph, and the convergence rows ship a "no sending
 *    chain" verdict. Those are the first thing every visitor sees, and the old
 *    spec destroyed all four before its first scan by running the demos up
 *    front.
 *
 *  - THE GUIDED TOUR IS ADVANCED ONE STEP AT A TIME, all seven, then reversed,
 *    dismissed and reopened. Each step also switches tabs, so this is seven
 *    distinct renderings the old spec collapsed into zero — it never clicked
 *    `#guide-next` at all.
 *
 *  - THE LOCKED STATES ARE SCANNED BEFORE THE UNLOCK. The Break-In Recovery tab
 *    ships with steps 2 and 3 `disabled`, and each is enabled only by completing
 *    the one before it. All four states of that chain are scanned in order.
 *
 *  - THE ERROR STATE IS DRIVEN. `sendMessage()` refuses when Bob is selected
 *    before he has a receiving chain, and renders `#composer-hint` — a
 *    `role="status"` element created lazily, which therefore does not exist in
 *    the DOM at all until the mistake is made. It is unreachable without making
 *    it on purpose, and had never been looked at.
 *
 *  - BOTH EXTREMES OF THE COMPROMISE-POINT CONTROL. `#fs-compromise` renders
 *    seven `.fs-point` buttons; at 0 every message is exposed and there is no
 *    `.safe` row, at 6 every message is safe and there is no `.exposed` row.
 *    Those two ends are the only states where one of the two row colours is
 *    absent, and the `.fs-steal` marker moves to the top and the bottom of the
 *    table respectively.
 *
 *  - THE QUIZ IS DRIVEN TO A FULL SCORE AND TO A WRONG ANSWER. `#quiz-retry`
 *    only un-hides once all seven are answered, and `.quiz-feedback.wrong` only
 *    exists after a wrong one. Both are scanned, then Try again returns it to
 *    the unanswered state.
 *
 *  - HOVER AND FOCUS ARE STATES. Both skip links are tabbed to and scanned in
 *    their revealed position, which is the only rendering of either that a
 *    visitor ever sees.
 */
export async function driveAllStates(page: Page, theme: string): Promise<void> {
  const scanAt = (s: string): Promise<void> => scan(page, `${theme} / ${s}`)

  await scanAt('first paint, tour at step 1 and every demo un-run')

  // ── The two skip links, in their revealed positions ─────────────────────
  await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur?.())
  await page.keyboard.press('Tab')
  await expect(page.locator('a.cl-skip-link')).toBeFocused()
  await scanAt('shared skip link focused, slid into view')
  // The lab's own skip link is the first focusable element inside #app.
  await page.locator('a.skip-link').focus()
  await expect(page.locator('a.skip-link')).toBeFocused()
  await scanAt("the lab's own skip link focused, slid into view")

  // ── Every tab, still empty ──────────────────────────────────────────────
  for (const tab of TABS) {
    await page.click(`#tab-${tab}`)
    await expect(page.locator(`#tab-${tab}`)).toHaveAttribute('aria-selected', 'true')
    await expect(page.locator(`#${tab}`)).toBeVisible()
    await scanAt(`tab "${tab}", nothing run yet`)
  }
  await page.click('#tab-conversation')

  // ── The guided tour, one step per click ─────────────────────────────────
  for (let i = 1; i < GUIDE_STEPS.length; i++) {
    await page.click('#guide-next')
    const step = GUIDE_STEPS[i]!
    await expect(page.locator('#guide-step')).toHaveText(`Step ${i + 1} of 7`)
    await expect(page.locator('#guide-title')).toHaveText(step.title)
    await expect(page.locator(`#tab-${step.tab}`)).toHaveAttribute('aria-selected', 'true')
    await expect(page.locator('#guide-back')).toBeEnabled()
    await expect(page.locator('#guide-next')).toHaveText(i === GUIDE_STEPS.length - 1 ? 'Finish' : 'Next →')
    await scanAt(`guided tour step ${i + 1}, "${step.title}"`)
  }

  await page.click('#guide-back')
  await expect(page.locator('#guide-step')).toHaveText('Step 6 of 7')
  await scanAt('guided tour stepped back')

  // "Finish" hides the panel and reveals the reopen button — a state the old
  // spec never rendered, because it never touched the tour.
  await page.click('#guide-next')
  await expect(page.locator('#guide-step')).toHaveText('Step 7 of 7')
  await page.click('#guide-next')
  await expect(page.locator('#guide-panel')).toBeHidden()
  await expect(page.locator('#guide-reopen')).toBeVisible()
  await scanAt('guided tour finished, collapsed to its reopen button')

  await page.locator('#guide-reopen').hover()
  await scanAt('the reopen button hovered')

  await page.click('#guide-reopen')
  await expect(page.locator('#guide-panel')).toBeVisible()
  await page.click('#guide-dismiss')
  await expect(page.locator('#guide-panel')).toBeHidden()
  await scanAt('guided tour dismissed by its own Hide guide button')

  // ── Conversation: the composer's refusal branch, then real traffic ──────
  await page.click('#tab-conversation')
  await page.check('input[name="sender"][value="bob"]')
  await page.fill('#message-input', 'bob speaks first')
  await page.click('#send-btn')
  await expect(page.locator('#composer-hint')).toContainText("Bob can't send yet")
  await expect(page.locator('#messages .message-bubble')).toHaveCount(0)
  await scanAt('composer refused: Bob has no sending chain yet')

  await page.check('input[name="sender"][value="alice"]')
  await page.locator('#sample-btn').hover()
  await scanAt('a primary button hovered')

  await page.getByRole('button', { name: /Send a sample message/i }).click()
  await expect(page.locator('#messages .message-bubble').first()).toContainText('Hi Bob')
  await expect(page.locator('#messages .wire-detail .wire-fields').first()).toContainText(
    'header.messageNumber',
  )
  await expect(page.locator('#coach')).toBeVisible()
  await expect(page.locator('#coach-what')).toContainText(/DH ratchet/i)
  await expect(page.locator('#converge-a2b')).toHaveClass(/match/)
  await scanAt("Alice's first message, the coach narrating a DH ratchet")

  await page.check('input[name="sender"][value="bob"]')
  await page.fill('#message-input', 'reply from bob')
  await page.click('#send-btn')
  await expect(page.locator('#messages .message-bubble')).toHaveCount(2)
  await expect(page.locator('#converge-b2a')).toHaveClass(/match/)
  await scanAt('Bob replied, both directions converged')

  // A same-direction follow-up is a symmetric-only step — a different coach
  // narration and a different state panel.
  await page.fill('#message-input', 'and one more')
  await page.click('#send-btn')
  await expect(page.locator('#messages .message-bubble')).toHaveCount(3)
  await expect(page.locator('#coach-what')).toContainText(/symmetric ratchet/i)
  await scanAt('a same-direction follow-up, narrated as a symmetric ratchet')

  // ── The MITM demo's rejection ───────────────────────────────────────────
  await page.getByRole('button', { name: /Simulate a tampered pre-key/i }).click()
  await expect(page.locator('#mitm-result')).toContainText(/Blocked/i)
  await scanAt('tampered pre-key blocked by the signature check')

  // ── X3DH, now with a live session behind it ─────────────────────────────
  await page.click('#tab-x3dh')
  await expect(page.locator('#x3dh-breakdown .x3dh-formula')).toHaveCount(4)
  await scanAt('X3DH breakdown with the four DH terms')

  // ── Out of order: the queue, a skipped-key store, and the drain ─────────
  await page.click('#tab-ooo')
  await page.click('#ooo-generate')
  await expect(page.locator('#ooo-pending .ooo-deliver')).toHaveCount(5)
  await scanAt('out-of-order batch generated, five messages pending')

  // Deliver m2 first: Bob has to store the keys for m0 and m1.
  await page.locator('#ooo-pending .ooo-deliver').nth(2).click()
  await expect(page.locator('#ooo-store-keys .ooo-key-chip')).toHaveText(['m0', 'm1'])
  await scanAt('m2 delivered first, two skipped keys held')

  await page.locator('#ooo-pending .ooo-deliver').first().click()
  await expect(page.locator('#ooo-store-keys .ooo-key-chip')).toHaveText(['m1'])
  await scanAt("m0 delivered late, its stored key consumed")

  await page.click('#ooo-reset')
  await expect(page.locator('#ooo-pending .empty-state')).toBeVisible()
  await scanAt('out-of-order demo reset to its empty state')

  // ── Live state: the timeline, which only exists after real traffic ──────
  await page.click('#tab-state')
  await expect(page.locator('#mk-timeline .mk-ratchet')).toHaveCount(2)
  await expect(page.locator('#mk-timeline .mk-ratchet').last()).toContainText('new root key RK')
  await expect(page.locator('#ratchet-teeth .tooth.active')).toHaveCount(1)
  await expect(page.locator('#stat-messages')).toHaveText('3')
  await scanAt('live state: three messages, two DH ratchets, the tooth chart lit')

  // ── Forward secrecy, at both extremes of the compromise control ─────────
  await page.click('#tab-fs')
  await page.click('#fs-run')
  await expect(page.locator('#fs-table .fs-row')).toHaveCount(6)
  await expect(page.locator('#fs-table .fs-row.safe')).toHaveCount(3)
  await expect(page.locator('#fs-table .fs-row.exposed')).toHaveCount(3)
  await expect(page.locator('#fs-table .fs-steal')).toHaveCount(1)
  await scanAt('forward secrecy run, compromise at 3')

  await page.locator('#fs-compromise .fs-point').first().click()
  await expect(page.locator('#fs-table .fs-row.safe')).toHaveCount(0)
  await expect(page.locator('#fs-table .fs-row.exposed')).toHaveCount(6)
  await scanAt('compromise at 0: every message exposed, no safe row on the page')

  await page.locator('#fs-compromise .fs-point').last().click()
  await expect(page.locator('#fs-table .fs-row.safe')).toHaveCount(6)
  await expect(page.locator('#fs-table .fs-row.exposed')).toHaveCount(0)
  await scanAt('compromise at 6: every message safe, no exposed row on the page')

  await page.locator('#fs-compromise .fs-point').nth(3).click()
  await expect(page.locator('#fs-table .fs-row.safe')).toHaveCount(3)

  // ── Break-in recovery: the locked chain, one unlock at a time ───────────
  await page.click('#tab-compromise')
  await expect(page.locator('#recovery-send-btn')).toBeDisabled()
  await expect(page.locator('#recovery-complete-btn')).toBeDisabled()
  await scanAt('break-in recovery, both later steps still locked')

  await page.click('#compromise-btn')
  await expect(page.locator('#compromise-status')).toBeVisible()
  await expect(page.locator('#compromise-btn')).toBeDisabled()
  await expect(page.locator('#recovery-send-btn')).toBeEnabled()
  await scanAt("attacker holds Bob's keys; step 2 unlocked")

  await page.click('#recovery-send-btn')
  await expect(page.locator('#recovery-status')).toBeVisible()
  await expect(page.locator('#recovery-complete-btn')).toBeEnabled()
  await scanAt('Alice sent with a fresh DH key; step 3 unlocked')

  await page.click('#recovery-complete-btn')
  await expect(page.locator('#recovery-complete-status')).toBeVisible()
  await expect(page.locator('#recovery-complete-btn')).toBeDisabled()
  await scanAt('break-in recovery complete, all three steps shown')

  // ── About: two scrolling comparison tables ──────────────────────────────
  await page.click('#tab-about')
  await expect(page.locator('#about .comparison-table')).toHaveCount(2)
  await scanAt('about tab with both comparison tables')

  await page.locator('#about a').first().hover()
  await scanAt('an in-prose link hovered')

  // ── Quiz: right, wrong, complete, and back to unanswered ────────────────
  await page.click('#tab-quiz')
  const q = page.locator('#quiz-body .quiz-question')
  await q.first().locator('.quiz-option').nth(2).click()
  await expect(q.first().locator('.quiz-feedback')).toHaveClass(/correct/)
  await expect(page.locator('#quiz-score')).toContainText('1 of 1')
  await scanAt('quiz question 1 answered correctly')

  await q.nth(1).locator('.quiz-option').first().click()
  await expect(q.nth(1).locator('.quiz-feedback')).toHaveClass(/wrong/)
  await scanAt('quiz question 2 answered wrongly, explained rather than just marked')

  // Answer the rest so the final score and the Try again button both render.
  for (let i = 2; i < 7; i++) {
    await q.nth(i).locator('.quiz-option').first().click()
  }
  await expect(page.locator('#quiz-body .quiz-feedback')).toHaveCount(7)
  await expect(page.locator('#quiz-score')).toContainText('Final score:')
  await expect(page.locator('#quiz-retry')).toBeVisible()
  await scanAt('quiz complete, final score and Try again shown')

  await page.click('#quiz-retry')
  await expect(page.locator('#quiz-body .quiz-feedback')).toHaveCount(0)
  await expect(page.locator('#quiz-retry')).toBeHidden()
  await scanAt('quiz reset to unanswered')

  // ── Restart: the whole lab back to its arrival state ────────────────────
  await page.click('#reset-btn')
  await expect(page.locator('#messages .message-bubble')).toHaveCount(0)
  await expect(page.locator('#intro-cta')).toBeVisible()
  await expect(page.locator('#guide-step')).toHaveText('Step 1 of 7')
  await expect(page.locator('#fs-table .empty-state')).toBeAttached()
  await expect(page.locator('#ooo-pending .empty-state')).toBeAttached()
  await scanAt('Restart: a fresh session and every demo back to empty')
}
