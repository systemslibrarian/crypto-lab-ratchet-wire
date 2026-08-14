/**
 * Known WCAG 1.4.11 / generated-content findings in this lab, captured through
 * the gate's own path so the baseline and the check cannot disagree.
 *
 * THIS FILE IS A TO-DO LIST, NOT A SET OF EXEMPTIONS. The gate ratchets on it:
 *   - a finding NOT listed here fails the run, so a regression cannot land;
 *   - a listed finding whose ratio gets WORSE fails, so the list cannot rot;
 *   - a listed finding that no longer appears ALSO fails, so a fixed entry must
 *     be deleted and the file can only shrink toward empty.
 * The last rule is what stops an allowlist becoming a permanent exemption.
 *
 * `unverified: true` marks an absolutely-positioned pseudo-element. It can paint
 * outside its host and the oracle measures it against the host's backdrop, so
 * that ratio is NOT trustworthy — hand-measure before acting on it.
 *
 * IT IS EMPTY, AND THAT IS THE TERMINAL STATE OF THE RATCHET, NOT AN UNRUN
 * CHECK. The first strict drive of this gate found eleven control boundaries
 * under 3:1, and every one was fixed in the page rather than listed here.
 *
 * Nine were this lab's own controls, all with the same root cause: a single
 * `--color-border` token doing two jobs with different requirements — dividing
 * surfaces, where WCAG asks nothing, and drawing the ONLY boundary a fill-less
 * or panel-coloured control has, where it asks 3:1. Measured at the colours this
 * lab shipped: `.btn-ghost` (#guide-back, #mitm-demo-btn, #ooo-reset,
 * #quiz-retry) 1.42:1 dark / 1.45:1 light; `#reset-btn.header-action` the same;
 * `#message-input` and `.quiz-option` 1.55:1 dark / 1.36:1 light;
 * `#guide-reopen` the same; `.fs-point` 1.42:1. The fix is a dedicated
 * `--color-control-border` applied to controls only, leaving `--color-border`
 * doing the divider job it is right for.
 *
 * The other two were the shared top bar's `a.cl-btn` and `#cl-theme-toggle` at
 * 2.45:1, whose fill-less 1px border composited from
 * `color-mix(..., --accent 38%, transparent)` over the bar. Raised to 50%
 * (3.38:1) in this lab's own copy of the bar — see the note beside the rule in
 * `index.html`.
 *
 * A run with `NT_BASELINE_CAPTURE=1` prints every finding through this same
 * path and asserts nothing, which is how this file is regenerated; the capture
 * run after those fixes printed zero findings, which is why it is `{}`.
 */
export const NONTEXT_BASELINE: Record<
  string,
  { ratio: number; required: number; unverified: boolean }
> = {}
