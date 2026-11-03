// @vitest-environment happy-dom
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { describe, it, expect } from 'vitest';

import { bodyWithoutScripts } from './page-body';

const here = dirname(fileURLToPath(import.meta.url));
const indexHtml = readFileSync(resolve(here, '../../index.html'), 'utf8');

/**
 * Each case is one the two regexes this replaced actually get wrong, measured
 * against both implementations rather than assumed. Four of the five redden if
 * either regex comes back — and the integration suite that consumes the result
 * does NOT, because this lab's own index.html happens to be the one shape the
 * regexes handled. That is why the extraction is a module with its own tests.
 */
describe('bodyWithoutScripts', () => {
  it('keeps the body of a <body> tag that carries attributes', () => {
    // /<body>([\s\S]*?)<\/body>/ matches nothing here and yields ''. The suite
    // would then boot the application against an empty page and go on passing.
    const body = bodyWithoutScripts('<html><body class="x" data-theme="dark"><p id="k">hi</p></body></html>');
    expect(body).toContain('id="k"');
    expect(body).toContain('hi');
  });

  it('removes an upper-case <SCRIPT> element', () => {
    // js/bad-tag-filter: /<script/ is case-sensitive, so the regex keeps this
    // element verbatim.
    const body = bodyWithoutScripts('<body><SCRIPT>uppercase()</SCRIPT><p>kept</p></body>');
    expect(body.toLowerCase()).not.toContain('<script');
    expect(body).not.toContain('uppercase()');
    expect(body).toContain('kept');
  });

  it('removes a script whose ATTRIBUTE contains a closing tag', () => {
    // js/incomplete-multi-character-sanitization: the lazy match ends at the
    // </script> inside the attribute, so the regex leaves `">x()</script>`
    // behind — script text that survived the strip. An HTML parser reads that
    // </script> as attribute text and removes the whole element.
    const body = bodyWithoutScripts('<body><script a="</script>">surviving()</script><p>kept</p></body>');
    expect(body.toLowerCase()).not.toContain('script');
    expect(body).not.toContain('surviving()');
    expect(body).toContain('kept');
  });

  it('leaves a <script> that is inside an HTML comment alone, comment and all', () => {
    // The regex is destructive in the other direction here: it deletes the
    // comment's contents, because a commented-out script still matches it. A
    // parser knows a script inside a comment is not a script.
    const body = bodyWithoutScripts('<body><!-- <script>commented()</script> --><p>kept</p></body>');
    expect(body).toContain('commented()');
    expect(body).toContain('kept');
  });

  it('leaves the real page a usable body with no script left in it', () => {
    const body = bodyWithoutScripts(indexHtml);
    // A floor, because an empty result is the body regex's failure mode and it
    // would make every assertion in the integration suite vacuous.
    expect(body.length).toBeGreaterThan(10_000);
    expect(body.toLowerCase()).not.toContain('<script');
    expect(body).toContain('id="mitm-demo-btn"');
  });
});
