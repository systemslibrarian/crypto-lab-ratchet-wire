/**
 * Extract the page body a DOM test should boot against: everything inside
 * `<body>`, with every `<script>` removed.
 *
 * This is a module rather than four lines inline because it is the thing worth
 * testing. It used to be two hand-rolled HTML parsers —
 * `html.match(/<body>([\s\S]*?)<\/body>/)` and
 * `.replace(/<script[\s\S]*?<\/script>/g, '')` — and CodeQL was right about
 * both: a single-pass strip misses nesting
 * (js/incomplete-multi-character-sanitization) and `<script` misses `<SCRIPT>`
 * (js/bad-tag-filter). The body regex had a third problem nobody reported: one
 * attribute on the `<body>` tag and it matches nothing, so the suite would
 * boot the application against an empty page and keep passing whatever it
 * asserted about elements that were never there.
 *
 * `DOMParser.parseFromString(..., 'text/html')` does not execute scripts, so
 * taking the body apart through the DOM is both complete and inert.
 */
export function bodyWithoutScripts(html: string): string {
  const parsed = new DOMParser().parseFromString(html, 'text/html');
  for (const script of Array.from(parsed.querySelectorAll('script'))) script.remove();
  return parsed.body.innerHTML;
}
