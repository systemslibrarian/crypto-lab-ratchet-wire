import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const tsc = path.join(root, 'node_modules', '.bin', process.platform === 'win32' ? 'tsc.cmd' : 'tsc');
const run = (args) => {
  const result = spawnSync(tsc, args, { cwd: root, encoding: 'utf8', timeout: 120_000 });
  assert.ifError(result.error);
  assert.equal(result.signal, null, 'Compiler must finish, not be terminated');
  return result;
};

const fixture = (options, source, check) => {
  const directory = mkdtempSync(path.join(root, '.compiler-guard-'));
  try {
    const config = {
      extends: path.join(root, 'tsconfig.json'),
      compilerOptions: { rootDir: root, ...options },
    };
    if (source !== null) {
      writeFileSync(path.join(directory, 'input.ts'), source);
      config.files = ['./input.ts'];
      config.include = [];
    }
    const filename = path.join(directory, 'tsconfig.json');
    writeFileSync(filename, JSON.stringify(config));
    check(run(['--project', filename, '--noEmit']));
  } finally {
    rmSync(directory, { recursive: true });
  }
};

test('the real compiler retains strictness, DOM/bundler settings and the Node integration test', () => {
  const result = run(['--showConfig']);
  assert.equal(result.status, 0, result.stdout + result.stderr);
  const config = JSON.parse(result.stdout);
  assert.deepEqual(config.compilerOptions.types, ['node']);
  for (const name of ['strict', 'noUnusedLocals', 'noUnusedParameters', 'noFallthroughCasesInSwitch', 'noEmit']) {
    assert.equal(config.compilerOptions[name], true, name);
  }
  assert.equal(config.compilerOptions.target, 'es2020');
  assert.equal(config.compilerOptions.moduleResolution, 'bundler');
  assert.deepEqual(config.compilerOptions.lib, ['es2020', 'dom', 'dom.iterable']);
  assert.ok(config.files.some(filename => path.resolve(root, filename) === path.join(root, 'src', '__tests__', 'app.integration.test.ts')));
  const manifest = JSON.parse(readFileSync(path.join(root, 'package.json'), 'utf8'));
  assert.ok(manifest.devDependencies['@types/node'], 'Node types must be a direct dependency');
});

test('Node and DOM APIs are both checked by the installed compiler', () => {
  fixture({}, `
    import { readFileSync } from 'node:fs';
    import { createHash } from 'node:crypto';
    export const digest: string = createHash('sha256').update(readFileSync(new URL(import.meta.url))).digest('hex');
    export const bytes: Uint8Array = Buffer.from('public synthetic fixture');
    export const element: HTMLElement = document.createElement('span');
    element.textContent = digest;
  `, result => assert.equal(result.status, 0, result.stdout + result.stderr));
});

test('removing ambient Node types fails the actual included integration-test imports', () => {
  fixture({ types: [] }, null, result => {
    assert.equal(result.status, 1, result.stdout + result.stderr);
    for (const name of ['fs', 'url', 'path', 'crypto']) {
      assert.match(result.stdout, new RegExp(`app\\.integration\\.test\\.ts.*TS2591:.*node:${name}`));
    }
  });
});

test('an implicit-any fixture remains a real compiler error', () => {
  fixture({}, 'export function unsupported(value) { return value; }', result => {
    assert.equal(result.status, 1, result.stdout + result.stderr);
    assert.match(result.stdout, /TS7006: Parameter 'value' implicitly has an 'any' type/);
  });
});
