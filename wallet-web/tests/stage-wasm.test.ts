/**
 * The prebuilt-prover digest gate, run against a throwaway tree.
 *
 * Under `QNERO_WASM_PREBUILT=1` the modules are bytes the deploy did not
 * build, and the only thing tying them to the machine that did is the SHA-256
 * manifest. The gate used to pin the two `.wasm` files and count the digests,
 * so the two generated `qnero_prover_wasm.js` glue files and the whole
 * `pkg-threaded/snippets/` tree were copied into `public/wasm/` unchecked. The
 * glue is what `deriveAccount` hands the seed to, and the snippet is the
 * worker entry point `initThreadPool` fetches, so that was the editable half
 * left open.
 *
 * Each case here builds a tree shaped like the repo, runs the real script in
 * it, and reads the exit status. Nothing touches the repo's own `public/`.
 */

import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

const SCRIPT = join(__dirname, '..', 'scripts', 'stage-wasm.sh');

/** The files the stage copies, with the contents this fixture gives them. */
const STAGED: Record<string, string> = {
  'pkg/qnero_prover_wasm.js': 'export function deriveAccount() {}\n',
  'pkg/qnero_prover_wasm_bg.wasm': 'single-threaded module bytes\n',
  'pkg-threaded/qnero_prover_wasm.js': 'export function deriveAccount() {}\n',
  'pkg-threaded/qnero_prover_wasm_bg.wasm': 'threaded module bytes\n',
  'pkg-threaded/snippets/wasm-bindgen-rayon-0/src/workerHelpers.js': 'export const pool = 1;\n',
};

const roots: string[] = [];

afterEach(() => {
  while (roots.length > 0) {
    const root = roots.pop();
    if (root !== undefined) {
      rmSync(root, { recursive: true, force: true });
    }
  }
});

function write(root: string, relative: string, contents: string): void {
  const path = join(root, relative);
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, contents);
}

/** A tree shaped like the repo, with the real script copied into it. */
function makeTree(): string {
  const root = mkdtempSync(join(tmpdir(), 'qnero-stage-wasm-'));
  roots.push(root);
  write(root, 'wallet-web/scripts/stage-wasm.sh', readFileSync(SCRIPT, 'utf8'));
  // The export check reads the crate's own source for every `js_name`.
  write(
    root,
    'crates/qnero-prover-wasm/src/lib.rs',
    '#[wasm_bindgen(js_name = deriveAccount)]\npub fn derive_account() {}\n',
  );
  for (const [relative, contents] of Object.entries(STAGED)) {
    write(root, join('crates/qnero-prover-wasm/www', relative), contents);
  }
  return root;
}

/** A manifest over the named paths, in `sha256sum` form. */
function writeManifest(root: string, paths: readonly string[]): void {
  const lines = paths.map((relative) => {
    const bytes = readFileSync(join(root, 'crates/qnero-prover-wasm/www', relative));
    return `${createHash('sha256').update(bytes).digest('hex')}  ${relative}`;
  });
  write(root, 'wallet-web/wasm-prebuilt.sha256', `${lines.join('\n')}\n`);
}

interface Run {
  status: number;
  output: string;
}

function stage(root: string): Run {
  try {
    const output = execFileSync(
      'bash',
      [join(root, 'wallet-web/scripts/stage-wasm.sh'), '--threaded'],
      { env: { ...process.env, QNERO_WASM_PREBUILT: '1' }, encoding: 'utf8', stdio: 'pipe' },
    );
    return { status: 0, output };
  } catch (error) {
    const failure = error as { status?: number; stdout?: string; stderr?: string };
    return {
      status: failure.status ?? 1,
      output: `${failure.stdout ?? ''}${failure.stderr ?? ''}`,
    };
  }
}

describe('the prebuilt prover gate', () => {
  it('stages a tree whose manifest covers every file it copies', () => {
    const root = makeTree();
    writeManifest(root, Object.keys(STAGED));
    const run = stage(root);
    expect(run.output).toContain('every staged prover file matches');
    expect(run.status).toBe(0);
  });

  it('refuses a manifest that leaves the glue out, naming the file', () => {
    const root = makeTree();
    writeManifest(
      root,
      Object.keys(STAGED).filter((path) => path.endsWith('.wasm')),
    );
    const run = stage(root);
    expect(run.status).not.toBe(0);
    expect(run.output).toContain('pkg/qnero_prover_wasm.js');
    expect(run.output).toContain('Nothing has been staged');
  });

  it('refuses a manifest that leaves the worker snippet out', () => {
    const root = makeTree();
    writeManifest(
      root,
      Object.keys(STAGED).filter((path) => !path.includes('snippets/')),
    );
    const run = stage(root);
    expect(run.status).not.toBe(0);
    expect(run.output).toContain('workerHelpers.js');
  });

  it('refuses glue that was edited after the manifest was written', () => {
    const root = makeTree();
    writeManifest(root, Object.keys(STAGED));
    // A line that reads as harmless and sends the seed somewhere else. The
    // export check passes it, because every declared name is still there.
    write(
      root,
      'crates/qnero-prover-wasm/www/pkg/qnero_prover_wasm.js',
      `${STAGED['pkg/qnero_prover_wasm.js'] ?? ''}// edited\n`,
    );
    const run = stage(root);
    expect(run.status).not.toBe(0);
    expect(run.output).toContain('does not match');
  });

  it('refuses a snippet that was edited after the manifest was written', () => {
    const root = makeTree();
    writeManifest(root, Object.keys(STAGED));
    write(
      root,
      'crates/qnero-prover-wasm/www/pkg-threaded/snippets/wasm-bindgen-rayon-0/src/workerHelpers.js',
      'export const pool = 2;\n',
    );
    const run = stage(root);
    expect(run.status).not.toBe(0);
    expect(run.output).toContain('does not match');
  });

  it('refuses when there is no manifest at all', () => {
    const root = makeTree();
    const run = stage(root);
    expect(run.status).not.toBe(0);
    expect(run.output).toContain('no readable SHA-256 manifest');
  });
});
