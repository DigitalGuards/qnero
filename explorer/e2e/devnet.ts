/**
 * The dev chain the smoke test runs against.
 *
 * It starts one node, shields once so an entry exists and sends once so a
 * settlement exists, then writes down the two heights the spec asserts on.
 * The node is pinned to one mining thread and every process is niced, because
 * a RandomX miner and a Plonky2 prover on one workstation is the whole
 * machine otherwise.
 */

import { spawn, spawnSync } from 'node:child_process';
import { connect, createServer } from 'node:net';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as sleep } from 'node:timers/promises';

const HERE = dirname(fileURLToPath(import.meta.url));
export const EXPLORER_DIR = join(HERE, '..');
const REPO = join(EXPLORER_DIR, '..');
const WORK = join(EXPLORER_DIR, '.devnet');

const NODE_BIN = join(REPO, 'chain', 'target', 'release', 'qnero-node');
const WALLET_BIN = join(REPO, 'target', 'release', 'qnero-wallet');

export const RPC_PORT = 9944;
export const RPC_HTTP = `http://127.0.0.1:${RPC_PORT}`;

export interface DevnetFacts {
  rpc: string;
  shieldHeight: number;
  shieldLeaf: number;
  shieldQnr: string;
  settlementHeight: number;
}

export const FACTS_PATH = join(WORK, 'facts.json');
const PID_PATH = join(WORK, 'node.pid');
const LOG_PATH = join(WORK, 'node.log');

function requireBinaries(): void {
  const missing = [NODE_BIN, WALLET_BIN].filter((path) => !existsSync(path));
  if (missing.length > 0) {
    throw new Error(
      [
        'the smoke test needs release builds of the node and the wallet:',
        '  cd chain && LIBCLANG_PATH=/usr/lib/llvm-18/lib nice -n 19 cargo build -j 4 --release -p qnero-node',
        '  nice -n 19 cargo build -j 2 --release -p qnero-wallet --features parallel',
        `missing: ${missing.map((path) => path.replace(`${REPO}/`, '')).join(', ')}`,
      ].join('\n'),
    );
  }
}

function wallet(args: string[], env: Record<string, string> = {}): string {
  const result = spawnSync('nice', ['-n', '19', WALLET_BIN, ...args], {
    cwd: WORK,
    encoding: 'utf8',
    env: { ...process.env, ...env },
    maxBuffer: 32 * 1024 * 1024,
  });
  if (result.status !== 0) {
    throw new Error(
      `qnero-wallet ${args[0] ?? ''} failed: ${result.stderr || result.stdout || 'no output'}`,
    );
  }
  return result.stdout;
}

/** Whether anything is listening on the RPC port. */
export async function portIsOpen(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = connect({ port, host: '127.0.0.1' });
    const done = (open: boolean): void => {
      socket.destroy();
      resolve(open);
    };
    socket.setTimeout(1000);
    socket.once('connect', () => {
      done(true);
    });
    socket.once('timeout', () => {
      done(false);
    });
    socket.once('error', () => {
      done(false);
    });
  });
}

/** Whether the port can be bound, which is the stronger statement after a stop. */
async function portIsFree(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const server = createServer();
    server.once('error', () => {
      resolve(false);
    });
    server.once('listening', () => {
      server.close(() => {
        resolve(true);
      });
    });
    server.listen(port, '127.0.0.1');
  });
}

async function rpc(method: string, params: unknown[] = []): Promise<unknown> {
  const response = await fetch(RPC_HTTP, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });
  const body = (await response.json()) as { result?: unknown; error?: { message: string } };
  if (body.error !== undefined) {
    throw new Error(`${method}: ${body.error.message}`);
  }
  return body.result;
}

async function waitForHeight(target: number, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const header = (await rpc('chain_getHeader')) as { number: string };
      if (Number(BigInt(header.number)) >= target) {
        return;
      }
    } catch {
      // The node is not answering yet.
    }
    await sleep(1000);
  }
  throw new Error(`the dev node did not reach block ${target} within ${timeoutMs} ms`);
}

function matchNumber(output: string, pattern: RegExp, what: string): number {
  const match = pattern.exec(output);
  if (match?.[1] === undefined) {
    throw new Error(`the wallet did not report ${what}:\n${output}`);
  }
  return Number(match[1]);
}

export async function startDevnet(): Promise<DevnetFacts> {
  requireBinaries();
  if (await portIsOpen(RPC_PORT)) {
    throw new Error(
      `something is already listening on ${RPC_PORT}; stop it before running the smoke test`,
    );
  }
  rmSync(WORK, { recursive: true, force: true });
  mkdirSync(WORK, { recursive: true });

  wallet(['--file', 'a.seed', 'keygen']);
  const minerKey = /qnm1[a-z0-9]+/.exec(wallet(['--file', 'a.seed', 'miner-address']))?.[0];
  if (minerKey === undefined) {
    throw new Error('qnero-wallet miner-address printed no qnm1 key');
  }

  writeFileSync(LOG_PATH, '');
  const child = spawn(
    'nice',
    ['-n', '19', NODE_BIN, '--dev', '--tmp', '--mining-threads', '1'],
    {
      cwd: WORK,
      env: { ...process.env, QNERO_MINER_KEY: minerKey },
      stdio: ['ignore', 'pipe', 'pipe'],
      detached: true,
    },
  );
  child.stdout.on('data', (chunk: Buffer) => {
    writeFileSync(LOG_PATH, chunk, { flag: 'a' });
  });
  child.stderr.on('data', (chunk: Buffer) => {
    writeFileSync(LOG_PATH, chunk, { flag: 'a' });
  });
  child.unref();
  if (child.pid === undefined) {
    throw new Error('the dev node did not start');
  }
  writeFileSync(PID_PATH, String(child.pid));

  await waitForHeight(2, 120_000);

  const bAddress = /qn1[a-z0-9]+/.exec(wallet(['--file', 'b.seed', 'keygen']))?.[0];
  if (bAddress === undefined) {
    throw new Error('qnero-wallet keygen printed no address');
  }

  const proving = { RAYON_NUM_THREADS: '4' };
  const shielded = wallet(
    ['--file', 'a.seed', 'shield', '--from-dev-account', 'alice', '--amount', '1000'],
    proving,
  );
  const shieldHeight = matchNumber(shielded, /included\s+block (\d+)/, 'the shield inclusion block');
  const shieldLeaf = matchNumber(shielded, /leaf\s+(\d+)/, "the shield's leaf");

  const sent = wallet(
    ['--file', 'a.seed', 'send', '--to', bAddress, '--amount', '300'],
    proving,
  );
  const settlementHeight = matchNumber(sent, /inclusion\s+block (\d+)/, 'the settlement block');

  const facts: DevnetFacts = {
    rpc: `ws://127.0.0.1:${RPC_PORT}`,
    shieldHeight,
    shieldLeaf,
    // 1000 pool quanta, at 10^10 planck each and 12 decimals, rendered with the
    // two decimals every amount on the site carries.
    shieldQnr: '10.00 QNR',
    settlementHeight,
  };
  writeFileSync(FACTS_PATH, `${JSON.stringify(facts, null, 2)}\n`);
  return facts;
}

export function readFacts(): DevnetFacts {
  return JSON.parse(readFileSync(FACTS_PATH, 'utf8')) as DevnetFacts;
}

/** Stop the node by its pidfile, and do not return until the port is free. */
export async function stopDevnet(): Promise<void> {
  if (!existsSync(PID_PATH)) {
    return;
  }
  const pid = Number(readFileSync(PID_PATH, 'utf8').trim());
  if (Number.isFinite(pid) && pid > 0) {
    try {
      process.kill(pid, 'SIGTERM');
    } catch {
      // Already gone.
    }
    const deadline = Date.now() + 30_000;
    while (Date.now() < deadline) {
      try {
        process.kill(pid, 0);
      } catch {
        break;
      }
      await sleep(500);
    }
    try {
      process.kill(pid, 'SIGKILL');
    } catch {
      // Already gone.
    }
  }
  rmSync(PID_PATH, { force: true });

  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    if (!(await portIsOpen(RPC_PORT)) && (await portIsFree(RPC_PORT))) {
      return;
    }
    await sleep(500);
  }
  throw new Error(`port ${RPC_PORT} is still held after stopping the dev node`);
}
