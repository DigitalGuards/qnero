/**
 * The dev chain the browser wallet is driven against.
 *
 * Shape and process discipline are the explorer's (`explorer/e2e/devnet.ts`):
 * one node, pinned to one mining thread, every process niced, stopped by
 * pidfile with the port confirmed closed and bindable before the harness
 * returns. A RandomX miner, a native Plonky2 prover and a wasm one on a
 * workstation is the whole machine otherwise.
 *
 * What is different is who holds the value. The explorer only needed a chain
 * with something on it. This suite needs value to arrive in a wallet whose
 * address does not exist until the browser has created it, so the setup goes
 * only as far as it can without that address: it starts the node, gives the
 * node wallet A's miner key, and shields a transparent balance into A. The
 * spec then reads the browser wallet's address off its own receive screen and
 * has A send to it, which is the only way into a shielded pool from outside
 * it: `shield` moves a dev account's transparent balance into the shielding
 * wallet's own note, and it takes no recipient.
 */

import { spawn, spawnSync } from 'node:child_process';
import { connect, createServer } from 'node:net';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as sleep } from 'node:timers/promises';

const HERE = dirname(fileURLToPath(import.meta.url));
export const APP_DIR = join(HERE, '..');
const REPO = join(APP_DIR, '..');
const WORK = join(APP_DIR, '.devnet');

const NODE_BIN = join(REPO, 'chain', 'target', 'release', 'qnero-node');
const WALLET_BIN = join(REPO, 'target', 'release', 'qnero-wallet');

/**
 * The port the dev chain answers on.
 *
 * Overridable, because 9944 is the port every Substrate node defaults to and
 * this workstation runs other ones: a suite that can only run when nothing
 * else holds that port is a suite that cannot be run on demand. The node, the
 * command-line wallet and the browser are all pointed at whatever this says,
 * so there is one place to change it and no second copy to disagree.
 */
export const RPC_PORT = Number(process.env['QNERO_DEVNET_PORT'] ?? '9944');
export const RPC_HTTP = `http://127.0.0.1:${RPC_PORT}`;
export const RPC_WS = `ws://127.0.0.1:${RPC_PORT}`;

/**
 * Four threads for a native prove, which is the workstation rule for this
 * repository, and it is also what the CLI's own docs assume.
 */
const PROVING_ENV = { RAYON_NUM_THREADS: '4' };

export interface DevnetFacts {
  rpc: string;
  /** The CLI wallet holding the shielded balance the browser is funded from. */
  senderSeed: string;
  senderAddress: string;
  /** The CLI wallet the browser pays, so a second implementation reads the note. */
  recipientSeed: string;
  recipientAddress: string;
  shieldHeight: number;
  shieldedQuanta: number;
}

export const FACTS_PATH = join(WORK, 'facts.json');
const PID_PATH = join(WORK, 'node.pid');
const LOG_PATH = join(WORK, 'node.log');

function requireBinaries(): void {
  const missing = [NODE_BIN, WALLET_BIN].filter((path) => !existsSync(path));
  if (missing.length > 0) {
    throw new Error(
      [
        'this suite needs release builds of the node and the command-line wallet:',
        '  cd chain && LIBCLANG_PATH=/usr/lib/llvm-18/lib nice -n 19 cargo build -j 2 --release -p qnero-node',
        '  nice -n 19 cargo build -j 2 --release -p qnero-wallet --features parallel',
        `missing: ${missing.map((path) => path.replace(`${REPO}/`, '')).join(', ')}`,
      ].join('\n'),
    );
  }
}

/**
 * One command-line wallet invocation, niced, inside the work directory.
 *
 * `--node` is passed on every call rather than left to the default, so the
 * command-line wallet and the browser are talking to the same chain even when
 * that chain is not on the port a node defaults to.
 */
export function wallet(args: string[], env: Record<string, string> = {}): string {
  const result = spawnSync('nice', ['-n', '19', WALLET_BIN, '--node', RPC_HTTP, ...args], {
    cwd: WORK,
    encoding: 'utf8',
    env: { ...process.env, ...env },
    maxBuffer: 32 * 1024 * 1024,
  });
  if (result.status !== 0) {
    throw new Error(
      `qnero-wallet ${args.join(' ')} failed:\n${result.stderr || result.stdout || 'no output'}`,
    );
  }
  return result.stdout;
}

/** A prove-and-submit command, which is the only kind that wants threads. */
export function walletProving(args: string[]): string {
  return wallet(args, PROVING_ENV);
}

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

export async function headHeight(): Promise<number> {
  const header = (await rpc('chain_getHeader')) as { number: string };
  return Number(BigInt(header.number));
}

async function waitForHeight(target: number, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      if ((await headHeight()) >= target) {
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

function matchAddress(output: string, prefix: 'qn1' | 'qnm1'): string {
  const match = new RegExp(`${prefix}[a-z0-9]+`).exec(output);
  if (match === null) {
    throw new Error(`the wallet printed no ${prefix} value:\n${output}`);
  }
  return match[0];
}

export async function startDevnet(): Promise<DevnetFacts> {
  requireBinaries();
  if (await portIsOpen(RPC_PORT)) {
    throw new Error(
      `something is already listening on ${RPC_PORT}; stop it before running this suite`,
    );
  }
  rmSync(WORK, { recursive: true, force: true });
  mkdirSync(WORK, { recursive: true });

  // Wallet A: the block author's wallet and the source of the browser's funds.
  wallet(['--file', 'sender.seed', 'keygen']);
  const senderAddress = matchAddress(wallet(['--file', 'sender.seed', 'address']), 'qn1');
  const minerKey = matchAddress(wallet(['--file', 'sender.seed', 'miner-address']), 'qnm1');

  writeFileSync(LOG_PATH, '');
  const child = spawn(
    'nice',
    [
      '-n',
      '19',
      NODE_BIN,
      '--dev',
      '--tmp',
      '--mining-threads',
      '1',
      '--rpc-port',
      String(RPC_PORT),
    ],
    {
      cwd: WORK,
      // The environment variable rather than the command line: every process
      // listing on a machine can read a command line, and the miner key
      // carries the coinbase viewing key.
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

  await waitForHeight(2, 180_000);

  // Wallet B: the recipient, so the payment the browser makes is read back by
  // an implementation that shares no code with it.
  wallet(['--file', 'recipient.seed', 'keygen']);
  const recipientAddress = matchAddress(wallet(['--file', 'recipient.seed', 'address']), 'qn1');

  // 2000 quanta, which is the 1000 the browser is funded with plus the fee of
  // the transfer that funds it and enough change to leave A spendable.
  const shieldedQuanta = 2000;
  const shielded = walletProving([
    '--file',
    'sender.seed',
    'shield',
    '--from-dev-account',
    'alice',
    '--amount',
    String(shieldedQuanta),
  ]);
  const shieldHeight = matchNumber(shielded, /included\s+block (\d+)/, 'the shield inclusion block');

  const facts: DevnetFacts = {
    rpc: RPC_WS,
    senderSeed: join(WORK, 'sender.seed'),
    senderAddress,
    recipientSeed: join(WORK, 'recipient.seed'),
    recipientAddress,
    shieldHeight,
    shieldedQuanta,
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
