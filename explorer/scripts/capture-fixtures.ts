/**
 * Capture decoder fixtures from a running dev node.
 *
 * ```text
 * nice -n 19 npx vite-node scripts/capture-fixtures.ts -- ws://127.0.0.1:9944
 * ```
 *
 * Run it against a devnet that has shielded once and sent once, so that both
 * an entry and a settlement are on the chain. It writes `tests/fixtures/`,
 * which the decoder tests read; nothing in it is hand-written, and nothing in
 * it names the machine it came from.
 */

import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { connect, normaliseEvents } from '../src/chain/api';
import type { EventRecord } from '../src/lib/events';

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT = join(HERE, '..', 'tests', 'fixtures');

/** Hex kept for a body too large to carry whole. The parse never reads past the head. */
const TRUNCATE_BYTES = 64;

async function eventsAt(
  context: Awaited<ReturnType<typeof connect>>,
  hash: string,
): Promise<EventRecord[]> {
  const at = await context.api.at(hash);
  const query = at.query['system']?.['events'];
  if (query === undefined) {
    throw new Error('the runtime declares no System::Events');
  }
  const records = await query();
  return normaliseEvents(records as unknown as Parameters<typeof normaliseEvents>[0]);
}

function write(name: string, value: unknown): void {
  mkdirSync(OUT, { recursive: true });
  writeFileSync(join(OUT, name), `${JSON.stringify(value, null, 2)}\n`);
  console.log(`wrote tests/fixtures/${name}`);
}

/** The provider retries forever, so a missing node has to be its own error. */
async function connectOrGiveUp(
  endpoint: string,
  timeoutMs: number,
): Promise<Awaited<ReturnType<typeof connect>>> {
  let timer: NodeJS.Timeout | undefined;
  const expiry = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => {
      reject(new Error(`no node answered ${endpoint} within ${timeoutMs} ms`));
    }, timeoutMs);
  });
  try {
    return await Promise.race([connect(endpoint), expiry]);
  } finally {
    clearTimeout(timer);
  }
}

async function main(): Promise<void> {
  const endpoint = process.argv[2] ?? 'ws://127.0.0.1:9944';
  const context = await connectOrGiveUp(endpoint, 15_000);
  const bestHash = await context.provider.send<string>('chain_getBlockHash', []);
  const bestHeader = await context.provider.send<{ number: string }>('chain_getHeader', [bestHash]);
  const head = Number(BigInt(bestHeader.number));

  let shieldHeight: number | null = null;
  let settlementHeight: number | null = null;
  for (let height = head; height >= 1; height -= 1) {
    const hash = await context.provider.send<string>('chain_getBlockHash', [height]);
    const events = await eventsAt(context, hash);
    if (shieldHeight === null && events.some((e) => e.section === 'shielded' && e.method === 'Shielded')) {
      shieldHeight = height;
    }
    if (
      settlementHeight === null &&
      events.some((e) => e.section === 'shielded' && e.method === 'SlotSettled')
    ) {
      settlementHeight = height;
    }
    if (shieldHeight !== null && settlementHeight !== null) {
      break;
    }
  }
  if (shieldHeight === null || settlementHeight === null) {
    throw new Error(
      `this chain has no ${shieldHeight === null ? 'shield entry' : 'settlement'} in its first ${head} blocks`,
    );
  }

  const capture = async (height: number): Promise<{ hash: string; header: unknown; events: EventRecord[]; extrinsics: string[] }> => {
    const hash = await context.provider.send<string>('chain_getBlockHash', [height]);
    const header = await context.provider.send<unknown>('chain_getHeader', [hash]);
    const block = await context.provider.send<{ block: { extrinsics: string[] } }>(
      'chain_getBlock',
      [hash],
    );
    return { hash, header, events: await eventsAt(context, hash), extrinsics: block.block.extrinsics };
  };

  const shield = await capture(shieldHeight);
  const settlement = await capture(settlementHeight);

  write('meta.json', {
    capturedFrom: 'a local --dev --tmp node',
    specName: context.specName,
    specVersion: context.specVersion,
    transactionVersion: context.transactionVersion,
    tokenSymbol: context.tokenSymbol,
    tokenDecimals: context.tokenDecimals,
    ss58Format: context.ss58Format,
    shieldHeight,
    settlementHeight,
  });
  write('header-settlement.json', { hash: settlement.hash, header: settlement.header });
  write('events-shield.json', { height: shieldHeight, hash: shield.hash, records: shield.events });
  write('events-settlement.json', {
    height: settlementHeight,
    hash: settlement.hash,
    records: settlement.events,
  });

  const layout = {
    signatureLengths: [...context.layout.signatureLengths.entries()],
    extensions: [...context.layout.extensions],
    multiAddress: context.layout.multiAddress,
  };
  const entries = [
    ...shield.extrinsics.map((hex, index) => ({ block: 'shield', index, hex })),
    ...settlement.extrinsics.map((hex, index) => ({ block: 'settlement', index, hex })),
  ].map((entry) => {
    const bytes = (entry.hex.length - 2) / 2;
    const truncated = bytes > 16384;
    return {
      ...entry,
      bytes,
      truncated,
      hex: truncated ? entry.hex.slice(0, 2 + TRUNCATE_BYTES * 2) : entry.hex,
    };
  });
  write('extrinsics.json', { layout, entries });

  await context.api.disconnect();
}

await main();
