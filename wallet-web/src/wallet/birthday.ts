/**
 * Where a wallet starts reading the chain, read at the wizard's last step.
 *
 * A birthday is the bottom of the first sync's header walk. Read it and a new
 * wallet skips every block under it; miss it and the wallet reads the chain
 * from block zero, which is correct and, on a public chain, slow.
 *
 * # The race this module exists for
 *
 * The socket is opened at boot and the wizard is three screens long, so the
 * two used to be a race the wizard always lost on a slow network: `createWallet`
 * read `session.context` once, found `null` because the socket had not settled,
 * recorded no birthday, and a restore height somebody had typed into the form
 * was gone with it. The wallet then read from block zero and nothing on the
 * screen said the number had been dropped.
 *
 * So the read waits. At the last step of the wizard, for a bounded time, it
 * polls for the two things a birthday needs: the connection and the prover's
 * limits. If they arrive it reads the head and records the birthday from it.
 * If they do not, the outcome carries the typed height back to the caller
 * rather than discarding it, so the page can record it the moment a node
 * answers.
 *
 * The session's fields are not React state and nothing publishes an event when
 * a socket settles, so polling is the honest mechanism: the loop is bounded,
 * its clock is injected, and `tests/birthday.test.ts` drives every edge of it.
 */

import type { ChainContext } from '../chain/api';
import { normaliseHash } from '../lib/hex';
import type { SyncCheckpoint } from './model';

/** How long the wizard's last step waits for a node before it goes on. */
export const BIRTHDAY_WAIT_MS = 8000;

/** How often that wait looks again. */
export const BIRTHDAY_POLL_MS = 100;

/** The two session fields a birthday read needs, read fresh on every poll. */
export interface BirthdaySources {
  context: () => ChainContext | null;
  limits: () => { max_tree_depth: number } | null;
}

/** The two chain reads a birthday is made of, injected so a test can drive them. */
export interface BirthdayReads {
  birthdayAt: (
    context: ChainContext,
    height: number | null,
    maxTreeDepth: number,
  ) => Promise<{ blockNumber: number; blockHash: string; nextLeaf: number }>;
  genesisHash: (context: ChainContext) => Promise<string | null>;
}

/** The recorded birthday, as the store takes it. */
export interface RecordedBirthday {
  checkpoint: SyncCheckpoint;
  genesisHash: string;
}

/**
 * What the read came to.
 *
 * `no-node` and `refused` both carry `restoreHeight`, which is the number
 * somebody typed, or `null` for a wallet being created now. Carrying it is the
 * whole point: a wallet made while the socket was still settling can record
 * its birthday later, and it cannot if the height was thrown away here.
 */
export type BirthdayOutcome =
  | { kind: 'read'; birthday: RecordedBirthday; restoreHeight: number | null }
  | { kind: 'no-node'; restoreHeight: number | null }
  | { kind: 'refused'; restoreHeight: number | null; message: string };

/** The injected clock, so the wait is a millisecond in a test and 8 s in a page. */
export interface BirthdayClock {
  now: () => number;
  sleep: (ms: number) => Promise<void>;
  waitMs?: number;
  pollMs?: number;
}

const realClock: BirthdayClock = {
  now: () => Date.now(),
  sleep: (ms) =>
    new Promise((resolve) => {
      setTimeout(resolve, ms);
    }),
};

/**
 * Wait for the connection and the prover's limits, or give up saying so.
 *
 * Both are read again on every pass rather than captured once: that single
 * capture is the bug this module replaces.
 */
async function waitForChain(
  sources: BirthdaySources,
  clock: BirthdayClock,
): Promise<{ context: ChainContext; maxTreeDepth: number } | null> {
  const waitMs = clock.waitMs ?? BIRTHDAY_WAIT_MS;
  const pollMs = clock.pollMs ?? BIRTHDAY_POLL_MS;
  const until = clock.now() + waitMs;
  for (;;) {
    const context = sources.context();
    const limits = sources.limits();
    if (context !== null && limits !== null) {
      return { context, maxTreeDepth: limits.max_tree_depth };
    }
    if (clock.now() >= until) {
      return null;
    }
    await clock.sleep(pollMs);
  }
}

/**
 * Read the birthday for a wallet being created or restored.
 *
 * `restoreHeight` is the height somebody typed, or `null` for a wallet created
 * now, which starts at the node's own head. A restore that asked for the whole
 * chain never reaches here: it has no birthday by choice.
 */
export async function readBirthday(
  sources: BirthdaySources,
  reads: BirthdayReads,
  restoreHeight: number | null,
  clock: BirthdayClock = realClock,
): Promise<BirthdayOutcome> {
  const ready = await waitForChain(sources, clock);
  if (ready === null) {
    return { kind: 'no-node', restoreHeight };
  }
  try {
    const read = await reads.birthdayAt(ready.context, restoreHeight, ready.maxTreeDepth);
    const genesis = await reads.genesisHash(ready.context);
    if (genesis === null) {
      throw new Error('this node has no block zero, so it cannot say which chain it serves.');
    }
    return {
      kind: 'read',
      restoreHeight,
      birthday: {
        checkpoint: {
          blockNumber: read.blockNumber,
          blockHash: read.blockHash,
          nextLeaf: read.nextLeaf,
        },
        // Normalised, like the birthday's own block hash beside it and like
        // the genesis every sync records: one spelling in the store is one
        // spelling every later comparison reads.
        genesisHash: normaliseHash(genesis),
      },
    };
  } catch (error) {
    return { kind: 'refused', restoreHeight, message: (error as Error).message };
  }
}

/**
 * The sentence a wallet shows once about where it starts reading.
 *
 * One line, in the wallet's own words. The claim about whose number it is, and
 * what an honest node that disagrees does with it, lives behind the balance
 * screen's Last sync disclosure: see `docs/WALLET.md`.
 */
export function birthdayNoticeFor(outcome: BirthdayOutcome): string | null {
  if (outcome.kind === 'read') {
    return outcome.restoreHeight === null
      ? null
      : `This wallet reads the chain from block ${outcome.birthday.checkpoint.blockNumber}, ` +
          'the restore height you gave, rounded down to its epoch.';
  }
  if (outcome.kind === 'no-node') {
    return outcome.restoreHeight === null
      ? 'No node answered, so this wallet reads the chain from block zero. That is correct and ' +
          'slow. Connect a node in Settings.'
      : `No node answered, so block ${outcome.restoreHeight} has not been recorded yet. This ` +
          'wallet records it as soon as a node answers.';
  }
  return `This wallet reads the chain from block zero: ${outcome.message}`;
}
