/**
 * What a sync is made of, in the order a reader meets it.
 *
 * The sending screen has a weighted bar, a named phase list and a clock; the
 * sync had a spinner inside a disabled button and forty-five words about
 * ciphertexts and spend markers. So the sync borrows the sending screen's
 * shape, and this module is the part of it that is arithmetic: which phase a
 * stage belongs to, and how far along the bar is.
 *
 * Its own module for the reason `sendPhases.ts` is: what it says can be
 * asserted without a browser, and a mapping that silently stops covering a
 * stage is a bar that stops moving.
 *
 * The stage names are `wallet/sync.ts`'s own and they are internal: `spend
 * markers` and `scan` are the vocabulary of the pass rather than of the
 * screen, and the labels here are what a reader sees.
 */

/** The phases, their stages, and roughly what share of a full pass each is. */
export const SYNC_PHASES: { label: string; keys: readonly string[]; weight: number }[] = [
  { label: 'checking the node', keys: ['chain', 'gates'], weight: 0.02 },
  { label: 'reading spent status', keys: ['spend markers'], weight: 0.13 },
  { label: 'reading the chain', keys: ['headers'], weight: 0.35 },
  { label: 'reading transfers', keys: ['scan'], weight: 0.5 },
];

const TOTAL_WEIGHT = SYNC_PHASES.reduce((sum, phase) => sum + phase.weight, 0);

/** Which phase a stage belongs to, or -1 for one this screen does not name. */
export function syncPhaseIndex(stage: string | null): number {
  if (stage === null) {
    return -1;
  }
  return SYNC_PHASES.findIndex((phase) => phase.keys.includes(stage));
}

/**
 * The share of its own phase a detail reports, or null.
 *
 * Every long stage counts out loud ("120 of 640"), so the running phase's own
 * progress is a measurement rather than a clock guessing at one. A phase with
 * nothing to count sits at its own boundary until it ends, which is honest:
 * the alternative is a bar that moves while nothing does.
 */
export function countedFraction(detail: string | null): number | null {
  if (detail === null) {
    return null;
  }
  const found = /(\d[\d,]*) of (\d[\d,]*)/.exec(detail);
  if (found === null) {
    return null;
  }
  const done = Number((found[1] ?? '0').replace(/,/g, ''));
  const total = Number((found[2] ?? '0').replace(/,/g, ''));
  if (!Number.isFinite(done) || !Number.isFinite(total) || total <= 0) {
    return null;
  }
  return Math.min(1, Math.max(0, done / total));
}

/**
 * Whether a detail is a count, which is the only kind the phase row shows.
 *
 * A counted detail reads beside its label: "reading the chain 5 of 5 entry
 * hashes". A sentence one does not: "checking the node checking the chain this
 * node serves" and "reading the chain checking each block against the tree it
 * published" are a stutter rather than a phase and its progress. The sending
 * screen puts its sentence details on the elapsed line, and this screen does
 * the same.
 */
export function isCountedDetail(detail: string | null | undefined): boolean {
  return detail !== null && detail !== undefined && countedFraction(detail) !== null;
}

/**
 * The bar's share for the next frame of one pass, which only ever grows.
 *
 * A stage detail with no count reports nothing, and `syncFraction` reads that
 * as its phase's start. "reading the chain" counting "5 of 5 entry hashes"
 * and then saying "checking each block against the tree it published" took the
 * bar from 155 px of its 309 px track to 79 px in two frames 0.3 s apart, with
 * the 300 ms width transition animating the retreat. A bar that visibly slides
 * backwards is the exact "this is stuck" reading the phase list exists to
 * prevent, and on a chain at block 2,000 that phase is seconds long.
 *
 * The floor is per pass. `SyncProgress` is mounted only while a sync runs, so
 * the ref holding the previous value is created when a pass starts and goes
 * with it when the pass ends.
 */
export function advanceSyncFraction(
  previous: number,
  stage: string | null,
  detail: string | null,
): number {
  return Math.max(previous, syncFraction(stage, detail));
}

/** How far along the whole pass is: phases finished, plus this one's share. */
export function syncFraction(stage: string | null, detail: string | null): number {
  const current = syncPhaseIndex(stage);
  if (current < 0) {
    return 0;
  }
  const done = SYNC_PHASES.slice(0, current).reduce((sum, phase) => sum + phase.weight, 0);
  const phase = SYNC_PHASES[current];
  if (phase === undefined) {
    return 1;
  }
  const within = countedFraction(detail) ?? 0;
  return (done + phase.weight * within) / TOTAL_WEIGHT;
}
