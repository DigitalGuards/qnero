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
