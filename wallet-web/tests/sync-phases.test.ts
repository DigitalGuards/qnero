/**
 * The sync's phase list, and the bar over it.
 *
 * A bar is a claim about how far along something is, and the claim is only
 * true while every stage the pass reports has a phase to belong to. The
 * mapping is the part that rots: a stage renamed in `wallet/sync.ts` and not
 * here is a bar that stops moving and a phase list that never lights up, and
 * neither of those fails anything else in this suite.
 *
 * So the stage names are read out of the pass itself rather than copied here.
 */

import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import {
  SYNC_PHASES,
  countedFraction,
  syncFraction,
  syncPhaseIndex,
} from '../src/screens/syncPhases';

const SYNC_SOURCE = readFileSync(new URL('../src/wallet/sync.ts', import.meta.url), 'utf8');

/** Every stage `runSync` reports, as it spells them. */
function stagesReported(): Set<string> {
  const found = new Set<string>();
  for (const match of SYNC_SOURCE.matchAll(/progress\(\s*'([^']+)'/g)) {
    found.add(match[1] ?? '');
  }
  return found;
}

describe('the phases a sync is drawn as', () => {
  it('names every stage the pass reports', () => {
    const missing = [...stagesReported()].filter((stage) => syncPhaseIndex(stage) < 0);
    expect(missing, `these stages have no phase on the screen: ${missing.join(', ')}`).toEqual([]);
  });

  it('keeps the stages in the order the pass runs them', () => {
    expect(syncPhaseIndex('chain')).toBe(0);
    expect(syncPhaseIndex('gates')).toBe(0);
    expect(syncPhaseIndex('spend markers')).toBe(1);
    expect(syncPhaseIndex('headers')).toBe(2);
    expect(syncPhaseIndex('scan')).toBe(3);
  });

  it('names no phase for a stage that is not a sync, such as the prover building', () => {
    // The worker reports its own stages through the same listener, and one of
    // them is a circuit build. A phase list that lit up for it would be
    // telling a reader a scan is somewhere it is not.
    expect(syncPhaseIndex('build')).toBe(-1);
    expect(syncPhaseIndex(null)).toBe(-1);
  });

  it('spends the whole bar over the four phases', () => {
    expect(SYNC_PHASES.reduce((sum, phase) => sum + phase.weight, 0)).toBeCloseTo(1, 5);
  });
});

describe('how far along the bar is', () => {
  it('is nothing before a stage is reported', () => {
    expect(syncFraction(null, null)).toBe(0);
    expect(syncFraction('chain', null)).toBeCloseTo(0, 5);
  });

  it('reads the running phase out of its own count', () => {
    // "reading transfers 320 of 640" is half of the last phase, which is half
    // of the bar: the count is a measurement rather than a clock guessing.
    expect(countedFraction('320 of 640')).toBeCloseTo(0.5, 5);
    expect(countedFraction('1,024 of 2,048')).toBeCloseTo(0.5, 5);
    expect(countedFraction('paging the settled set')).toBeNull();
    expect(countedFraction(null)).toBeNull();
  });

  it('never goes backwards from one phase to the next', () => {
    const start = syncFraction('spend markers', null);
    const middle = syncFraction('headers', '50 of 100');
    const late = syncFraction('scan', '600 of 640');
    expect(start).toBeLessThan(middle);
    expect(middle).toBeLessThan(late);
    expect(late).toBeLessThanOrEqual(1);
  });

  it('holds a count that overruns its own total at the phase boundary', () => {
    // A node that answers more than it reported would otherwise push the bar
    // past the phase it is in.
    expect(countedFraction('900 of 640')).toBe(1);
    expect(syncFraction('scan', '900 of 640')).toBeCloseTo(1, 5);
  });
});
