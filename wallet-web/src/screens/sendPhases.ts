/**
 * The sending screen's phases, and what share of the wait each one is.
 *
 * Its own module so the weighting can be asserted without pulling React into
 * a Node test environment: what it says is arithmetic, and the failure it
 * exists to prevent is arithmetic too.
 */

import type { SpendProgress } from '../wallet/send';

/**
 * The phases, and roughly what share of the wait each one is.
 *
 * Weighted rather than counted. Eight equal steps put the bar at 75% the
 * moment proving starts and left it there for the next ten to fifty seconds,
 * which is the exact reading the phase list exists to prevent: a bar that
 * raced to three quarters and stopped is a send that looks hung. The weights
 * are this machine's measurement (`docs/BENCH.md`): proving is about two
 * thirds of a payment on the threaded module and more than that on one thread.
 */
export const PHASES: { key: SpendProgress['stage']; label: string; weight: number }[] = [
  { key: 'fee', label: 'fee floor', weight: 0.01 },
  { key: 'select', label: 'choosing what to spend', weight: 0.01 },
  { key: 'build', label: 'building the circuits', weight: 0.2 },
  { key: 'anchor', label: 'anchoring to the head', weight: 0.02 },
  { key: 'tree', label: 'rebuilding the tree', weight: 0.03 },
  { key: 'prove', label: 'proving the private batch', weight: 0.65 },
  { key: 'submit', label: 'submitting', weight: 0.02 },
  { key: 'confirm', label: 'waiting for inclusion', weight: 0.06 },
];

const TOTAL_WEIGHT = PHASES.reduce((sum, phase) => sum + phase.weight, 0);

/**
 * How far along the bar is: everything finished, plus what the running phase
 * has spent of its own share.
 *
 * `millisInPhase` is the clock since this phase started, and `expectedMillis`
 * is what the whole payment is expected to take, so the phase's own budget is
 * its weight of that. Both of those are load bearing. The elapsed clock of the
 * whole send over the whole send's expectation was neither: it crawled to 11%
 * through a circuit build that is a fifth of the payment, jumped fifty-eight
 * points in one frame when proving started, then saturated at the clamp and
 * sat still for the last ten seconds. A bar that jumps and then freezes is the
 * exact reading the weights were introduced to prevent.
 *
 * The running phase's own progress comes from the clock rather than from the
 * worker, which reports a stage and not a fraction, so the bar keeps moving
 * while the longest phase is busy. It is clamped below the next boundary, so
 * it never claims a phase is done before it is.
 */
export function progressFraction(
  current: number,
  millisInPhase: number,
  expectedMillis: number,
): number {
  if (current < 0) {
    return 0;
  }
  const done = PHASES.slice(0, current).reduce((sum, phase) => sum + phase.weight, 0);
  const phase = PHASES[current];
  if (phase === undefined) {
    return 1;
  }
  const budget = expectedMillis * (phase.weight / TOTAL_WEIGHT);
  const within = budget > 0 ? Math.min(0.95, Math.max(0, millisInPhase / budget)) : 0;
  return (done + phase.weight * within) / TOTAL_WEIGHT;
}
