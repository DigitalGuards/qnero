/**
 * Two numbers on screen, and what each one was saying wrongly.
 *
 * The balance dimmed everything after the decimal point. MyMonero dims the
 * trailing zeros of a twelve-decimal amount, which is padding; a pool quantum
 * is a hundredth of a QNR, so every Qnero balance carries exactly two
 * significant decimals and the same rule dimmed all of them. A 6.92 QNR
 * balance rendered as a bright 6 with the 0.92 at 3.18:1, the faintest thing
 * on the panel.
 *
 * The progress bar weighted eight phases equally. Proving is about two thirds
 * of a payment, so the bar reached 75% the moment proving started and stayed
 * there for the next ten to fifty seconds, which reads as a send that has
 * hung: the exact thing the phase list exists to prevent.
 */

import { describe, expect, it } from 'vitest';

import { formatQuantaAsQnr, splitAmountForDisplay } from '../src/lib/units';
import { PHASES, progressFraction } from '../src/screens/sendPhases';

describe('the balance', () => {
  it('dims padding and nothing else', () => {
    expect(splitAmountForDisplay('6.92')).toEqual({ significant: '6.92', pad: '' });
    expect(splitAmountForDisplay('10.370000000')).toEqual({
      significant: '10.37',
      pad: '0000000',
    });
    expect(splitAmountForDisplay('6.00')).toEqual({ significant: '6', pad: '.00' });
    expect(splitAmountForDisplay('12')).toEqual({ significant: '12', pad: '' });
  });

  it('leaves every quanta balance bright, because none of it is padding', () => {
    for (const quanta of [692n, 1n, 100n, 1000n, 123_456n]) {
      const text = formatQuantaAsQnr(quanta).replace(' QNR', '');
      const split = splitAmountForDisplay(text);
      if (text.endsWith('.00')) {
        // A whole number of QNR: the ".00" is the only padding there is.
        expect(split.pad).toBe('.00');
      } else {
        expect(split.pad).toBe('');
        expect(split.significant).toBe(text);
      }
    }
  });
});

describe('the sending bar', () => {
  it('gives proving the share of the wait it actually takes', () => {
    const prove = PHASES.find((phase) => phase.key === 'prove');
    const total = PHASES.reduce((sum, phase) => sum + phase.weight, 0);
    expect((prove?.weight ?? 0) / total).toBeGreaterThan(0.5);
  });

  it('is under half way when proving starts, where counting phases put it at 75%', () => {
    const proveIndex = PHASES.findIndex((phase) => phase.key === 'prove');
    expect(progressFraction(proveIndex, 0, 20_000)).toBeLessThan(0.5);
    // What the equal-weight bar said at the same moment.
    expect((proveIndex + 1) / PHASES.length).toBeCloseTo(0.75, 2);
  });

  it('keeps moving while the worker is busy, and never claims the phase is done', () => {
    const proveIndex = PHASES.findIndex((phase) => phase.key === 'prove');
    const early = progressFraction(proveIndex, 2000, 20_000);
    const late = progressFraction(proveIndex, 18_000, 20_000);
    expect(late).toBeGreaterThan(early);
    expect(late).toBeLessThan(progressFraction(proveIndex + 1, 0, 20_000));
  });

  it('does not run past the end when a payment takes longer than expected', () => {
    const proveIndex = PHASES.findIndex((phase) => phase.key === 'prove');
    expect(progressFraction(proveIndex, 600_000, 20_000)).toBeLessThanOrEqual(1);
    expect(progressFraction(PHASES.length, 0, 20_000)).toBe(1);
  });

  it('starts at nothing before the first phase reports', () => {
    expect(progressFraction(-1, 0, 20_000)).toBe(0);
  });
});
