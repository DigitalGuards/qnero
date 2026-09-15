import { describe, expect, it } from 'vitest';

import {
  decodeCoinbase,
  decodeDifficultyAdjustment,
  decodeFailures,
  decodeLeafInsertions,
  decodeSettlements,
  decodeShieldEntries,
  successfulExtrinsics,
  type EventRecord,
} from '../src/lib/events';
import { POOL_STEP_PLANCK, formatQnr } from '../src/lib/units';
import settlementFixture from './fixtures/events-settlement.json' with { type: 'json' };
import shieldFixture from './fixtures/events-shield.json' with { type: 'json' };

const shield = shieldFixture.records as unknown as EventRecord[];
const settlement = settlementFixture.records as unknown as EventRecord[];

describe('shield entries', () => {
  it('reads the payer, the amount and the leaf together', () => {
    const entries = decodeShieldEntries(shield);
    expect(entries).toHaveLength(1);
    const entry = entries[0];
    expect(entry?.who).toBe('qzk1Nxai3dZD9Cn5kwGcgL6mKxsfxwqdis7kDQJ52aJS2vSn7');
    expect(entry?.valuePlanck).toBe(10_000_000_000_000n);
    expect(entry?.leafIndex).toBe(7);
    expect(entry?.entryIndex).toBe(0);
    expect(entry?.commitment).toBe(
      '0x58d2c08bceec2672da4eb08d943c5ff9f018019d75da21a4f3cf68b764d27969',
    );
  });

  it('measures the ciphertext the reference wallet pads to', () => {
    expect(decodeShieldEntries(shield)[0]?.ciphertextBytes).toBe(1792);
  });

  it('is the only place a value and an account meet, so the amount is exact', () => {
    const entry = decodeShieldEntries(shield)[0];
    expect(formatQnr(entry?.valuePlanck ?? 0n)).toBe('10.00 QNR');
    expect((entry?.valuePlanck ?? 0n) / POOL_STEP_PLANCK).toBe(1000n);
  });

  it('finds none in a block that settled instead', () => {
    expect(decodeShieldEntries(settlement)).toHaveLength(0);
  });
});

describe('settlements', () => {
  it('groups a block’s slots under the extrinsic that carried them', () => {
    const settlements = decodeSettlements(settlement);
    expect(settlements).toHaveLength(1);
    expect(settlements[0]?.extrinsicIndex).toBe(2);
    expect(settlements[0]?.segments).toBe(1);
    expect(settlements[0]?.declaredSlots).toBe(1);
    expect(settlements[0]?.slots).toHaveLength(1);
  });

  it('reads both nullifiers and both outputs of a slot', () => {
    const slot = decodeSettlements(settlement)[0]?.slots[0];
    expect(slot?.nullifiers).toEqual([
      '0xb3f6f23467e093e7d3fa114592a2f68be07dcf12b8e4c534cbc5db955e56ff8a',
      '0x5aaea98866b4d06ed82c5276b526a98a0350694ae3e07226326068af60580989',
    ]);
    expect(slot?.outputs.map((output) => output.leafIndex)).toEqual([10, 11]);
    expect(slot?.outputs.map((output) => output.commitment)).toEqual([
      '0xfb9b40e7d5cdabacb075993cc4844473a3ddf161f4d7a79d4704e3e80241d51d',
      '0xd6efa3530bf81fcc71cdbfcf956a06f7224704d770bb3f5b6e7a5f8e25b19ec1',
    ]);
    expect(slot?.outputs.map((output) => output.ciphertextBytes)).toEqual([1792, 1792]);
  });

  it('reads the fee in planck and the author’s share beside it', () => {
    const first = decodeSettlements(settlement)[0];
    expect(first?.feePlanck).toBe(80_000_000_000n);
    expect((first?.feePlanck ?? 0n) / POOL_STEP_PLANCK).toBe(8n);
    expect(first?.authorFeePlanck).toBe(40_000_000_000n);
  });

  it('reports none for a block that only shielded', () => {
    expect(decodeSettlements(shield)).toHaveLength(0);
  });
});

describe('coinbase', () => {
  it('reads the minted note and the emission behind it', () => {
    const coinbase = decodeCoinbase(settlement);
    expect(coinbase?.blockNumber).toBe(10);
    expect(coinbase?.leafIndex).toBe(12);
    expect(coinbase?.valuePlanck).toBe(450_000_000_000n);
    expect(coinbase?.creditedPlanck).toBe(410_000_000_000n);
    expect(coinbase?.hasCiphertext).toBe(false);
    expect(coinbase?.inner).toBe(
      '0xeb0262dbedfd41ea4406347fadfee3f454472303213434c876f2e5b4b2c5072c',
    );
  });

  it('folds this block’s settled-fee share into the note', () => {
    const coinbase = decodeCoinbase(settlement);
    expect(coinbase?.authorFeePlanck).toBe(40_000_000_000n);
    expect((coinbase?.creditedPlanck ?? 0n) + (coinbase?.authorFeePlanck ?? 0n)).toBe(
      coinbase?.valuePlanck,
    );
  });

  it('mints with no settled fee when nothing settled', () => {
    const coinbase = decodeCoinbase(shield);
    expect(coinbase?.valuePlanck).toBe(420_000_000_000n);
    expect(coinbase?.authorFeePlanck).toBe(0n);
    expect(coinbase?.creditedPlanck).toBe(420_000_000_000n);
  });

  it('finds none in a block with no CoinbaseMinted event', () => {
    expect(decodeCoinbase(shield.filter((record) => record.method !== 'CoinbaseMinted'))).toBeNull();
  });
});

describe('the rest of a block', () => {
  it('enumerates every leaf the block appended', () => {
    expect(decodeLeafInsertions(settlement)).toEqual([10, 11, 12]);
    expect(decodeLeafInsertions(shield)).toEqual([7, 8]);
  });

  it('reads a retarget as two U512 values and the observed time', () => {
    const adjustment = decodeDifficultyAdjustment(settlement);
    expect(adjustment?.oldDifficulty).toBe(136n);
    expect(adjustment?.newDifficulty).toBe(136n);
    expect(adjustment?.observedBlockTimeMs).toBe(14794);
  });

  it('marks a call the filter refused', () => {
    const failures = decodeFailures([
      {
        phase: { kind: 'applyExtrinsic', index: 3 },
        section: 'system',
        method: 'ExtrinsicFailed',
        fields: { dispatch_error: 'CallFiltered', dispatch_info: {} },
      },
      {
        phase: { kind: 'applyExtrinsic', index: 4 },
        section: 'system',
        method: 'ExtrinsicFailed',
        fields: { dispatch_error: { module: { index: 24, error: '0x02000000' } }, dispatch_info: {} },
      },
    ]);
    expect(failures[0]?.filtered).toBe(true);
    expect(failures[0]?.extrinsicIndex).toBe(3);
    expect(failures[1]?.filtered).toBe(false);
    expect(failures[1]?.kind).toBe('module');
  });

  it('lists the extrinsics that succeeded', () => {
    expect([...successfulExtrinsics(settlement)]).toEqual([0, 1, 2]);
  });

  it('says which field moved when a layout changes under it', () => {
    const broken = settlement.map((record) =>
      record.method === 'BatchSettled'
        ? { ...record, fields: { segments: 1, slot_count: 1, fee: 1 } }
        : record,
    );
    expect(() => decodeSettlements(broken)).toThrow(/has no field slots/);
  });
});
