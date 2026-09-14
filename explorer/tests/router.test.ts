import { describe, expect, it } from 'vitest';

import { href, parseRoute } from '../src/app/router';

describe('routes', () => {
  it('reads the routes the site links to', () => {
    expect(parseRoute('#/')).toEqual({ name: 'home' });
    expect(parseRoute('')).toEqual({ name: 'home' });
    expect(parseRoute('#/blocks')).toEqual({ name: 'blocks', before: null });
    expect(parseRoute('#/block/0x00ff')).toEqual({ name: 'block', id: '0x00ff' });
    expect(parseRoute('#/settlement/0xabc?at=0xdef')).toEqual({
      name: 'settlement',
      hash: '0xabc',
      at: '0xdef',
    });
    expect(parseRoute('#/search?q=0x01')).toEqual({ name: 'search', query: '0x01' });
    expect(parseRoute('#/reveals')).toEqual({ name: 'reveals' });
    expect(parseRoute('#/nowhere')).toEqual({ name: 'notFound', path: '/nowhere' });
  });

  it('takes a block height only when it is one', () => {
    expect(parseRoute('#/blocks?before=1200')).toEqual({ name: 'blocks', before: 1200 });
    expect(parseRoute('#/blocks?before=0')).toEqual({ name: 'blocks', before: 0 });
    // A heading reading "from height NaN" and a pager doing arithmetic on it is
    // worse than a link that quietly means "newest".
    for (const raw of ['abc', '-5', '1e9', '12.5', '']) {
      expect(parseRoute(`#/blocks?before=${raw}`)).toEqual({ name: 'blocks', before: null });
    }
  });

  it('round-trips every route it builds a link for', () => {
    for (const route of [
      { name: 'home' },
      { name: 'blocks', before: null },
      { name: 'blocks', before: 40 },
      { name: 'block', id: '0x01' },
      { name: 'settlement', hash: '0x02', at: null },
      { name: 'settlement', hash: '0x02', at: '0x03' },
      { name: 'search', query: '0x04' },
      { name: 'reveals' },
    ] as const) {
      expect(parseRoute(href(route))).toEqual(route);
    }
  });
});
