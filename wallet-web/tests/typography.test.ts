/**
 * The type scale, and the merge that was deleting it.
 *
 * `styles/tokens.css` calls the 13/12/11/10 px scale the thing the MyMonero
 * carry-over is for, and the app declares it with `text-body`, `text-ui`,
 * `text-meta` and `text-label`. None of those reached the DOM in six
 * components: `tailwind-merge`'s stock configuration has no name for them, so
 * it filed each one under text colour and dropped it whenever a colour class
 * came later in the same `cn()` call. A panel title declared at 10 px rendered
 * at 13 px, three pixels from the field labels under it that were declared in
 * the same style and reached the page through plain CSS.
 *
 * Nothing here renders a browser, because the failure is not a rendering one:
 * the class was already gone from the attribute. These are the exact call
 * sites that lost their size, asserted at the level the loss happened at.
 *
 * The second half is the collision that made the first half look right. A
 * colour token and a size token cannot share a name, because `text-<name>` is
 * one class and one namespace wins it. `--color-body` won `text-body`, so
 * every filled button's label took the page ground as its colour and looked
 * correct only for as long as that value stayed near black.
 */

import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { cn } from '../src/utils/cn';

/** The size utilities this app declares, all from `styles/app.css`. */
const SIZES = ['text-display', 'text-body', 'text-ui', 'text-meta', 'text-label'];

describe('the type scale survives the merge', () => {
  for (const size of SIZES) {
    it(`keeps ${size} beside a colour`, () => {
      expect(cn(size, 'text-ink')).toContain(size);
      expect(cn(size, 'text-ink')).toContain('text-ink');
      expect(cn('text-muted', size)).toContain(size);
    });
  }

  it('still lets one size override another', () => {
    expect(cn('text-meta', 'text-body')).toBe('text-body');
    expect(cn('text-label', 'text-display')).toBe('text-display');
  });

  it('still lets one colour override another', () => {
    expect(cn('text-ink', 'text-muted')).toBe('text-muted');
  });

  /**
   * The six call sites the review measured in Chromium, each with the size it
   * declares and the colour that was eating it.
   */
  const CALL_SITES: Record<string, { classes: string[]; size: string }> = {
    'the panel title': {
      classes: ['mb-3 text-label uppercase tracking-label text-muted'],
      size: 'text-label',
    },
    'a notice': {
      classes: ['flex gap-2 rounded-panel border p-2 text-meta', 'border-notice-edge bg-notice-bg text-notice'],
      size: 'text-meta',
    },
    'an address block': {
      classes: ['border p-2 text-meta leading-4', 'border-edge bg-field text-ink'],
      size: 'text-meta',
    },
    "a note's state pill": {
      classes: ['inline-block rounded-control border px-1.5 py-px text-label uppercase tracking-label', 'border-edge text-muted'],
      size: 'text-label',
    },
    'the action button': {
      classes: ['bg-accent-fill text-on-accent text-body font-semibold hover:bg-accent-hover'],
      size: 'text-body',
    },
    'a tab-bar link': {
      classes: [
        'flex h-14 flex-col items-center justify-center gap-1 text-label uppercase',
        'tracking-label transition-colors',
        'text-muted hover:text-ink',
      ],
      size: 'text-label',
    },
  };

  for (const [what, site] of Object.entries(CALL_SITES)) {
    it(`${what} still declares ${site.size}`, () => {
      expect(cn(...site.classes).split(' ')).toContain(site.size);
    });
  }

  it('keeps the action button its own foreground colour', () => {
    const classes = cn('bg-accent-fill text-on-accent text-body font-semibold').split(' ');
    expect(classes).toContain('text-on-accent');
    expect(classes).toContain('text-body');
  });
});

describe('the theme namespaces do not collide', () => {
  const css = readFileSync(join(import.meta.dirname, '..', 'src', 'styles', 'app.css'), 'utf8');

  function namesOf(prefix: string): Set<string> {
    const names = new Set<string>();
    const pattern = new RegExp(`^\\s*--${prefix}-([a-z0-9-]+)\\s*:`, 'gm');
    for (const match of css.matchAll(pattern)) {
      const name = match[1];
      // `--text-body--line-height` is the size's own line height rather than a
      // second size.
      if (name !== undefined && !name.includes('--')) {
        names.add(name);
      }
    }
    return names;
  }

  it('gives no colour token the name of a size token', () => {
    const colours = namesOf('color');
    const sizes = namesOf('text');
    expect(sizes.size).toBeGreaterThan(0);
    const shared = [...sizes].filter((name) => colours.has(name));
    expect(shared, `these names generate one class from two namespaces: ${shared.join(', ')}`).toEqual([]);
  });
});
