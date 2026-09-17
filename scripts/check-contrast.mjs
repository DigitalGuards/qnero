/*
 * Measures brand/tokens.css and fails on a pair that does not clear its bar.
 *
 * The stylesheet header states ratios. This is what makes them true: it parses
 * the three token blocks (the bare `:root` dark palette, the light media-query
 * block and the `data-theme='light'` block), resolves `var()` indirection, and
 * checks every role against the surface it actually lands on, in both themes.
 *
 *   node scripts/check-contrast.mjs
 *
 * Bars, from WCAG 2.2:
 *   4.5:1  body text and any token that carries prose (1.4.3)
 *   3:1    a control's edge and non-text information (1.4.11)
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const css = readFileSync(resolve(here, '../brand/tokens.css'), 'utf8');

/** Strip comments, then read `--name: value;` pairs out of one block. */
function block(open) {
  const from = css.indexOf(open);
  if (from === -1) throw new Error(`no block: ${open}`);
  let depth = 0;
  let i = css.indexOf('{', from);
  const start = i;
  for (; i < css.length; i += 1) {
    if (css[i] === '{') depth += 1;
    else if (css[i] === '}') {
      depth -= 1;
      if (depth === 0) break;
    }
  }
  const body = css.slice(start + 1, i).replace(/\/\*[\s\S]*?\*\//g, '');
  const out = {};
  for (const [, k, v] of body.matchAll(/(--[a-z0-9-]+)\s*:\s*([^;]+);/g)) out[k] = v.trim();
  return out;
}

const dark = block(':root {');
const light = block(":root[data-theme='light'] {");
const lightMedia = block(":root:not([data-theme='dark']) {");

/** `var(--x)` resolves against its own theme, falling back to dark. */
function resolveToken(theme, name) {
  let v = theme[name] ?? dark[name];
  let guard = 0;
  while (v && v.startsWith('var(') && guard < 10) {
    const inner = v.slice(4, v.indexOf(')')).trim();
    v = theme[inner] ?? dark[inner];
    guard += 1;
  }
  return v;
}

function channel(c) {
  const s = c / 255;
  return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
}

function luminance(hex) {
  const h = hex.replace('#', '').trim();
  if (!/^[0-9a-f]{6}$/i.test(h)) throw new Error(`not a hex colour: ${hex}`);
  const [r, g, b] = [0, 2, 4].map((i) => parseInt(h.slice(i, i + 2), 16));
  return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b);
}

function contrast(a, b) {
  const [x, y] = [luminance(a), luminance(b)].sort((p, q) => q - p);
  return (x + 0.05) / (y + 0.05);
}

/** [ink, ground, bar, what it carries] */
const PAIRS = [
  ['--text-primary', '--bg-panel', 4.5, 'body text on a panel'],
  ['--text-primary', '--bg-body', 4.5, 'body text on the body'],
  ['--text-secondary', '--bg-panel', 4.5, 'secondary prose on a panel'],
  ['--text-secondary', '--bg-body', 4.5, 'secondary prose on the body'],
  ['--text-muted', '--bg-panel', 4.5, 'labels and table headers on a panel'],
  ['--text-muted', '--bg-body', 4.5, 'labels and table headers on the body'],
  ['--text-muted', '--bg-raised', 4.5, 'labels on a raised surface'],
  ['--accent', '--bg-panel', 4.5, 'link ink on a panel'],
  ['--accent', '--bg-body', 4.5, 'link ink on the body'],
  ['--accent-on-fill', '--accent-fill', 4.5, 'the primary action label'],
  ['--accent-on-fill', '--accent-fill-hover', 4.5, 'the primary action label, hovered'],
  ['--destructive', '--bg-panel', 4.5, 'destructive ink on a panel'],
  ['--destructive-on-fill', '--destructive-fill', 4.5, 'a destructive action label'],
  ['--positive', '--bg-panel', 4.5, 'positive ink on a panel'],
  ['--notice', '--bg-panel', 4.5, 'a notice on a panel'],
  ['--border-strong', '--bg-panel', 3, "a control's edge on a panel"],
  ['--border-strong', '--bg-body', 3, "a control's edge on the body"],
  ['--text-dim', '--bg-panel', 3, 'a placeholder or disabled control'],
];

/** Hue in degrees and HSL saturation, for the accent/notice separation. */
function hsl(hex) {
  const h = hex.replace('#', '');
  const [r, g, b] = [0, 2, 4].map((i) => parseInt(h.slice(i, i + 2), 16) / 255);
  const max = Math.max(r, g, b);
  const min = Math.min(r, g, b);
  const lightness = (max + min) / 2;
  const d = max - min;
  if (d === 0) return { hue: 0, saturation: 0, lightness };
  const saturation = d / (lightness > 0.5 ? 2 - max - min : max + min);
  let deg;
  if (max === r) deg = ((g - b) / d) % 6;
  else if (max === g) deg = (b - r) / d + 2;
  else deg = (r - g) / d + 4;
  return { hue: (((deg * 60) % 360) + 360) % 360, saturation, lightness };
}

let failed = 0;
const rows = [];
for (const [name, theme] of [
  ['dark', dark],
  ['light', light],
  ['light (media)', lightMedia],
]) {
  for (const [inkName, groundName, bar, what] of PAIRS) {
    const ink = resolveToken(theme, inkName);
    const ground = resolveToken(theme, groundName);
    if (!ink || !ground) throw new Error(`${name}: missing ${inkName} or ${groundName}`);
    if (ink === 'transparent' || ground === 'transparent') continue;
    const ratio = contrast(ink, ground);
    const ok = ratio >= bar;
    if (!ok) failed += 1;
    rows.push(
      `${ok ? 'ok  ' : 'FAIL'} ${name.padEnd(13)} ${ratio.toFixed(2).padStart(5)}:1 ` +
        `(needs ${bar}) ${inkName} on ${groundName} -- ${what}`,
    );
  }

  // The warm hue is the accent's alone: a saturated notice inside its band
  // reads as the same thing. Either the notice is unsaturated, which is what
  // it is here, or it sits a long way off the accent. The 0.12 threshold and
  // the 60 degree bar are `wallet-web/tests/policy.test.ts`'s, so the two
  // checks agree.
  const border = resolveToken(theme, '--notice-border');
  if (border === 'transparent') {
    rows.push(`ok   ${name.padEnd(13)}       -- notice has no border to collide`);
  } else {
    const accent = hsl(resolveToken(theme, '--accent-fill'));
    const notice = hsl(border);
    if (notice.saturation < 0.12) {
      rows.push(
        `ok   ${name.padEnd(13)}       -- notice is unsaturated ` +
          `(S ${notice.saturation.toFixed(3)}), no hue to collide`,
      );
    } else {
      const raw = Math.abs(accent.hue - notice.hue) % 360;
      const distance = raw > 180 ? 360 - raw : raw;
      const ok = distance >= 60;
      if (!ok) failed += 1;
      rows.push(
        `${ok ? 'ok  ' : 'FAIL'} ${name.padEnd(13)} ${distance.toFixed(0).padStart(5)}deg ` +
          `(needs 60) accent/notice hue separation`,
      );
    }
  }

  // The accent is the one thing carrying identity, so it stays saturated.
  const accentSat = hsl(resolveToken(theme, '--accent-fill')).saturation;
  const satOk = accentSat > 0.3;
  if (!satOk) failed += 1;
  rows.push(
    `${satOk ? 'ok  ' : 'FAIL'} ${name.padEnd(13)} ${accentSat.toFixed(2).padStart(5)}    ` +
      `(needs >0.30) accent saturation`,
  );
}

console.log(rows.join('\n'));
if (failed > 0) {
  console.error(`\n${failed} pair(s) below the bar.`);
  process.exit(1);
}
console.log(`\nAll ${rows.length} checks pass.`);
