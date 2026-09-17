# Qnero brand

The palette, the two typefaces and the mark, in one place, for qnero.io,
Qloak, silQ Road and the faucet.

```
brand/
  tokens.css     every colour, both themes, plus font stacks and the radius
  fonts.css      the @font-face block
  fonts/         Archivo variable + IBM Plex Mono 400/500/600, latin subsets
  favicon.svg    the mark on its tile, for a browser tab
  mark.svg       the mark alone, for an open-graph card or a document
```

Nothing edits the copies. Change a value here, then:

```sh
node scripts/sync-brand.mjs        # fan out to the four apps
node scripts/check-contrast.mjs    # every pair still clears its bar
```

`node scripts/sync-brand.mjs --check` fails when a copy has drifted. Before
this existed the same palette was maintained by hand in four stylesheets, and
they had already come apart.

## The palette

Monero orange on a warm neutral ramp. One accent, and it appears on exactly
one thing per view: the action that view is for.

| | value | role |
|---|---|---|
| Monero orange | `#FF6600` | the accent, and the mark |
| Ember ink | `#B84300` | orange as *text* on a light ground, where `#FF6600` measures 2.9:1 and fails |
| Graphite | `#141312` | the ground |
| Coal | `#1E1C1A` | panels and fields |
| Seam | `#2E2B28` | rules and hairlines |
| Ash | `#A8A29A` | labels, table headers, provenance notes |
| Bone | `#F4F2F0` | body text on dark, the ground on light |
| Monero grey | `#4C4C4C` | reference value from the canvas; control edges use `--border-strong`, which clears 3:1 |

Two roles that look like one. `--accent` is ink on the page's own ground and
must clear 4.5:1, so it darkens to Ember ink in light. `--accent-fill` is a
ground of its own and owes contrast only to the label on it, so it stays
`#FF6600` in both themes: the primary button is the same orange in daylight
and at night, which is most of what makes the four apps read as one project.

A notice is deliberately unsaturated. A yellow warning beside an orange action
leaves about 29 degrees between "do this" and "be careful", and the two read as
one warm block. The warm hue belongs to the accent alone; a notice is a strong
border and the secondary ink, with an icon carrying the alarm.

## The type

**Archivo** (OFL 1.1) for everything but data, as the variable face, because
the brand's display type is drawn on the width axis: 125% for display, 110%
for headings, 100% for body. One file covers every weight and width, which is
smaller than the three static cuts it replaces.

**IBM Plex Mono** (OFL 1.1) at 400/500/600 for identifiers, hashes, endpoints
and amounts.

Both are served from Qnero's own origin. Every app here states that it makes
no third-party request, and a privacy coin whose front page hands a font CDN
each reader's IP address has broken that promise before the reader has read a
word. Latin subsets only: 132 KB for all four files, and the OFL text travels
beside them in `fonts/`, as the licence requires of anyone redistributing them.

## The mark

Four squares: a 4-ary Poseidon node, three of them Bone and the fourth orange
and displaced — one leaf lit, stepping out of the tree. It is the commitment
tree the chain actually uses, and there is no letterform in it, so it reads at
16 px where a thin-stroked glyph would not.

Qloak and silQ Road inline the mark as a `data:` URI rather than linking
`favicon.svg`, so it costs no request and needs nothing their content policies
do not already admit. Those two copies are checked by each app's own tests.

## Accessibility

`scripts/check-contrast.mjs` parses `tokens.css` and measures every role
against the surface it lands on, in the dark block and both light blocks: 4.5:1
for anything carrying prose (WCAG 1.4.3), 3:1 for a control's edge (1.4.11).
The ratios quoted in `tokens.css` are that script's output, not an estimate.
It also holds the accent/notice hue separation at 60 degrees, matching
`wallet-web/tests/policy.test.ts`.

## Provenance

The surface ramp and the two-part elevation recipe — a half-pixel inset
highlight over a one-pixel dark shadow — descend from MyMonero's stylesheet,
BSD-3-Clause. Each app's `NOTICE` carries the attribution. The palette itself
is Qnero's own.
