import { QRCodeSVG } from 'qrcode.react';
import type { ReactNode } from 'react';

/**
 * A QR code.
 *
 * The address is the hard case and it decides the encoding. A Qnero address is
 * bech32m carrying an ML-KEM-1024 encapsulation key, so it is 2571 characters:
 * near QR byte mode's 2953-character ceiling and well inside alphanumeric
 * mode's 4296. QR's alphanumeric charset is uppercase only, and bech32m is
 * defined to be case insensitive with an all-uppercase form, so the code
 * carries the uppercase spelling and the page shows the lowercase one. A
 * scanner hands back the uppercase string, which decodes to the same address.
 *
 * Drawn as an SVG rather than a canvas, so it stays sharp when a phone camera
 * is held up to a scaled browser window and so the e2e can see it in the DOM.
 * The quiet zone and the two fixed colours are the specification's: a code
 * drawn in theme colours is a code some scanners will not read.
 *
 * # Why the level is L
 *
 * The key is 1568 uniformly random bytes, so the payload does not compress and
 * the symbol is version 35 territory whatever is done to it: at level M the
 * address needs a 141-module symbol, which is 1.85 CSS px per module even when
 * the SVG fills a 480 px column, under the two pixels per module a scanner
 * wants. Level L is the smallest module count this payload has, and at this
 * size it is the level that buys a reader something: stronger correction on a
 * symbol already too dense to scan is denser modules for nothing. The real fix
 * is a shorter address, which is a protocol change and is planned separately.
 * So the SVG fills its column up to 480 px at level L, and the screen leads
 * with the address text because that is what actually gets handed over.
 */
export function Qr({
  value,
  caption,
  alt,
  uppercase = false,
}: {
  value: string;
  /** The sentence under the code. */
  caption?: string;
  /** What the code is, for a reader who is not looking at it. */
  alt?: string;
  uppercase?: boolean;
}): ReactNode {
  return (
    <figure className="m-0 flex flex-col items-start gap-2">
      <div className="w-full max-w-[480px] rounded-panel bg-white p-2" data-testid="qr">
        <QRCodeSVG
          value={uppercase ? value.toUpperCase() : value}
          // The rendered size is the column's. `size` is the SVG's own
          // attribute and the class overrides it, so the viewBox is what
          // decides the geometry and the box decides the pixels.
          className="h-auto w-full"
          size={480}
          level="L"
          marginSize={1}
          bgColor="#ffffff"
          fgColor="#000000"
          role="img"
          aria-label={alt ?? caption ?? 'QR code'}
        />
      </div>
      {caption !== undefined && (
        <figcaption className="text-meta text-muted">{caption}</figcaption>
      )}
    </figure>
  );
}
