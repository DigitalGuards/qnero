import { QRCodeSVG } from 'qrcode.react';
import type { ReactNode } from 'react';

/**
 * A QR code.
 *
 * The address is the hard case and it decides the encoding. A Qnero address is
 * bech32m carrying an ML-KEM-1024 encapsulation key, so it is about 2600
 * characters: near QR byte mode's 2953-character ceiling and well inside
 * alphanumeric mode's 4296. QR's alphanumeric charset is uppercase only, and
 * bech32m is defined to be case insensitive with an all-uppercase form, so the
 * code carries the uppercase spelling and the page shows the lowercase one. A
 * scanner hands back the uppercase string, which decodes to the same address.
 *
 * Drawn as an SVG rather than a canvas, so it stays sharp when a phone camera
 * is held up to a scaled browser window and so the e2e can see it in the DOM.
 * The quiet zone and the two fixed colours are the specification's: a code
 * drawn in theme colours is a code some scanners will not read.
 *
 * # Why it grows
 *
 * An address needs a 141-module symbol. Pinned at 264 px that is 1.85 CSS px
 * per module, about 0.49 mm on a 96 dpi screen, which is under the two pixels
 * per module a scanner wants and it was the same 264 px on a 1280 px window
 * where the panel offered 728. So the SVG fills its column up to 480 px, and
 * the error correction goes to level M now that there is room for it: the
 * version cost of the stronger level is small at this size against what it
 * buys a phone photographing a laptop at arm's length.
 */
export function Qr({
  value,
  caption,
  uppercase = false,
}: {
  value: string;
  caption?: string;
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
          level="M"
          marginSize={1}
          bgColor="#ffffff"
          fgColor="#000000"
          role="img"
          aria-label={caption ?? 'QR code'}
        />
      </div>
      {caption !== undefined && (
        <figcaption className="text-meta text-muted">{caption}</figcaption>
      )}
    </figure>
  );
}
