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
 */
export function Qr({
  value,
  caption,
  size = 264,
  uppercase = false,
}: {
  value: string;
  caption?: string;
  size?: number;
  uppercase?: boolean;
}): ReactNode {
  return (
    <figure className="m-0 flex flex-col items-start gap-2">
      <div className="rounded-panel bg-white p-2" data-testid="qr">
        <QRCodeSVG
          value={uppercase ? value.toUpperCase() : value}
          size={size}
          level="L"
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
