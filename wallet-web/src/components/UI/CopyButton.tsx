import { Check, Copy } from 'lucide-react';
import { useEffect, useState, type ReactNode } from 'react';

import { Button } from './Button';

/**
 * Copy, and say whether it happened.
 *
 * A page is not always allowed to write to the clipboard, and a button that
 * says "Copied" when nothing was copied is worse than one that says nothing:
 * the value is selectable either way, which is the fallback. So the label
 * follows what the promise actually did.
 */
export function CopyButton({
  value,
  label = 'Copy',
  testId,
}: {
  value: string;
  label?: string;
  testId?: string;
}): ReactNode {
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!copied) {
      return;
    }
    const timer = setTimeout(() => {
      setCopied(false);
    }, 2000);
    return () => {
      clearTimeout(timer);
    };
  }, [copied]);

  return (
    <Button
      data-testid={testId}
      onClick={() => {
        navigator.clipboard.writeText(value).then(
          () => {
            setCopied(true);
          },
          () => {
            setCopied(false);
          },
        );
      }}
    >
      {copied ? <Check className="size-3.5" aria-hidden /> : <Copy className="size-3.5" aria-hidden />}
      {copied ? 'Copied' : label}
    </Button>
  );
}
