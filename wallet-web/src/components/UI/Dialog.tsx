import * as DialogPrimitive from '@radix-ui/react-dialog';
import { X } from 'lucide-react';
import type { ReactNode } from 'react';

import { cn } from '../../utils/cn';
import { Button } from './Button';

/**
 * The modal, on Radix's dialog primitive, styled to MyMonero's panel.
 *
 * Radix rather than a hand-rolled overlay for the reasons a modal is hard:
 * focus goes into it and comes back out to what opened it, the page behind is
 * inert to a screen reader, and Escape closes it. This wallet uses it for the
 * two questions that destroy something no other copy of exists, and it states
 * what is lost inside the dialog rather than in a toast that has already gone
 * by the time the button is pressed.
 *
 * Both of those dialogs get an explicit Cancel beside the destructive action,
 * because the way out of a question like this cannot be a 14 px muted X in a
 * corner. On the lock screen the path is two clicks from a mistyped passphrase
 * to a wipe that only a seed written down recovers from, so the second click
 * has something to land on that is not the red one.
 *
 * The two halves are the same width, which is MyMonero's own action box. They
 * were not: Cancel sat at its intrinsic 72 px beside a 215 px destructive
 * button, so on the one action in this wallet that destroys something the
 * dangerous target was three times the size of the way out.
 */
export const Dialog = DialogPrimitive.Root;
export const DialogTrigger = DialogPrimitive.Trigger;
export const DialogClose = DialogPrimitive.Close;

export function DialogContent({
  title,
  description,
  children,
  className,
}: {
  title: string;
  description?: ReactNode;
  children?: ReactNode;
  className?: string;
}): ReactNode {
  return (
    <DialogPrimitive.Portal>
      <DialogPrimitive.Overlay className="fixed inset-0 z-40 bg-black/60" />
      <DialogPrimitive.Content
        className={cn(
          'fixed left-1/2 top-1/2 z-50 w-[min(420px,calc(100vw-32px))] -translate-x-1/2 ' +
            '-translate-y-1/2 rounded-panel border border-edge bg-panel p-4 ' +
            'shadow-[var(--shadow-modal)]',
          className,
        )}
      >
        <DialogPrimitive.Title className="mb-2 text-body font-semibold text-ink">
          {title}
        </DialogPrimitive.Title>
        {description !== undefined && (
          <DialogPrimitive.Description asChild>
            <div className="mb-3 space-y-2 text-meta text-ink-2">{description}</div>
          </DialogPrimitive.Description>
        )}
        <div className="flex flex-wrap gap-2 [&>*]:flex-1">
          <DialogPrimitive.Close asChild>
            <Button data-testid="dialog-cancel">Cancel</Button>
          </DialogPrimitive.Close>
          {children}
        </div>
        <DialogPrimitive.Close asChild>
          <Button
            variant="quiet"
            size="small"
            aria-label="Close"
            className="absolute right-2 top-2 no-underline"
          >
            <X className="size-3.5" aria-hidden />
          </Button>
        </DialogPrimitive.Close>
      </DialogPrimitive.Content>
    </DialogPrimitive.Portal>
  );
}
