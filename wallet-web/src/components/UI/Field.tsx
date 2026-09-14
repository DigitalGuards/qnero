import * as LabelPrimitive from '@radix-ui/react-label';
import type { InputHTMLAttributes, ReactElement, ReactNode, TextareaHTMLAttributes } from 'react';
import { Children, cloneElement, isValidElement, useId } from 'react';

import { cn } from '../../utils/cn';

/**
 * The label-over-value row every form in MyMonero is built from.
 *
 * The label is a real `<label>` through Radix's primitive, tied to the control
 * by id, so clicking it focuses the control and a screen reader reads the two
 * together. The hint under it is where a wallet says the thing a field cannot:
 * how many characters a seed still needs, how much one payment can reach, what
 * a memo is padded to.
 */
export function Field({
  label,
  note,
  hint,
  error,
  htmlFor,
  children,
}: {
  label: string;
  note?: string;
  hint?: ReactNode;
  error?: string;
  htmlFor: string;
  children: ReactNode;
}): ReactNode {
  const errorId = `${htmlFor}-error`;
  /*
   * The control carries the failure as well as the sentence under it.
   *
   * A field whose value was refused was drawn in the accent, which is the
   * colour this palette reserves for the one action a screen is for: the
   * focused address field holding an invalid address looked like the thing to
   * do next. Unfocused it looked like every other field. And a reader who
   * moved back into the input after the message was announced heard no invalid
   * state and no description, because neither attribute was set.
   *
   * `aria-invalid` is also what `.mm-input[aria-invalid='true']` keys on in
   * `styles/app.css`, and that rule wins over the focus border, so an errored
   * field is red whether or not it has focus.
   */
  const marked = Children.map(children, (child) =>
    isValidElement(child)
      ? cloneElement(child as ReactElement<Record<string, unknown>>, {
          'aria-invalid': error === undefined ? undefined : true,
          'aria-describedby': error === undefined ? undefined : errorId,
        })
      : child,
  );
  return (
    <div className="mb-3">
      <LabelPrimitive.Root className="mm-label flex justify-between gap-2" htmlFor={htmlFor}>
        <span>{label}</span>
        {note !== undefined && <span className="normal-case text-muted">{note}</span>}
      </LabelPrimitive.Root>
      {marked}
      {error !== undefined ? (
        // Announced, because a field failure is the one thing on a form that
        // happens after the reader has stopped looking at it. This is where
        // the unlock screen's wrong-passphrase message lands too, so it is
        // the one treatment for the one event.
        <p className="mt-1 text-meta text-destructive" id={errorId} role="alert">
          {error}
        </p>
      ) : (
        hint !== undefined && <p className="mt-1 text-meta text-muted">{hint}</p>
      )}
    </div>
  );
}

export function Input({
  className,
  ...props
}: InputHTMLAttributes<HTMLInputElement>): ReactNode {
  return <input className={cn('mm-input', className)} {...props} />;
}

export function Textarea({
  className,
  ...props
}: TextareaHTMLAttributes<HTMLTextAreaElement>): ReactNode {
  return <textarea className={cn('mm-input resize-y', className)} {...props} />;
}

/** A field id that is stable across renders, for the label to point at. */
export function useFieldId(prefix: string): string {
  return `${prefix}-${useId()}`;
}
