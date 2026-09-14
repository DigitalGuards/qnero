import * as LabelPrimitive from '@radix-ui/react-label';
import type { InputHTMLAttributes, ReactNode, TextareaHTMLAttributes } from 'react';
import { useId } from 'react';

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
  return (
    <div className="mb-3">
      <LabelPrimitive.Root className="mm-label flex justify-between gap-2" htmlFor={htmlFor}>
        <span>{label}</span>
        {note !== undefined && <span className="normal-case text-dim">{note}</span>}
      </LabelPrimitive.Root>
      {children}
      {error !== undefined ? (
        <p className="mt-1 text-meta text-destructive">{error}</p>
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
