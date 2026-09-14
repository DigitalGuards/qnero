import type { ReactNode } from 'react';

import { shortHash } from '../lib/hex';

export function Panel({
  title,
  children,
}: {
  title?: string;
  children: ReactNode;
}): ReactNode {
  return (
    <section className="panel" data-panel={title}>
      {title === undefined ? null : <h2 className="panel__title">{title}</h2>}
      {children}
    </section>
  );
}

export function Fields({ children }: { children: ReactNode }): ReactNode {
  return <div className="fields">{children}</div>;
}

export function Field({
  label,
  value,
  note,
  wide = false,
  mono = false,
}: {
  label: string;
  value: ReactNode;
  note?: ReactNode;
  wide?: boolean;
  mono?: boolean;
}): ReactNode {
  return (
    <div className={wide ? 'field field--wide' : 'field'} data-field={label}>
      <span className="field__label">{label}</span>
      <div className={mono ? 'field__value mono' : 'field__value'}>{value}</div>
      {note === undefined ? null : <span className="field__note">{note}</span>}
    </div>
  );
}

export function Notice({ children }: { children: ReactNode }): ReactNode {
  return <div className="notice">{children}</div>;
}

export function ErrorBox({ children }: { children: ReactNode }): ReactNode {
  return (
    <div className="error" role="alert">
      {children}
    </div>
  );
}

export function Empty({ children }: { children: ReactNode }): ReactNode {
  return <div className="empty">{children}</div>;
}

export function Loading({ what }: { what: string }): ReactNode {
  return (
    <p className="loading" role="status">
      Reading {what}
    </p>
  );
}

/** A hash, shortened for the eye with the whole value one hover or one copy away. */
export function Hash({
  value,
  href,
  full = false,
}: {
  value: string;
  href?: string;
  full?: boolean;
}): ReactNode {
  const text = full ? value : shortHash(value);
  if (href === undefined) {
    return (
      <span className="mono" title={value}>
        {text}
      </span>
    );
  }
  return (
    <a className="mono" href={href} title={value}>
      {text}
    </a>
  );
}
