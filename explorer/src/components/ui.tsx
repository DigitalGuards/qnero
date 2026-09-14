import type { ReactNode } from 'react';

import { shortHash } from '../lib/hex';

/**
 * A panel.
 *
 * `prose` caps the panel itself at a reading measure. The measure belongs on
 * the container: a `ch` cap on the paragraph resolves against the paragraph's
 * own font size, so an 11px note inside a wide panel would stop at half the
 * box and read as a broken grid. A panel holding a table or the field grid
 * keeps the full width.
 */
export function Panel({
  title,
  prose = false,
  children,
}: {
  title?: string;
  prose?: boolean;
  children: ReactNode;
}): ReactNode {
  return (
    <section className={prose ? 'panel panel--prose' : 'panel'} data-panel={title}>
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

/**
 * A panel the node kept no state for.
 *
 * The absence sentence this replaces ("no coinbase note", "no settlement",
 * "settled no slot") is a claim about what the chain published at that block.
 * Over a read that failed it is a false one, and it is read by someone checking
 * whether something happened there. Every page that reads events shares this,
 * because a settlement below a node's state window is the same unread block
 * from the block page and from the settlement page.
 */
export function NotRead({ what, error }: { what: string; error: string }): ReactNode {
  return (
    <Empty>
      <span className="dim" title={error}>
        State not kept at this block, so {what} could not be read. This is not an absence.
      </span>
    </Empty>
  );
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
