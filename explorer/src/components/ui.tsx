import { useState, type ReactNode } from 'react';

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

/**
 * One labelled value.
 *
 * `display` is the balance treatment Qloak has and this site did not: every
 * value on the chain page, Best block and Pool value included, was 13 px,
 * identical to the prose beside it, so nothing on the page said "this is the
 * number". It belongs on the four or five figures a page is opened for and
 * nowhere else.
 */
export function Field({
  label,
  value,
  note,
  wide = false,
  mono = false,
  display = false,
}: {
  label: string;
  value: ReactNode;
  note?: ReactNode;
  wide?: boolean;
  mono?: boolean;
  display?: boolean;
}): ReactNode {
  const classes = ['field__value'];
  if (mono) {
    classes.push('mono');
  }
  if (display) {
    classes.push('field__value--display');
  }
  return (
    <div className={wide ? 'field field--wide' : 'field'} data-field={label}>
      <span className="field__label">{label}</span>
      <div className={classes.join(' ')}>{value}</div>
      {note === undefined ? null : <span className="field__note">{note}</span>}
    </div>
  );
}

/**
 * State a reader has to act on: a read that failed, a stale head, a claim
 * refused. It is the one colour on this site that means "attend to this", and
 * it was spent on essays: five pages carried a yellow box of reading matter,
 * one of them 408 px tall on a 667 px screen. Reading matter goes in prose or
 * behind a disclosure; this stays for state.
 */
export function Notice({ children }: { children: ReactNode }): ReactNode {
  return <div className="notice">{children}</div>;
}

/**
 * What a panel costs, in one line a reader can act on.
 *
 * `leaks` is the difference between a request that carries the reader's value
 * to the node and one that reads a range and names nothing. It is the fact the
 * consent gate exists for, so it is a tag beside the sentence rather than the
 * fourth paragraph of one.
 */
export function Leak({ leaks }: { leaks: boolean }): ReactNode {
  return (
    <span className={leaks ? 'tag tag--leak' : 'tag'}>
      {leaks ? 'sends the value' : 'sends no value'}
    </span>
  );
}

/** The reasoning behind a sentence, for the reader who wants it. */
export function Why({ summary, children }: { summary: string; children: ReactNode }): ReactNode {
  return (
    <details className="why">
      <summary>{summary}</summary>
      {children}
    </details>
  );
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

export interface SkeletonPanel {
  title: string;
  fields?: number;
  rows?: number;
}

/**
 * The shape of the page that is coming.
 *
 * A page whose figures are all read live used to paint one 11 px muted line
 * for the whole connect, under a wordmark whose third line read "no chain".
 * One line on 667 px of screen reads as a broken page rather than as progress.
 *
 * So the head and the panel frames render at once with their titles, and the
 * values are short muted rules until they are values. The movement that says
 * the page is working is the one 2 px bar under the header, not here. The
 * rules carry no information, so they are hidden from a reader who is being
 * read to; the masthead's status slot is what speaks.
 */
export function PageSkeleton({
  title,
  panels,
}: {
  title: string | null;
  panels: readonly SkeletonPanel[];
}): ReactNode {
  return (
    <>
      <header className="page__head">
        {title === null ? (
          <span className="skeleton skeleton--h1" aria-hidden="true" />
        ) : (
          <h1>{title}</h1>
        )}
      </header>
      {panels.map((panel) => (
        <section className="panel" key={panel.title}>
          <h2 className="panel__title">{panel.title}</h2>
          {panel.rows === undefined ? null : (
            <div aria-hidden="true">
              {Array.from({ length: panel.rows }, (_unused, index) => (
                <span className="skeleton skeleton--row" key={index} />
              ))}
            </div>
          )}
          {panel.fields === undefined ? null : (
            <div className="fields" aria-hidden="true">
              {Array.from({ length: panel.fields }, (_unused, index) => (
                <div className="field" key={index}>
                  <span className="skeleton skeleton--label" />
                  <span className="skeleton skeleton--value" />
                </div>
              ))}
            </div>
          )}
        </section>
      ))}
    </>
  );
}

/**
 * The whole value, for the reader who needs the whole value.
 *
 * A shortened hash is readable and a shortened hash cannot be pasted into
 * anything. A hover title answers a pointer and answers nothing on a phone,
 * which is where most of the hex on this site is read.
 */
export function Copy({ value }: { value: string }): ReactNode {
  const [state, setState] = useState<'idle' | 'done' | 'failed'>('idle');
  const label =
    state === 'done' ? 'Copied' : state === 'failed' ? 'Select it by hand' : 'Copy the whole value';
  return (
    <button
      type="button"
      className="copy"
      aria-label={label}
      title={label}
      onClick={() => {
        try {
          void navigator.clipboard.writeText(value).then(
            () => {
              setState('done');
            },
            () => {
              setState('failed');
            },
          );
        } catch {
          // No clipboard on this origin. The title says what to do instead.
          setState('failed');
        }
      }}
    >
      {state === 'done' ? 'copied' : 'copy'}
    </button>
  );
}

/** A hash, shortened for the eye with the whole value one press away. */
export function Hash({
  value,
  href,
  full = false,
  copy = false,
}: {
  value: string;
  href?: string;
  full?: boolean;
  copy?: boolean;
}): ReactNode {
  const text = full ? value : shortHash(value);
  const body =
    href === undefined ? (
      <span className="mono" title={value}>
        {text}
      </span>
    ) : (
      <a className="mono" href={href} title={value}>
        {text}
      </a>
    );
  if (!copy) {
    return body;
  }
  return (
    <span className="hashline">
      {body}
      <Copy value={value} />
    </span>
  );
}
