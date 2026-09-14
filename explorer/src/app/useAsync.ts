import { useEffect, useState } from 'react';

export type AsyncState<T> =
  | { status: 'loading' }
  | { status: 'ready'; value: T }
  | { status: 'error'; error: string };

export function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/**
 * Run one async read and keep its outcome under a key.
 *
 * The key is what the read depends on, written out by the caller. An answer is
 * shown only while the key that produced it is still the current one, so a
 * fast click through blocks can never leave an older block's answer on the
 * page, and a changed key reads as loading with no state written during
 * render.
 *
 * The read is handed a liveness check. Dropping a result is enough for a
 * single round trip; a read that pages, like the nullifier count, has to be
 * able to stop paging, or an abandoned walk keeps issuing requests nobody will
 * ever look at. A read that does not care takes no argument.
 */
export function useAsync<T>(
  key: string | null,
  run: ((live: () => boolean) => Promise<T>) | null,
): AsyncState<T> {
  const [entry, setEntry] = useState<{ key: string; state: AsyncState<T> } | null>(null);

  useEffect(() => {
    if (key === null || run === null) {
      return;
    }
    let live = true;
    run(() => live).then(
      (value) => {
        if (live) {
          setEntry({ key, state: { status: 'ready', value } });
        }
      },
      (error: unknown) => {
        if (live) {
          setEntry({ key, state: { status: 'error', error: messageOf(error) } });
        }
      },
    );
    return () => {
      live = false;
    };
    // The key is the whole dependency: `run` is a fresh closure every render.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);

  if (key === null || entry === null || entry.key !== key) {
    return { status: 'loading' };
  }
  return entry.state;
}
