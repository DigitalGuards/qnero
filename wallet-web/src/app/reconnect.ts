/**
 * How long to wait before trying a dead endpoint again.
 *
 * Short at first, because the common failure is a phone changing networks or a
 * tunnel coming up and the answer arrives within seconds. Then long, because
 * an endpoint that has refused three times is down rather than busy, and a
 * wallet hammering it every five seconds for the life of the tab is a wallet
 * that has mistaken a schedule for a fix.
 *
 * Its own module so the schedule can be asserted without a browser and without
 * a socket: what a retry loop gets wrong is the arithmetic, and the arithmetic
 * is the whole of it.
 */

/** The wait after the first, second and third failure, in milliseconds. */
export const RECONNECT_SCHEDULE_MS = [5_000, 15_000, 60_000] as const;

/** How many failures in a row before the reader is pointed at Settings. */
export const RECONNECT_ATTEMPTS_BEFORE_SETTINGS = 3;

/**
 * The wait after `attempts` consecutive failures, in milliseconds.
 *
 * `attempts` counts the failure that has just happened, so the first failure
 * is 1 and waits the first entry. Past the schedule it holds at the last one.
 */
export function reconnectDelayMs(attempts: number): number {
  const index = Math.min(Math.max(attempts, 1), RECONNECT_SCHEDULE_MS.length) - 1;
  return RECONNECT_SCHEDULE_MS[index] ?? 60_000;
}

/**
 * The countdown as whole seconds, never below zero and never above the wait.
 *
 * Rounded up, so a reader is never told "0 s" over a connection that has not
 * been tried yet: the last second of a wait reads as one second.
 */
export function secondsUntil(retryAt: number, now: number): number {
  return Math.max(0, Math.ceil((retryAt - now) / 1000));
}
