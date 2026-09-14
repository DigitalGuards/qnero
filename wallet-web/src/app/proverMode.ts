/**
 * Which prover module this page should load.
 *
 * The default is "the best one this context can run": the threaded module when
 * the origin is cross-origin isolated, and the single-threaded one otherwise.
 * `?prover=single` pins it to the single-threaded module on an isolated origin
 * too, which is how the two rows in `docs/BENCH.md` are measured on one
 * machine with one build, and how somebody reporting a threading bug can say
 * whether the single-threaded module has it as well.
 *
 * A cap of one is not a threaded module with one thread. A rayon pool of one
 * is the serial module with a worker's worth of overhead, so the worker takes
 * a cap of one as "do not load the threaded module at all".
 */

/** The cap on the threaded prover's pool. See `README.md` on why it is four. */
export const MAX_PROVER_THREADS = 4;

export function readThreadCap(search: string = globalThis.location.search): number {
  try {
    return new URLSearchParams(search).get('prover') === 'single' ? 1 : MAX_PROVER_THREADS;
  } catch {
    // No location, or a search string this runtime will not parse. The default
    // is the one that works everywhere.
    return MAX_PROVER_THREADS;
  }
}

/**
 * What the last payment on this machine actually cost, per module.
 *
 * `config.json` carries a published figure and it is a figure from one
 * workstation: the sending screen quoted "about 11 seconds" while its own
 * elapsed clock beside it read 14.3 s and climbing, which is the wallet's one
 * claim about how long a wait will be disagreeing with itself in front of the
 * person being asked to wait.
 *
 * So the published figure is the first payment's estimate and nothing more.
 * After that the screen quotes this machine. It is `localStorage` rather than
 * the store because it is a convenience per browser, it is worthless on
 * another machine, and a wallet that has been locked has no store to read.
 */
const MEASURED_KEY = 'qnero-wallet-prove-seconds';

function measuredKey(threads: number): string {
  return `${MEASURED_KEY}-${threads > 1 ? 'threaded' : 'single'}`;
}

export function readMeasuredProveSeconds(threads: number): number | null {
  try {
    const stored = localStorage.getItem(measuredKey(threads));
    if (stored === null) {
      return null;
    }
    const seconds = Number(stored);
    return Number.isFinite(seconds) && seconds > 0 ? seconds : null;
  } catch {
    return null;
  }
}

export function writeMeasuredProveSeconds(threads: number, millis: number): void {
  if (!Number.isFinite(millis) || millis <= 0) {
    return;
  }
  try {
    localStorage.setItem(measuredKey(threads), String(Math.round(millis / 1000)));
  } catch {
    // A private window, or site data blocked. The published figure is then
    // what every payment is quoted against, which is where this started.
  }
}
