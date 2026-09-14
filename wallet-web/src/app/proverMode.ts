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
