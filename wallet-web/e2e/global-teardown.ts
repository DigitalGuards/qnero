/**
 * Stop the dev chain, and do not return until its port is free.
 *
 * A node left running holds the port, and the next run refuses rather than
 * quietly reading a chain from the run before it.
 */

import { stopDevnet } from './devnet';

export default async function globalTeardown(): Promise<void> {
  await stopDevnet();
}
