/**
 * Start the dev chain once, before the browser is launched.
 *
 * Playwright's web server starts in parallel with this, and that is the order
 * to want: the build and the node's first blocks are the two slow things and
 * neither needs the other.
 */

import { startDevnet } from './devnet';

export default async function globalSetup(): Promise<void> {
  const facts = await startDevnet();
  console.log(
    `dev chain up: ${facts.rpc}, ${facts.shieldedQuanta} quanta shielded in block ${facts.shieldHeight}`,
  );
}
