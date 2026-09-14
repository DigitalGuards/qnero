import { startDevnet } from './devnet';

export default async function globalSetup(): Promise<void> {
  const facts = await startDevnet();
  console.log(
    `devnet ready: shield in block ${facts.shieldHeight}, settlement in block ${facts.settlementHeight}`,
  );
}
