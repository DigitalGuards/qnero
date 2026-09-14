import { stopDevnet } from './devnet';

export default async function globalTeardown(): Promise<void> {
  await stopDevnet();
  console.log('devnet stopped and the RPC port is free');
}
