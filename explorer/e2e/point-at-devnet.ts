/**
 * Point the built directory at the dev chain this suite starts.
 *
 * `public/config.json` names the public testnet, because that file is what a
 * built directory carries and a build served to readers has to name the chain
 * it is actually on. The suite serves the same build against a `--dev --tmp`
 * node on loopback, so it rewrites the copy in `dist/` after the build and
 * before the preview server comes up. Nothing in `public/` is touched.
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { EXPLORER_DIR, RPC_PORT } from './devnet';

const path = join(EXPLORER_DIR, 'dist', 'config.json');
const config = JSON.parse(readFileSync(path, 'utf8')) as Record<string, unknown>;
config['rpcEndpoint'] = `ws://127.0.0.1:${String(RPC_PORT)}`;
config['chainName'] = 'Qnero devnet';
writeFileSync(path, `${JSON.stringify(config, null, 2)}\n`);
console.log(`dist/config.json points at ws://127.0.0.1:${String(RPC_PORT)}`);
