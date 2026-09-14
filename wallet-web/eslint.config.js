import js from '@eslint/js';
import reactHooks from 'eslint-plugin-react-hooks';
import tseslint from 'typescript-eslint';

/**
 * The Merkle-proof fence.
 *
 * The node serves the same proof under two names, `zkTree_getMerkleProof` and
 * the `ZkTreeApi_get_merkle_proof` runtime call, and a client can reach either
 * through several spellings: `provider.send` with the method first
 * (`state_call`, `state_callAt`), `provider.send('archive_v1_call', [hash,
 * function, callParameters])` with the method second, and polkadot-js sugar
 * that hides the wire call entirely (`api.call.zkTreeApi.getMerkleProof`,
 * `api.rpc.zkTree.getMerkleProof`). Keying on one argument position let two of
 * those through, and the sugar is the shape this codebase already uses for the
 * QPoW constants, so it is the natural way to reintroduce the call.
 *
 * The four selectors below are keyed on the name wherever it is written rather
 * than on where it sits in a parameter list. `tests/lint-fence.test.ts` runs
 * every spelling through them.
 */
const MERKLE_PROOF_MESSAGE =
  'A Merkle proof call names one leaf to whoever runs the node. Read ZkTree::Leaves instead.';

export const merkleProofFence = [
  {
    // Either name the node answers to, at any argument position, so the
    // `archive_v1_call` layout [hash, function, callParameters] is covered
    // together with `state_call`'s [function, callParameters].
    selector: "Literal[value=/^(zkTree_getMerkleProof|ZkTreeApi_get_merkle_proof)$/i]",
    message: MERKLE_PROOF_MESSAGE,
  },
  {
    // Any raw send carrying a Merkle-proof name, whatever the parameter
    // layout and whatever the runtime API is called.
    selector: "CallExpression[callee.property.name='send'] Literal[value=/merkle_?proof/i]",
    message: MERKLE_PROOF_MESSAGE,
  },
  {
    // The polkadot-js runtime-call and RPC sugar: api.call.<api>.getMerkleProof,
    // api.rpc.zkTree.getMerkleProof, and the snake-case spelling of both.
    selector: "CallExpression[callee.type='MemberExpression'][callee.property.name=/merkle_?proof/i]",
    message: MERKLE_PROOF_MESSAGE,
  },
  {
    // The same sugar written with a computed key.
    selector: 'MemberExpression[computed=true][property.value=/merkle_?proof/i]',
    message: MERKLE_PROOF_MESSAGE,
  },
];

/**
 * The transport fence.
 *
 * `chain/api.ts` states that every read goes through `ChainContext.send` and
 * that `tests/privacy.test.ts` records the property there. That claim held
 * only as long as nobody wrote the next read against polkadot-js's typed API,
 * and one already had been: the head subscription went out over
 * `api.rpc.chain.subscribeNewHeads`, which the recording seam cannot see.
 *
 * The shapes that carry a name to a node are `api.rpc.*` (an RPC call or a
 * subscription), `api.query.*` (a storage read, and the one that would carry a
 * raw nullifier under `Blake2_128Concat`), `api.call.*` (a runtime API, which
 * is how a Merkle proof is reached) and `api.derive.*`. `api.tx` is not on the
 * list: reading `.callIndex` off a submittable builds nothing and opens no
 * socket, which is what `chain/submit.ts` does with it.
 *
 * `src/chain/api.ts` is exempt, because that is where the seam is built and
 * where `storage()` turns `api.query` into a key without asking anybody.
 */
const NODE_SEAM_MESSAGE =
  'Reach the node through ChainContext.send or ChainContext.subscribe. The typed API bypasses ' +
  'the seam tests/privacy.test.ts records, so a read written this way is invisible to it.';

export const nodeSeamFence = [
  {
    // `context.api.rpc`, `this.api.query`, and anything else that reads the
    // member off an object called `api`.
    selector:
      "MemberExpression[property.name=/^(rpc|query|call|derive)$/][object.property.name='api']",
    message: NODE_SEAM_MESSAGE,
  },
  {
    // The same four, off a bare `api`.
    selector: "MemberExpression[property.name=/^(rpc|query|call|derive)$/][object.name='api']",
    message: NODE_SEAM_MESSAGE,
  },
];

/**
 * The worker fence.
 *
 * `src/worker/protocol.ts` states the split the whole privacy argument rests
 * on: the worker holds the seed and never opens a socket, the page opens every
 * socket and holds no secret, so the side that could leak a secret into a
 * request has no way to make one. Only the page's half of that was checked.
 * `tests/privacy.test.ts` records the page's transport seam, the transport
 * fence above keys on `api.*`, and the end-to-end recorder patches
 * `WebSocket.prototype.send` through `addInitScript`, which Playwright
 * evaluates in page frames: a worker has its own realm with an unpatched
 * `WebSocket`, `fetch` and `XMLHttpRequest`. One line inside `src/worker/`
 * where the plaintext seed hex is in scope passed the lint, every unit test
 * and every end-to-end run with its allowlist assertion green.
 *
 * The worker's one legitimate network use is the same-origin `import(url)`
 * that loads the wasm module, which is a dynamic import rather than any of
 * these names, so the fence leaves it alone.
 */
const WORKER_NETWORK_MESSAGE =
  'The worker holds the seed and opens no socket. That split is what makes "the node learns ' +
  'nothing" checkable, and nothing outside it can see a request made from here.';

export const workerNetworkFence = [
  {
    // `new WebSocket(...)`, and the same for the other transports.
    selector:
      "NewExpression[callee.name=/^(WebSocket|XMLHttpRequest|EventSource|BroadcastChannel)$/]",
    message: WORKER_NETWORK_MESSAGE,
  },
  {
    // The name anywhere at all, so a `typeof` probe or an alias is caught too.
    // None of them has a legitimate use in this directory.
    selector: "Identifier[name=/^(WebSocket|XMLHttpRequest|EventSource|sendBeacon)$/]",
    message: WORKER_NETWORK_MESSAGE,
  },
  {
    // `fetch(...)` bare.
    selector: "CallExpression[callee.name='fetch']",
    message: WORKER_NETWORK_MESSAGE,
  },
  {
    // `self.fetch`, `globalThis.fetch`, and any other object's.
    selector: "MemberExpression[property.name='fetch']",
    message: WORKER_NETWORK_MESSAGE,
  },
];

export default tseslint.config(
  // `public/wasm` is the generated wasm-bindgen glue, staged by
  // `scripts/stage-wasm.sh`. It is a build output that happens to be
  // JavaScript, and linting somebody else's generated code says nothing.
  {
    ignores: [
      'dist',
      'node_modules',
      'public/wasm',
      'test-results',
      'playwright-report',
      '.devnet',
    ],
  },
  js.configs.recommended,
  ...tseslint.configs.strictTypeChecked,
  {
    languageOptions: {
      parserOptions: { projectService: true, tsconfigRootDir: import.meta.dirname },
    },
    plugins: { 'react-hooks': reactHooks },
    rules: {
      ...reactHooks.configs.recommended.rules,
      '@typescript-eslint/consistent-type-imports': 'error',
      '@typescript-eslint/restrict-template-expressions': [
        'error',
        { allowNumber: true, allowBoolean: true },
      ],
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
      'no-restricted-syntax': ['error', ...merkleProofFence],
    },
  },
  {
    // Everything but the file that owns the seam.
    files: ['src/**/*.ts', 'src/**/*.tsx'],
    ignores: ['src/chain/api.ts'],
    rules: { 'no-restricted-syntax': ['error', ...merkleProofFence, ...nodeSeamFence] },
  },
  {
    // The side that holds the seed. Last, because a later block replaces the
    // rule rather than adding to it, so this one carries all three fences.
    files: ['src/worker/**'],
    rules: {
      'no-restricted-syntax': [
        'error',
        ...merkleProofFence,
        ...nodeSeamFence,
        ...workerNetworkFence,
      ],
    },
  },
  { files: ['**/*.js'], ...tseslint.configs.disableTypeChecked },
);
