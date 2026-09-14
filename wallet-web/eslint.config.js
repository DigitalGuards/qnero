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
  { files: ['**/*.js'], ...tseslint.configs.disableTypeChecked },
);
