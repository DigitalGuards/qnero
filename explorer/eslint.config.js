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

export default tseslint.config(
  { ignores: ['dist', 'node_modules', 'test-results', 'playwright-report', '.devnet'] },
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
  { files: ['**/*.js'], ...tseslint.configs.disableTypeChecked },
);
