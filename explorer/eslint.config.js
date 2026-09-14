import js from '@eslint/js';
import reactHooks from 'eslint-plugin-react-hooks';
import tseslint from 'typescript-eslint';

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
      // The node exposes the same proof three ways: the `zkTree_getMerkleProof`
      // method and the `ZkTreeApi_get_merkle_proof` runtime call behind
      // `state_call`, `state_callAt` and `archive_v1_call`. Keying only on the
      // method name would leave the two replacements the node documents open,
      // and a runtime call is the shape this codebase already uses for the
      // QPoWApi constants, so it would be the natural way to reintroduce it.
      'no-restricted-syntax': [
        'error',
        {
          selector: "CallExpression[callee.property.name='send'][arguments.0.value=/^zkTree_getMerkleProof$/]",
          message:
            'A Merkle proof call names one leaf to whoever runs the node. Read ZkTree::Leaves instead.',
        },
        {
          selector:
            "CallExpression[callee.property.name='send'][arguments.0.value=/^(state_call|state_callAt|archive_v1_call)$/][arguments.1.elements.0.value=/get_merkle_proof/i]",
          message:
            'A Merkle proof runtime call names one leaf to whoever runs the node. Read ZkTree::Leaves instead.',
        },
      ],
    },
  },
  { files: ['**/*.js'], ...tseslint.configs.disableTypeChecked },
);
