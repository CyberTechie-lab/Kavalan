import js from '@eslint/js';
import tseslint from 'typescript-eslint';
import firebaseRulesPlugin from '@firebase/eslint-plugin-security-rules';

export default [
  {
    ignores: ['node_modules/**', 'dist/**', 'public/firebase-client.js'],
  },
  ...tseslint.config(
    js.configs.recommended,
    ...tseslint.configs.recommended,
    {
      files: ['**/*.ts', '**/*.tsx', '**/*.js', '**/*.mjs'],
      rules: {
        '@typescript-eslint/no-explicit-any': 'off',
        '@typescript-eslint/no-unused-vars': ['warn', { argsIgnorePattern: '^_' }],
      },
    }
  ),
  firebaseRulesPlugin.configs['flat/recommended'],
];
