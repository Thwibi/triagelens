import js from '@eslint/js'
import react from 'eslint-plugin-react'
import reactHooks from 'eslint-plugin-react-hooks'
import globals from 'globals'
import tseslint from 'typescript-eslint'

export default tseslint.config(
  {
    ignores: [
      'dist/**',
      'node_modules/**',
      '../backend/app/static/**',
      'coverage/**',
      '**/*.tsbuildinfo',
      // Generated from the backend OpenAPI document; do not hand-edit or lint.
      'src/api/openapi.d.ts',
    ],
  },
  js.configs.recommended,
  {
    files: ['**/*.{ts,tsx}'],
    extends: [...tseslint.configs.strictTypeChecked, ...tseslint.configs.stylisticTypeChecked],
    languageOptions: {
      ecmaVersion: 2023,
      sourceType: 'module',
      globals: { ...globals.browser, ...globals.es2023 },
      parserOptions: {
        ecmaFeatures: { jsx: true },
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    settings: {
      react: { version: '18.3' },
    },
    plugins: {
      react,
      'react-hooks': reactHooks,
    },
    rules: {
      // The base rule cannot see TypeScript types; the typed version replaces it.
      'no-unused-vars': 'off',
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
      '@typescript-eslint/consistent-type-imports': ['error', { fixStyle: 'inline-type-imports' }],
      '@typescript-eslint/no-import-type-side-effects': 'error',
      '@typescript-eslint/explicit-module-boundary-types': 'error',
      '@typescript-eslint/no-non-null-assertion': 'error',
      '@typescript-eslint/restrict-template-expressions': ['error', { allowNumber: true }],
      '@typescript-eslint/switch-exhaustiveness-check': 'error',
      // Mandated by spec 00 section 9: dangerouslySetInnerHTML is banned outright
      // so log content can never be injected as live markup.
      'react/no-danger': 'error',
      'react/jsx-no-target-blank': 'error',
      'react/self-closing-comp': 'error',
      'react/jsx-uses-react': 'off',
      'react/react-in-jsx-scope': 'off',
      'react-hooks/rules-of-hooks': 'error',
      'react-hooks/exhaustive-deps': 'error',
      eqeqeq: ['error', 'always'],
      'no-console': ['error', { allow: ['error'] }],
      'no-implicit-coercion': 'error',
      'no-param-reassign': 'error',
      'prefer-const': 'error',
      'no-var': 'error',
      'object-shorthand': 'error',
      curly: ['error', 'multi-line'],
    },
  },
  {
    files: ['**/*.test.{ts,tsx}', 'src/test/**/*.{ts,tsx}'],
    rules: {
      'no-console': 'off',
      '@typescript-eslint/no-unsafe-assignment': 'off',
      '@typescript-eslint/no-unsafe-member-access': 'off',
      '@typescript-eslint/no-non-null-assertion': 'off',
    },
  },
  {
    // Plain-JS build tooling: recommended rules, no type information needed.
    files: ['**/*.js', '**/*.mjs'],
    languageOptions: {
      ecmaVersion: 2023,
      sourceType: 'module',
      globals: { ...globals.node },
    },
  },
  {
    // Build tooling runs in Node, not the browser.
    files: ['vite.config.ts', '**/*.config.ts'],
    languageOptions: {
      globals: { ...globals.node },
    },
    rules: {
      'no-console': 'off',
    },
  },
  {
    // Browser E2E specs and helpers run under Node (Playwright).
    files: ['e2e/**/*.ts'],
    languageOptions: {
      globals: { ...globals.node },
    },
  },
)