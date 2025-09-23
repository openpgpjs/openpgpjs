// @ts-check
import eslint from '@eslint/js';
import { defineConfig, globalIgnores } from 'eslint/config';
import tseslint from 'typescript-eslint';
import globals from 'globals';
// @ts-expect-error missing types
import pluginChaiFriendly from 'eslint-plugin-chai-friendly';
import pluginImport from 'eslint-plugin-import';
import pluginStylistic from '@stylistic/eslint-plugin';
// @ts-expect-error missing types
import pluginUnicorn from 'eslint-plugin-unicorn';

export default defineConfig(
  eslint.configs.recommended,
  tseslint.configs.recommended,
  globalIgnores(['dist/', 'test/lib/', 'docs/', '.jsdocrc.cjs']),
  {
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'module',
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname
      },
      globals: {
        ...globals.browser,
        ...globals.nodeBuiltin,
        ...globals.mocha
      }
    },
    settings: {
      'import/resolver': {
        typescript: { alwaysTryTypes: true }
      }
    },
    plugins: {
      'chai-friendly': pluginChaiFriendly,
      'import': pluginImport,
      '@stylistic': pluginStylistic,
      'unicorn': pluginUnicorn
    },
    rules: {
      'arrow-body-style': 'off',
      'arrow-parens': ['error','as-needed'],
      'class-methods-use-this': 'off', // TODO warn

      'comma-dangle': ['error', 'never'],
      '@typescript-eslint/comma-spacing': 'off',
      'consistent-return': 'off',
      'default-case': 'off',
      '@typescript-eslint/default-param-last': 'off',
      'eol-last': ['error', 'always'],
      'function-call-argument-newline': 'off',
      'func-names': ['error', 'never'],
      'function-paren-newline': 'off',
      'global-require': 'off',
      'key-spacing': 'off',
      'keyword-spacing': 'error',
      'max-classes-per-file': 'off',
      'max-len': 'off',
      'newline-per-chained-call': 'off',
      'no-bitwise': 'off',
      'no-continue': 'off',
      'no-else-return': 'off',
      'no-empty': ['error', { 'allowEmptyCatch': true }],
      'no-multiple-empty-lines': ['error', { 'max': 2, 'maxEOF': 1, 'maxBOF':0 }],
      'no-nested-ternary': 'off', // TODO warn
      'no-param-reassign': 'off', // TODO get rid of this
      'no-plusplus': 'off',
      'no-restricted-syntax': ['error', 'ForInStatement', 'LabeledStatement', 'WithStatement'],
      'object-curly-newline': 'off',
      '@typescript-eslint/no-shadow': 'off', // TODO get rid of this
      'object-property-newline': [
        'error',
        {
          'allowMultiplePropertiesPerLine': true
        }
      ],
      'object-shorthand': 'off',
      'operator-assignment': 'off',
      'operator-linebreak': [
        'error',
        'after'
      ],
      'padded-blocks': 'off',
      'prefer-arrow-callback': 'off',
      'prefer-destructuring': 'off',
      'prefer-rest-params': 'off', // TODO get rid of this
      'prefer-spread': 'off', // TODO get rid of this
      'prefer-template': 'off',
      'quote-props': 'off',
      'quotes': ['error', 'single', { 'avoidEscape': true }],
      'spaced-comment': 'off',
      'indent': 'off',
      'no-unused-vars': 'off',
      '@typescript-eslint/no-unused-vars': [
        'error',
        {
          'argsIgnorePattern': '^_'
        }
      ],
      // eslint-plugin-import rules:
      'import/named': 'error',
      'import/extensions': 'off', // temporary: we use them in tests (ESM compliant), but not in the lib (to limit diff)
      'import/first': 'off',
      'import/no-extraneous-dependencies': ['error', { 'devDependencies': true, 'optionalDependencies': false, 'peerDependencies': false }],
      'import/no-unassigned-import': 'error',
      'import/no-unresolved': 'error',
      'import/prefer-default-export': 'off',
      'import/newline-after-import': 'error',

      // Custom silencers:
      'no-multi-assign': 'off',
      'no-underscore-dangle': 'off',
      'no-await-in-loop': 'off',
      'camelcase': 'off', // snake_case used in tests, need to fix separately
      '@typescript-eslint/naming-convention': 'off', // supersedes 'camelcase' rule
      '@typescript-eslint/lines-between-class-members': 'off',
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/no-this-alias': 'off',

      // Custom errors:
      '@typescript-eslint/no-use-before-define': ['error', { 'functions': false, 'classes': true, 'variables': false, 'allowNamedExports': true }],
      'no-constant-condition': [2, { 'checkLoops': false }],
      'new-cap': ['error', {
        properties: false,
        newIsCap: true,
        newIsCapExceptions: [],
        capIsNew: false
      }],
      'max-lines': [2, { 'max': 620, 'skipBlankLines': true, 'skipComments': true }],
      '@typescript-eslint/no-unused-expressions': 'off',
      'chai-friendly/no-unused-expressions': ['error', { 'allowShortCircuit': true }],
      '@typescript-eslint/no-empty-object-type': ['error', { allowInterfaces: 'with-single-extends' }],

      '@stylistic/indent': ['error', 2, { 'SwitchCase': 1 }],
      '@stylistic/quotes': ['error', 'single', { avoidEscape: true }],
      '@stylistic/space-before-function-paren': ['error', { 'anonymous': 'ignore', 'named': 'never', 'asyncArrow': 'always' }],
      '@stylistic/no-mixed-operators': ['error', {
        allowSamePrecedence: true,
        groups: [
          ['==', '!=', '===', '!==', '>', '>=', '<', '<='],
          ['&&', '||']
        ]
      }],
      '@stylistic/no-mixed-spaces-and-tabs': 'error',
      '@stylistic/eol-last': 'error',
      '@stylistic/no-trailing-spaces': 'error',
      '@stylistic/no-tabs': 'error',
      'unicorn/switch-case-braces': ['error', 'avoid'],
      'no-console': 'warn',
      'no-process-exit': 'error'
    }
  }
);
