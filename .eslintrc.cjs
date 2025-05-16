module.exports = {
  'extends': [
    'airbnb-base',
    'airbnb-typescript/base'
  ],

  'parser': '@typescript-eslint/parser',

  'parserOptions': {
    'ecmaVersion': 11,
    'sourceType': 'module',
    'project': 'tsconfig.json'
  },

  'env': {
    'browser': true,
    'es6': true,
    'node': true
  },

  'plugins': [
    '@typescript-eslint',
    'chai-friendly',
    'import',
    'unicorn'
  ],

  'settings': {
    'import/resolver': {
      'typescript': {}
    }
  },

  'globals': { // TODO are all these necessary?
    'globalThis': true,
    'console': true,
    'Promise': true,
    'importScripts': true,
    'process': true,
    'Event': true,
    'describe': true,
    'it': true,
    'mocha': true,
    'before': true,
    'beforeEach': true,
    'after': true,
    'afterEach': true,
    'escape': true,
    'unescape': true,
    'resolves': true,
    'rejects': true,
    'TransformStream': true,
    'BigInt': true
  },

  'rules': {
    'arrow-body-style': 'off',
    'arrow-parens': ['error','as-needed'],
    'class-methods-use-this': 'off',
    '@typescript-eslint/comma-dangle': ['error', 'never'],
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
    'no-nested-ternary': 'off',
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
    '@typescript-eslint/space-before-function-paren': ['error', { 'anonymous': 'ignore', 'named': 'never', 'asyncArrow': 'always' }],
    'spaced-comment': 'off',
    'indent': 'off',
    '@typescript-eslint/indent': ['error', 2, { 'SwitchCase': 1 }],
    'no-unused-vars': 'off',
    "@typescript-eslint/no-unused-vars": [
      "error",
      {
        "argsIgnorePattern": "^_",
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

    // Custom silencers:
    'no-multi-assign': 'off',
    'no-underscore-dangle': 'off',
    'no-await-in-loop': 'off',
    'camelcase': 'off', // snake_case used in tests, need to fix separately
    '@typescript-eslint/naming-convention': 'off', // supersedes 'camelcase' rule
    '@typescript-eslint/lines-between-class-members': 'off',

    // Custom errors:
    '@typescript-eslint/no-use-before-define': ['error', { 'functions': false, 'classes': true, 'variables': false, 'allowNamedExports': true }],
    'no-constant-condition': [2, { 'checkLoops': false }],
    'new-cap': [2, { 'properties': false, 'capIsNewExceptionPattern': 'EAX|OCB|GCM|CMAC|CBC|OMAC|CTR', 'newIsCapExceptionPattern': 'type|hash*' }],
    'max-lines': [2, { 'max': 620, 'skipBlankLines': true, 'skipComments': true }],
    '@typescript-eslint/no-unused-expressions': 0,
    'chai-friendly/no-unused-expressions': [2, { 'allowShortCircuit': true }],
    'unicorn/switch-case-braces': ['error', 'avoid'],

    // Custom warnings:
    'no-console': 1
  }
};
