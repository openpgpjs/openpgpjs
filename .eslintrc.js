module.exports = {
  'extends': 'airbnb-base',
  'parserOptions': {
    'ecmaVersion': 11,
    'sourceType': 'module'
  },

  'env': {
    'browser': true,
    'es6': true,
    'node': true
  },

  'plugins': [
    'chai-friendly',
    'import'
  ],

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
    'comma-dangle': ['error', 'never'],
    'comma-spacing': 'off',
    'consistent-return': 'off',
    'default-case': 'off',
    'default-param-last': 'off',
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
    'no-shadow': 'off', // TODO get rid of this
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
    'space-before-function-paren': 'off',
    'spaced-comment': 'off',
    'indent': ['error', 2, { 'SwitchCase': 1 }],
    'no-unused-vars': 'error',

    // eslint-plugin-import rules:
    'import/named': 'error',
    'import/extensions': 'error',
    'import/first': 'off',
    'import/no-extraneous-dependencies': ['error', { 'devDependencies': true, 'optionalDependencies': false, 'peerDependencies': false }],
    'import/no-unassigned-import': 'error',
    'import/prefer-default-export': 'off',

    // Custom silencers:
    'camelcase': 'off', // used in tests, need to fix separately
    'no-multi-assign': 'off',
    'no-underscore-dangle': 'off',
    'no-await-in-loop': 'off',

    // Custom errors:
    'no-use-before-define': [2, { 'functions': false, 'classes': true, 'variables': false }],
    'no-constant-condition': [2, { 'checkLoops': false }],
    'new-cap': [2, { 'properties': false, 'capIsNewExceptionPattern': 'EAX|OCB|GCM|CMAC|CBC|OMAC|CTR', 'newIsCapExceptionPattern': 'type|hash*' }],
    'max-lines': [2, { 'max': 620, 'skipBlankLines': true, 'skipComments': true }],
    'no-unused-expressions': 0,
    'chai-friendly/no-unused-expressions': [2, { 'allowShortCircuit': true }],

    // Custom warnings:
    'no-console': 1
  }
};
