module.exports = {
  "extends": "airbnb-base",
  "parserOptions": { "sourceType": "module" },

  "env": {
    "browser": true,
    "es6": true,
    "node": true
  },

  "globals": { // TODO are all these necessary?
    "console": true,
    "Promise": true,
    "importScripts": true,
    "process": true,
    "Event": true,
    "describe": true,
    "it": true,
    "sinon": true,
    "mocha": true,
    "before": true,
    "beforeEach": true,
    "after": true,
    "afterEach": true,
    "escape": true,
    "unescape": true,
    "postMessage": true,
    "resolves": true,
    "rejects": true
  },

  "rules": {
    // Auto generated rules:
    "accessor-pairs": "error",
    "array-bracket-newline": "error",
    "array-bracket-spacing": [
      "error",
      "never"
    ],
    "array-callback-return": "error",
    "array-element-newline": "off",
    "arrow-body-style": "off",
    "arrow-parens": [
      "error",
      "as-needed"
    ],
    "arrow-spacing": [
      "error",
      {
        "after": true,
        "before": true
      }
    ],
    "block-scoped-var": "off",
    "block-spacing": [
      "error",
      "always"
    ],
    "brace-style": "off",
    "callback-return": "error",
    "camelcase": [
      "error",
      {
        "properties": "never"
      }
    ],
    "capitalized-comments": "off",
    "class-methods-use-this": "error",
    "comma-dangle": [ "error", "never" ],
    "comma-spacing": "off",
    "comma-style": [
      "error",
      "last"
    ],
    "complexity": "off",
    "computed-property-spacing": [
      "error",
      "never"
    ],
    "consistent-return": "off",
    "consistent-this": "error",
    "curly": "error",
    "default-case": "off",
    "dot-location": "error",
    "dot-notation": [
      "error",
      {
        "allowKeywords": true
      }
    ],
    "eol-last": "off",
    "eqeqeq": "error",
    "for-direction": "error",
    "func-call-spacing": "error",
    "func-name-matching": "error",
    "func-names": [
      "error",
      "never"
    ],
    "func-style": "off",
    "function-paren-newline": "off",
    "generator-star-spacing": "error",
    "getter-return": "error",
    "global-require": "off",
    "guard-for-in": "off",
    "handle-callback-err": "error",
    "id-blacklist": "error",
    "id-length": "off",
    "id-match": "error",
    "implicit-arrow-linebreak": [
      "error",
      "beside"
    ],
    "init-declarations": "off",
    "jsx-quotes": "error",
    "key-spacing": "off",
    "keyword-spacing": "off",
    "line-comment-position": "off",
    "linebreak-style": [
      "error",
      "unix"
    ],
    "lines-around-comment": "off",
    "lines-around-directive": "error",
    "lines-between-class-members": "error",
    "max-depth": "off",
    "max-len": "off",
    "max-lines": "off",
    "max-nested-callbacks": "error",
    "max-params": "off",
    "max-statements": "off",
    "max-statements-per-line": "off",
    "multiline-comment-style": "off",
    "multiline-ternary": "off",
    "new-parens": "error",
    "newline-after-var": "off",
    "newline-before-return": "off",
    "newline-per-chained-call": "off",
    "no-alert": "error",
    "no-array-constructor": "error",
    "no-await-in-loop": "error",
    "no-bitwise": "off",
    "no-buffer-constructor": "error",
    "no-caller": "error",
    "no-catch-shadow": "error",
    "no-confusing-arrow": "error",
    "no-continue": "off",
    "no-div-regex": "error",
    "no-duplicate-imports": "error",
    "no-else-return": "off",
    "no-empty": [
      "error",
      {
        "allowEmptyCatch": true
      }
    ],
    "no-empty-function": "off",
    "no-eq-null": "error",
    "no-eval": "error",
    "no-extend-native": "error",
    "no-extra-bind": "error",
    "no-extra-label": "error",
    "no-extra-parens": "off",
    "no-floating-decimal": "error",
    "no-implicit-globals": "error",
    "no-implied-eval": "error",
    "no-inline-comments": "off",
    "no-inner-declarations": [
      "error",
      "functions"
    ],
    "no-invalid-this": "error",
    "no-iterator": "error",
    "no-label-var": "error",
    "no-labels": "error",
    "no-lone-blocks": "error",
    "no-lonely-if": "error",
    "no-loop-func": "error",
    "no-magic-numbers": "off",
    "no-mixed-operators": "off",
    "no-mixed-requires": "error",
    "no-multi-assign": "error",
    "no-multi-spaces": [
      "error",
      {
        "ignoreEOLComments": true
      }
    ],
    "no-multi-str": "error",
    "no-multiple-empty-lines": "error",
    "no-native-reassign": "error",
    "no-negated-condition": "off",
    "no-negated-in-lhs": "error",
    "no-nested-ternary": "off",
    "no-new": "error",
    "no-new-func": "error",
    "no-new-object": "error",
    "no-new-require": "error",
    "no-new-wrappers": "error",
    "no-octal-escape": "error",
    "no-param-reassign": "off",
    "no-path-concat": "error",
    "no-plusplus": "off",
    "no-process-env": "error",
    "no-process-exit": "error",
    "no-proto": "error",
    "no-prototype-builtins": "off",
    "no-restricted-globals": "error",
    "no-restricted-imports": "error",
    "no-restricted-modules": "error",
    "no-restricted-properties": "error",
    "no-restricted-syntax": "error",
    "no-return-assign": "error",
    "no-return-await": "error",
    "no-script-url": "error",
    "no-self-compare": "error",
    "no-shadow": "off",
    "no-shadow-restricted-names": "error",
    "no-spaced-func": "error",
    "no-sync": "error",
    "no-tabs": "error",
    "no-template-curly-in-string": "error",
    "no-ternary": "off",
    "no-throw-literal": "error",
    "no-undef-init": "error",
    "no-undefined": "off",
    "no-unmodified-loop-condition": "error",
    "no-unneeded-ternary": [
      "error",
      {
        "defaultAssignment": true
      }
    ],
    "no-unused-expressions": "error",
    "no-use-before-define": "off",
    "no-useless-call": "error",
    "no-useless-computed-key": "error",
    "no-useless-concat": "error",
    "no-useless-constructor": "error",
    "no-useless-rename": "error",
    "no-useless-return": "error",
    "no-var": "off",
    "no-void": "error",
    "no-warning-comments": "off",
    "no-whitespace-before-property": "error",
    "no-with": "error",
    "nonblock-statement-body-position": "error",
    "object-curly-newline": "off",
    "object-curly-spacing": "off",
    "object-property-newline": [
      "error",
      {
        "allowMultiplePropertiesPerLine": true
      }
    ],
    "object-shorthand": "off",
    "one-var": "off",
    "one-var-declaration-per-line": [
      "error",
      "initializations"
    ],
    "operator-assignment": "off",
    "operator-linebreak": [
      "error",
      "after"
    ],
    "padded-blocks": "off",
    "padding-line-between-statements": "error",
    "prefer-arrow-callback": "off",
    "prefer-const": "off",
    "prefer-destructuring": "off",
    "prefer-numeric-literals": "error",
    "prefer-promise-reject-errors": "error",
    "prefer-reflect": "off",
    "prefer-rest-params": "off",
    "prefer-spread": "off",
    "prefer-template": "off",
    "quote-props": "off",
    "quotes": "off",
    "radix": [
      "error",
      "as-needed"
    ],
    "require-await": "error",
    "require-jsdoc": "off",
    "rest-spread-spacing": "error",
    "semi": "off",
    "semi-spacing": [
      "error",
      {
        "after": true,
        "before": false
      }
    ],
    "semi-style": [
      "error",
      "last"
    ],
    "sort-imports": "off",
    "sort-keys": "off",
    "sort-vars": "off",
    "space-before-blocks": "off",
    "space-before-function-paren": "off",
    "space-in-parens": [
      "error",
      "never"
    ],
    "space-infix-ops": "off",
    "space-unary-ops": "error",
    "spaced-comment": "off",
    "strict": "off",
    "switch-colon-spacing": "error",
    "symbol-description": "error",
    "template-curly-spacing": "error",
    "template-tag-spacing": "error",
    "unicode-bom": [
      "error",
      "never"
    ],
    "valid-jsdoc": "off",
    "vars-on-top": "off",
    "wrap-iife": "error",
    "wrap-regex": "off",
    "yield-star-spacing": "error",
    "yoda": [
      "error",
      "never"
    ],

    // Custom silencers: 
    "camelcase": 0,
    "no-debugger": 0,
    "no-multi-assign": 0,
    "no-underscore-dangle": 0, 
    "one-var-declaration-per-line": 0,

    // Custom errors:
    "no-undef": 2,
    "no-trailing-spaces": 2,
    "no-mixed-operators": [ 2, {"groups": [["&", "|", "^", "~", "<<", ">>", ">>>"], ["&&", "||"]]}],
    "no-use-before-define": [ 2, { "functions": false, "classes": true, "variables": false }],
    "no-unused-expressions": [ 2, { "allowShortCircuit": true } ],

    // Custom warnings:
    "no-console": 0,
    "no-unused-vars": 0,
    "indent": [ 0, 2, { "SwitchCase": 1 } ],

    // Consider fixing these:
    "new-cap": [ 0, { "properties": false, "capIsNewExceptionPattern": "^type_.*" }],
    "no-lonely-if": 0,
    "no-fallthrough": 0,
    "consistent-this": 0,
    "no-invalid-this": 0,
    "callback-return": 0,
    "no-useless-call": 0, // only occurs for workers
    "import/extensions": 0,
    "no-useless-escape": 0,
    "no-case-declarations": 0,
    "no-restricted-syntax": 0,
    "no-array-constructor": 0,
    "no-constant-condition": 0,
    "no-buffer-constructor": 0, // deprecated
    "no-restricted-properties": 0 // Math.pow
  }
};
