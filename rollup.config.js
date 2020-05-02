import { builtinModules } from 'module';

import resolve from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';
import replace from '@rollup/plugin-replace';
import { terser } from "rollup-plugin-terser";

import pkg from './package.json';

const nodeDependencies = Object.keys(pkg.dependencies);

const banner =
  `/*! OpenPGP.js v${pkg.version} - ` +
  `${new Date().toISOString().split('T')[0]} - ` +
  `this is LGPL licensed code, see LICENSE/our website ${pkg.homepage} for more information. */`;

const terserOptions = {
  ecma: 2017,
  compress: {
    unsafe: true
  }
};

export default [
  {
    input: 'src/index.js',
    output: [
      { file: 'dist/openpgp.js', format: 'iife', name: pkg.name, banner },
      { file: 'dist/openpgp.min.js', format: 'iife', name: pkg.name, banner, plugins: [terser(terserOptions)] },
      { file: 'dist/openpgp.mjs', format: 'es', banner },
      { file: 'dist/openpgp.min.mjs', format: 'es', banner, plugins: [terser(terserOptions)] }
    ],
    plugins: [
      resolve({
        browser: true
      }),
      commonjs({
        ignore: builtinModules.concat(nodeDependencies)
      }),
      replace({
        'OpenPGP.js VERSION': `OpenPGP.js ${pkg.version}`,
        'require(': 'void(',
        delimiters: ['', '']
      })
    ]
  },
  {
    input: 'src/index.js',
    external: builtinModules.concat(nodeDependencies),
    output: [
      { file: 'dist/node/openpgp.js', format: 'cjs', name: pkg.name, banner },
      { file: 'dist/node/openpgp.min.js', format: 'cjs', name: pkg.name, banner, plugins: [terser(terserOptions)] },
      { file: 'dist/node/openpgp.mjs', format: 'es', banner },
      { file: 'dist/node/openpgp.min.mjs', format: 'es', banner, plugins: [terser(terserOptions)] }
    ],
    plugins: [
      resolve(),
      commonjs(),
      replace({
        'OpenPGP.js VERSION': `OpenPGP.js ${pkg.version}`,
      })
    ]
  },
  {
    input: 'src/index.js',
    output: [
      { file: 'dist/lightweight/openpgp.js', format: 'iife', name: pkg.name, banner },
      { file: 'dist/lightweight/openpgp.min.js', format: 'iife', name: pkg.name, banner, plugins: [terser(terserOptions)] },
      { file: 'dist/lightweight/openpgp.mjs', format: 'es', banner },
      { file: 'dist/lightweight/openpgp.min.mjs', format: 'es', banner, plugins: [terser(terserOptions)] }
    ],
    plugins: [
      resolve({
        browser: true
      }),
      commonjs({
        ignore: builtinModules.concat(nodeDependencies).concat('elliptic')
      }),
      replace({
        'OpenPGP.js VERSION': `OpenPGP.js ${pkg.version}`,
        'externalIndutnyElliptic: false': 'externalIndutnyElliptic: true',
        'require(': 'void(',
        delimiters: ['', '']
      })
    ]
  },
  {
    input: 'node_modules/elliptic/dist/elliptic.min.js',
    output: [
      { file: 'dist/lightweight/elliptic.min.js', format: 'es' }
    ],
    plugins: [
      replace({
        'b.elliptic=a()': 'b.openpgp.elliptic=a()',
        delimiters: ['', '']
      })
    ]
  },
  {
    input: 'test/unittests.js',
    output: [
      { file: 'test/lib/unittests-bundle.js', format: 'iife' },
    ],
    plugins: [
      resolve({
        browser: true
      }),
      commonjs({
        ignore: builtinModules.concat(nodeDependencies).concat(['../..', '../../..'])
      })
    ]
  }
];
