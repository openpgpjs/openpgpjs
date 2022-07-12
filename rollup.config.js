/* eslint-disable no-process-env */

import { builtinModules } from 'module';
import { readFileSync } from 'fs';

import alias from '@rollup/plugin-alias';
import resolve from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';
import replace from '@rollup/plugin-replace';
import terser from '@rollup/plugin-terser';
import { wasm } from '@rollup/plugin-wasm';
import typescript from '@rollup/plugin-typescript';

// ESlint does not support JSON module imports yet, see https://github.com/eslint/eslint/discussions/15305
// import pkg from './package.json' assert { type: 'json' };
const pkg = JSON.parse(readFileSync('./package.json'));

const nodeDependencies = Object.keys(pkg.dependencies || {});
const nodeBuiltinModules = builtinModules.concat(['module']);

const wasmOptions = {
  node: { targetEnv: 'node' },
  browser: { targetEnv: 'browser', maxFileSize: undefined } // always inlline (our wasm files are small)
};

const getChunkFileName = (chunkInfo, extension) => `[name].${extension}`;

/**
 * Dynamically imported modules which expose an index file as entrypoint end up with a chunk named `index`
 * by default. We want to preserve the module name instead.
 */
const setManualChunkName = chunkId => {
  if (chunkId.includes('seek-bzip')) {
    return 'seek-bzip';
  } else if (chunkId.includes('argon2id')) {
    return 'argon2id';
  } else {
    return undefined;
  }
};

const banner =
  `/*! OpenPGP.js v${pkg.version} - ` +
  `${new Date().toISOString().split('T')[0]} - ` +
  `this is LGPL licensed code, see LICENSE/our website ${pkg.homepage} for more information. */`;

const intro = "const globalThis = typeof window !== 'undefined' ? window : typeof global !== 'undefined' ? global : typeof self !== 'undefined' ? self : {};";

const terserOptions = {
  ecma: 2017,
  compress: {
    unsafe: true
  },
  output: {
    comments: '/^(?:!|#__)/',
    preserve_annotations: true
  }
};

const nodeBuild = {
  input: 'src/index.js',
  external: nodeBuiltinModules.concat(nodeDependencies),
  output: [
    { file: 'dist/node/openpgp.cjs', format: 'cjs', name: 'openpgp', banner, intro },
    { file: 'dist/node/openpgp.min.cjs', format: 'cjs', name: 'openpgp', banner, intro, plugins: [terser(terserOptions)], sourcemap: true },
    { file: 'dist/node/openpgp.mjs', format: 'es', banner, intro },
    { file: 'dist/node/openpgp.min.mjs', format: 'es', banner, intro, plugins: [terser(terserOptions)], sourcemap: true }
  ].map(options => ({ ...options, inlineDynamicImports: true })),
  plugins: [
    resolve({
      exportConditions: ['node'] // needed for resolution of noble-curves import of '@noble/crypto' in Node 18
    }),
    typescript({
      compilerOptions: { outDir: './dist/tmp-ts' }
    }),
    commonjs(),
    replace({
      'OpenPGP.js VERSION': `OpenPGP.js ${pkg.version}`
    }),
    wasm(wasmOptions.node)
  ]
};

const fullBrowserBuild = {
  input: 'src/index.js',
  external: nodeBuiltinModules.concat(nodeDependencies),
  output: [
    { file: 'dist/openpgp.js', format: 'iife', name: 'openpgp', banner, intro },
    { file: 'dist/openpgp.min.js', format: 'iife', name: 'openpgp', banner, intro, plugins: [terser(terserOptions)], sourcemap: true },
    { file: 'dist/openpgp.mjs', format: 'es', banner, intro },
    { file: 'dist/openpgp.min.mjs', format: 'es', banner, intro, plugins: [terser(terserOptions)], sourcemap: true }
  ].map(options => ({ ...options, inlineDynamicImports: true })),
  plugins: [
    resolve({
      browser: true
    }),
    typescript({
      compilerOptions: { outDir: './dist/tmp-ts' } // to avoid js files being overwritten
    }),
    commonjs({
      ignore: nodeBuiltinModules.concat(nodeDependencies)
    }),
    replace({
      'OpenPGP.js VERSION': `OpenPGP.js ${pkg.version}`,
      "import { createRequire } from 'module';": 'const createRequire = () => () => {}',
      delimiters: ['', '']
    }),
    wasm(wasmOptions.browser)
  ]
};

const lightweightBrowserBuild = {
  input: 'src/index.js',
  external: nodeBuiltinModules.concat(nodeDependencies),
  output: [
    { entryFileNames: 'openpgp.mjs', chunkFileNames: chunkInfo => getChunkFileName(chunkInfo, 'mjs') },
    { entryFileNames: 'openpgp.min.mjs', chunkFileNames: chunkInfo => getChunkFileName(chunkInfo, 'min.mjs'), plugins: [terser(terserOptions)], sourcemap: true }
  ].map(options => ({ ...options, dir: 'dist/lightweight', manualChunks: setManualChunkName, format: 'es', banner, intro })),
  preserveEntrySignatures: 'exports-only',
  plugins: [
    resolve({
      browser: true
    }),
    typescript({
      compilerOptions: { outDir: './dist/lightweight/tmp-ts' }
    }),
    commonjs({
      ignore: nodeBuiltinModules.concat(nodeDependencies)
    }),
    replace({
      'OpenPGP.js VERSION': `OpenPGP.js ${pkg.version}`,
      "import { createRequire } from 'module';": 'const createRequire = () => () => {}',
      delimiters: ['', '']
    }),
    wasm(wasmOptions.browser)
  ]
};

const testBuild = {
  input: 'test/unittests.js',
  output: [
    { file: 'test/lib/unittests-bundle.js', format: 'es', intro, sourcemap: true, inlineDynamicImports: true }
  ],
  external: nodeBuiltinModules.concat(nodeDependencies),
  plugins: [
    alias({
      entries: {
        '@protontech/openpgp': `./dist/${process.env.npm_config_lightweight ? 'lightweight/' : ''}openpgp.mjs`
      }
    }),
    resolve({
      browser: true
    }),
    typescript({
      compilerOptions: { outDir: './test/lib/tmp-ts' }
    }),
    commonjs({
      ignore: nodeBuiltinModules.concat(nodeDependencies),
      requireReturnsDefault: 'preferred'
    }),
    replace({
      "import { createRequire } from 'module';": 'const createRequire = () => () => {}',
      delimiters: ['', '']
    }),
    wasm(wasmOptions.browser)
  ]
};

export default Object.assign([
  nodeBuild,
  fullBrowserBuild,
  lightweightBrowserBuild,
  testBuild
].filter(config => {
  config.output = config.output.filter(output => {
    return (output.file || output.dir + '/' + output.entryFileNames).includes(
      process.env.npm_config_build_only || // E.g. `npm install --build-only=lightweight`.
      'dist' // Don't build test bundle by default.
    );
  });
  return config.output.length;
}), {
  allow_empty: true // Fake option to trick rollup into accepting empty config array when filtered above.
});
