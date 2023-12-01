// eslint-disable-next-line import/no-import-module-exports
import openpgp from '../initOpenpgp.js';

// All functions that need to be fuzz-tested
// A fuzz target module needs to export a function called fuzz,
// which takes a Buffer parameter and executes the actual code under test.
// The Buffer, a subclass of Uint8Array
// Jazzer.js provides the wrapper class FuzzedDataProvider, which allows reading primitive types from the Buffer

/**
 * @param { Buffer } inputData
 */
export async function fuzz(inputData) {
  const fuzzerData = inputData.toString();

  openpgp.createMessage({ binary: new Uint8Array(fuzzerData) });
}

