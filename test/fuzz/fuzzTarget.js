// All functions that need to be fuzz-tested
import { FuzzedDataProvider } from '@jazzer.js/core';
// A fuzz target module needs to export a function called fuzz,
// which takes a Buffer parameter and executes the actual code under test.
// The Buffer, a subclass of Uint8Array
// Jazzer.js provides the wrapper class FuzzedDataProvider, which allows reading primitive types from the Buffer

/**
 * @param { Buffer } fuzzerInputData
 */
// module.exports.fuzz = function (inputData) {
//   // const fuzzerData = inputData.toString();
//   const data = new FuzzedDataProvider(inputData);
//   const intParam = data.consumeIntegral(4);
//   const stringParam = data.consumeString(4, 'utf-8');
//   myAwesomeCode(intParam, stringParam);
//   // myAwesomeCode(fuzzerData);
// };

// example
/**
 * @param { Buffer } fuzzerInputData
 */
export function fuzz (fuzzerInputData) {
  const data = new FuzzedDataProvider(fuzzerInputData);
  const s1 = data.consumeString(data.consumeIntegralInRange(10, 15), 'utf-8');
  const i1 = data.consumeIntegral(1);
  if (s1 === 'Hello World!') {
    if (i1 === 3) {
      throw new Error('Crash!');
    }
  }
}
