import openpgp from '../initOpenpgp.js';

/**
 * @param { Buffer } inputData
 */
export function fuzz (inputData) {
  return openpgp.createMessage({ binary: new Uint8Array(inputData) });
}

