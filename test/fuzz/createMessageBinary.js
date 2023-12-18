import { createMessage } from 'openpgp';

/**
 * @param { Buffer } inputData
 */
export function fuzz (inputData) {
  return createMessage({ binary: new Uint8Array(inputData) });
}

