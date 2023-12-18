import { readKey } from 'openpgp';

const expected = ['This message / key probably does not conform to a valid OpenPGP format'];

function ignoredError(error) {
  return expected.some(message => error.message.includes(message));
}

/**
 * @param { Buffer } inputData
 */
export function fuzz (inputData) {
  const binaryKey = new Uint8Array(inputData);
  binaryKey[0] |= 0x80;
  return readKey({ binaryKey })
    .catch(error => {
      if (error.message && !ignoredError(error)) {
        throw error;
      }
    });
}

