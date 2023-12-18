import { FuzzedDataProvider } from '@jazzer.js/core';

import { readKey } from 'openpgp';

const expected = ['Misformed armored text'];
const MAX_MESSAGE_LENGTH = 4096;

function ignoredError(error) {
  return expected.some(message => error.message.includes(message));
}

/**
 * @param { Buffer } inputData
 */
export function fuzz (inputData) {

  const data = new FuzzedDataProvider(inputData);
  const fuzzedText = data.consumeString(MAX_MESSAGE_LENGTH, 'utf-8');
  const armoredKey = `-----BEGIN PGP PRIVATE KEY BLOCK-----\n ${fuzzedText} -----END PGP PRIVATE KEY BLOCK-----`;

  return readKey({ armoredKey })
    .catch(error => {
      if (error.message && !ignoredError(error)) {
        throw error;
      }
    });
}

