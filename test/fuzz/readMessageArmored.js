import { FuzzedDataProvider } from '@jazzer.js/core';

import { readMessage } from 'openpgp';

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
  const armoredMessage = `-----BEGIN PGP MESSAGE-----\n ${fuzzedText} -----END PGP MESSAGE-----`;

  return readMessage({ armoredMessage })
    .catch(error => {
      if (error.message && !ignoredError(error)) {
        throw error;
      }
    });
}

