import { FuzzedDataProvider } from '@jazzer.js/core';

import { createMessage } from 'openpgp';

const MAX_MESSAGE_LENGTH = 4096;

/**
 * @param { Buffer } inputData
 */
export function fuzz (inputData) {
  const data = new FuzzedDataProvider(inputData);
  return createMessage({ text: data.consumeString(MAX_MESSAGE_LENGTH, 'utf-8') });
}
