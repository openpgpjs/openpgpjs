import { FuzzedDataProvider } from '@jazzer.js/core';

import { createCleartextMessage } from 'openpgp';

const MAX_MESSAGE_LENGTH = 4096;

/**
 * @param { Buffer } inputData
 */
export function fuzz (inputData) {
  const data = new FuzzedDataProvider(inputData);
  const text = data.bufToPrintableString(inputData, 2, MAX_MESSAGE_LENGTH, 'utf-8');
  return createCleartextMessage({ text });
}

