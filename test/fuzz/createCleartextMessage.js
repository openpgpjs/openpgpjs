import { FuzzedDataProvider } from '@jazzer.js/core';

import openpgp from '../initOpenpgp.js';

const MAX_MESSAGE_LENGTH = 4096;

/**
 * @param { Buffer } inputData
 */
export function fuzz (inputData) {
  const data = new FuzzedDataProvider(inputData);
  const text = data.bufToPrintableString(inputData, 2, MAX_MESSAGE_LENGTH, 'utf-8');
  return openpgp.createCleartextMessage({ text });
}

