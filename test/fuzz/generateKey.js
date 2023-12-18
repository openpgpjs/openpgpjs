import { FuzzedDataProvider } from '@jazzer.js/core';

import { generateKey } from 'openpgp';

const MAX_NAME_LENGTH = 30;
const MAX_COMMENT_LENGTH = 500;

/**
 * @param { Buffer } inputData
 */
export function fuzz (inputData) {

  const data = new FuzzedDataProvider(inputData);
  const asciiString = data.consumeString(MAX_COMMENT_LENGTH);
  const utf8String = data.consumeString(MAX_NAME_LENGTH, 'utf-8');

  return generateKey({ userIDs: [
    { name: utf8String },
    { email: utf8String },
    { comment: asciiString },
    { name: utf8String, email: utf8String, comment: asciiString }
  ],
  passphrase: asciiString,
  format: 'object' });
}

