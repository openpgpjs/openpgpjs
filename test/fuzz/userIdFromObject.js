import { FuzzedDataProvider } from '@jazzer.js/core';

import { UserIDPacket } from 'openpgp';

const expected = ['Invalid user ID format'];

function ignoredError(error) {
  return expected.some(message => error.message.includes(message));
}

const MAX_NAME_LENGTH = 30;
const MAX_COMMENT_LENGTH = 500;

/**
 * @param { Buffer } inputData
 */
export function fuzz (inputData) {
  const data = new FuzzedDataProvider(inputData);
  const asciiString = data.consumeString(MAX_COMMENT_LENGTH);
  const utf8String = data.consumeString(MAX_NAME_LENGTH, 'utf-8');

  try {
    return UserIDPacket.fromObject({ name: utf8String, email: utf8String, comment: asciiString });
  } catch (error) {
    if (error.message && !ignoredError(error)) {
      throw error;
    }
  }
}

