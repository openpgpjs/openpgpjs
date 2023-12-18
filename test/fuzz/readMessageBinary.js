import { readMessage } from 'openpgp';

const expected = ['This message / key probably does not conform to a valid OpenPGP format'];

function ignoredError(error) {
  return expected.some(message => error.message.includes(message));
}

/**
 * @param { Buffer } inputData
 */
export function fuzz (inputData) {
  const binaryMessage = new Uint8Array(`-----BEGIN PGP MESSAGE-----\n ${inputData.toString('base64')} -----END PGP MESSAGE-----`);

  return readMessage({ binaryMessage })
    .catch(error => {
      if (error.message && !ignoredError(error)) {
        throw error;
      }
    });
}

