const { FuzzedDataProvider } = require('@jazzer.js/core');

const ignored = ['Misformed armored text'];
const MAX_MESSAGE_LENGTH = 9000;

function ignoredError(error) {
  return ignored.some(message => error.message.includes(message));
}

/**
 * @param { Buffer } inputData
 */
module.exports.fuzz = function(inputData) {
  import('../initOpenpgp.js').then(openpgp => {
    const data = new FuzzedDataProvider(inputData);
    const fuzzedText = data.consumeString(MAX_MESSAGE_LENGTH, 'utf-8');
    const armoredKey = `-----BEGIN PGP PRIVATE KEY BLOCK----- ${fuzzedText} -----END PGP PRIVATE KEY BLOCK-----`;

    return openpgp.default.readKey({ armoredKey })
      .catch(error => {
        if (error.message && !ignoredError(error)) {
          throw error;
        }
      });
  });
};

