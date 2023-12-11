const ignored = ['This message / key probably does not conform to a valid OpenPGP format'];

function ignoredError(error) {
  return ignored.some(message => error.message.includes(message));
}

/**
 * @param { Buffer } inputData
 */
module.exports.fuzz = function(inputData) {
  import('../initOpenpgp.js').then(openpgp => {
    const binaryMessage = new Uint8Array(`-----BEGIN PGP MESSAGE----- ${inputData} -----END PGP MESSAGE-----`);

    return openpgp.default.readMessage({ binaryMessage })
      .catch(error => {
        if (error.message && !ignoredError(error)) {
          throw error;
        }
      });
  });
};

