const ignored = ['This message / key probably does not conform to a valid OpenPGP format'];

function ignoredError(error) {
  return ignored.some(message => error.message.includes(message));
}

/**
 * @param { Buffer } inputData
 */
module.exports.fuzz = function(inputData) {
  import('../initOpenpgp.js').then(openpgp => {
    const binaryKey = new Uint8Array(`-----BEGIN PGP PRIVATE KEY BLOCK----- ${inputData} -----END PGP PRIVATE KEY BLOCK-----`);

    return openpgp.default.readKey({ binaryKey })
      .catch(error => {
        if (error.message && !ignoredError(error)) {
          throw error;
        }
      });
  });
};

