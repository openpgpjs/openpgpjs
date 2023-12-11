/**
 * @param { Buffer } inputData
 */
module.exports.fuzz = function(inputData) {
  import('../initOpenpgp.js').then(openpgp => {
    return openpgp.default.createMessage({ binary: new Uint8Array(inputData) });
  });
};

