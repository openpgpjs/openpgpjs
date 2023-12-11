const { FuzzedDataProvider } = require('@jazzer.js/core');

const MAX_MESSAGE_LENGTH = 9000;
/**
 * @param { Buffer } inputData
 */
module.exports.fuzz = function(inputData) {
  import('../initOpenpgp.js').then(openpgp => {
    const data = new FuzzedDataProvider(inputData);
    const text = data.bufToPrintableString(inputData, 2, MAX_MESSAGE_LENGTH, 'utf-8');
    return openpgp.default.createCleartextMessage({ text });
  });

};

