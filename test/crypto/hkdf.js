const { expect } = require('chai');

const computeHKDF = require('../../src/crypto/hkdf');
const enums = require('../../src/enums');
const util = require('../../src/util');

// WebCrypto implements HKDF natively, no need to test it
const maybeDescribe = util.getNodeCrypto() ? describe : describe;

module.exports = () => maybeDescribe('HKDF test vectors', function() {
  // Vectors from https://www.rfc-editor.org/rfc/rfc5869#appendix-A
  it('Test Case 1', async function() {
    const inputKey = util.hexToUint8Array('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b');
    const salt = util.hexToUint8Array('000102030405060708090a0b0c');
    const info = util.hexToUint8Array('f0f1f2f3f4f5f6f7f8f9');
    const outLen = 42;

    const actual = await computeHKDF(enums.hash.sha256, inputKey, salt, info, outLen);
    const expected = util.hexToUint8Array('3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865');

    expect(actual).to.deep.equal(expected);
  });

  it('Test Case 2', async function() {
    const inputKey = util.hexToUint8Array('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f');
    const salt = util.hexToUint8Array('606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf');
    const info = util.hexToUint8Array('b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff');
    const outLen = 82;

    const actual = await computeHKDF(enums.hash.sha256, inputKey, salt, info, outLen);
    const expected = util.hexToUint8Array('b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87');

    expect(actual).to.deep.equal(expected);
  });

  it('Test Case 3', async function() {
    const inputKey = util.hexToUint8Array('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b');
    const salt = new Uint8Array();
    const info = new Uint8Array();
    const outLen = 42;

    const actual = await computeHKDF(enums.hash.sha256, inputKey, salt, info, outLen);
    const expected = util.hexToUint8Array('8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8');

    expect(actual).to.deep.equal(expected);
  });
});
