const openpgp = typeof window !== 'undefined' && window.openpgp ? window.openpgp : require('../..');
const crypto = require('../../src/crypto');
const random = require('../../src/crypto/random');
const util = require('../../src/util');

const sandbox = require('sinon/lib/sinon/sandbox');
const chai = require('chai');

chai.use(require('chai-as-promised'));

const expect = chai.expect;

/* eslint-disable no-unused-expressions */
/* eslint-disable no-invalid-this */
const native = util.getWebCrypto() || util.getNodeCrypto();
module.exports = () => (!native ? describe.skip : describe)('basic RSA cryptography with native crypto', function () {
  let sinonSandbox;
  let getWebCryptoStub;
  let getNodeCryptoStub;

  beforeEach(function () {
    sinonSandbox = sandbox.create();
    enableNative();
  });

  afterEach(function () {
    sinonSandbox.restore();
  });

  const disableNative = () => {
    enableNative();
    // stubbed functions return undefined
    getWebCryptoStub = sinonSandbox.stub(util, "getWebCrypto");
    getNodeCryptoStub = sinonSandbox.stub(util, "getNodeCrypto");
  };
  const enableNative = () => {
    getWebCryptoStub && getWebCryptoStub.restore();
    getNodeCryptoStub && getNodeCryptoStub.restore();
  };

  it('generate rsa key', async function() {
    const bits = 1024;
    const keyObject = await crypto.publicKey.rsa.generate(bits, 65537);
    expect(keyObject.n).to.exist;
    expect(keyObject.e).to.exist;
    expect(keyObject.d).to.exist;
    expect(keyObject.p).to.exist;
    expect(keyObject.q).to.exist;
    expect(keyObject.u).to.exist;
  });

  it('sign and verify using generated key params', async function() {
    const bits = 1024;
    const { publicParams, privateParams } = await crypto.generateParams(openpgp.enums.publicKey.rsaSign, bits);
    const message = await random.getRandomBytes(64);
    const hash_algo = openpgp.enums.write(openpgp.enums.hash, 'sha256');
    const hashed = await crypto.hash.digest(hash_algo, message);
    const { n, e, d, p, q, u } = { ...publicParams, ...privateParams };
    const signature = await crypto.publicKey.rsa.sign(hash_algo, message, n, e, d, p, q, u, hashed);
    expect(signature).to.exist;
    const verify = await crypto.publicKey.rsa.verify(hash_algo, message, signature, n, e, hashed);
    expect(verify).to.be.true;
  });

  it('encrypt and decrypt using generated key params', async function() {
    const bits = 1024;
    const { publicParams, privateParams } = await crypto.generateParams(openpgp.enums.publicKey.rsaSign, bits);
    const { n, e, d, p, q, u } = { ...publicParams, ...privateParams };
    const message = await crypto.generateSessionKey('aes256');
    const encrypted = await crypto.publicKey.rsa.encrypt(message, n, e);
    const decrypted = await crypto.publicKey.rsa.decrypt(encrypted, n, e, d, p, q, u);
    expect(decrypted).to.deep.equal(message);
  });

  it('decrypt nodeCrypto by bnCrypto and vice versa', async function() {
    if (!util.getNodeCrypto()) {
      this.skip(); // webcrypto does not implement RSA PKCS#1 v.15 decryption
    }
    const bits = 1024;
    const { publicParams, privateParams } = await crypto.generateParams(openpgp.enums.publicKey.rsaSign, bits);
    const { n, e, d, p, q, u } = { ...publicParams, ...privateParams };
    const message = await crypto.generateSessionKey('aes256');
    disableNative();
    const encryptedBn = await crypto.publicKey.rsa.encrypt(message, n, e);
    enableNative();
    const decrypted1 = await crypto.publicKey.rsa.decrypt(encryptedBn, n, e, d, p, q, u);
    expect(decrypted1).to.deep.equal(message);
    const encryptedNode = await crypto.publicKey.rsa.encrypt(message, n, e);
    disableNative();
    const decrypted2 = await crypto.publicKey.rsa.decrypt(encryptedNode, n, e, d, p, q, u);
    expect(decrypted2).to.deep.equal(message);
  });

  it('compare native crypto and bnSign', async function() {
    const bits = 1024;
    const { publicParams, privateParams } = await crypto.generateParams(openpgp.enums.publicKey.rsaSign, bits);
    const { n, e, d, p, q, u } = { ...publicParams, ...privateParams };
    const message = await random.getRandomBytes(64);
    const hashName = 'sha256';
    const hash_algo = openpgp.enums.write(openpgp.enums.hash, hashName);
    const hashed = await crypto.hash.digest(hash_algo, message);
    enableNative();
    const signatureNative = await crypto.publicKey.rsa.sign(hash_algo, message, n, e, d, p, q, u, hashed);
    disableNative();
    const signatureBN = await crypto.publicKey.rsa.sign(hash_algo, message, n, e, d, p, q, u, hashed);
    expect(util.uint8ArrayToHex(signatureNative)).to.be.equal(util.uint8ArrayToHex(signatureBN));
  });

  it('compare native crypto and bnVerify', async function() {
    const bits = 1024;
    const { publicParams, privateParams } = await crypto.generateParams(openpgp.enums.publicKey.rsaSign, bits);
    const { n, e, d, p, q, u } = { ...publicParams, ...privateParams };
    const message = await random.getRandomBytes(64);
    const hashName = 'sha256';
    const hash_algo = openpgp.enums.write(openpgp.enums.hash, hashName);
    const hashed = await crypto.hash.digest(hash_algo, message);
    enableNative();
    const signatureNative = await crypto.publicKey.rsa.sign(hash_algo, message, n, e, d, p, q, u, hashed);
    const verifyNative = await crypto.publicKey.rsa.verify(hash_algo, message, signatureNative, n, e);
    disableNative();
    const verifyBN = await crypto.publicKey.rsa.verify(hash_algo, message, signatureNative, n, e, hashed);
    expect(verifyNative).to.be.true;
    expect(verifyBN).to.be.true;
  });
});
