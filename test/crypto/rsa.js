const openpgp = typeof window !== 'undefined' && window.openpgp ? window.openpgp : require('../..');
const crypto = require('../../src/crypto');
const random = require('../../src/crypto/random');
const util = require('../../src/util');

const chai = require('chai');

chai.use(require('chai-as-promised'));

const expect = chai.expect;

/* eslint-disable no-unused-expressions */
/* eslint-disable no-invalid-this */
const native = util.getWebCrypto() || util.getNodeCrypto();
module.exports = () => (!native ? describe.skip : describe)('basic RSA cryptography with native crypto', function () {
  it('generate rsa key', async function() {
    const bits = util.getWebCryptoAll() ? 2048 : 1024;
    const keyObject = await crypto.publicKey.rsa.generate(bits, 65537);
    expect(keyObject.n).to.exist;
    expect(keyObject.e).to.exist;
    expect(keyObject.d).to.exist;
    expect(keyObject.p).to.exist;
    expect(keyObject.q).to.exist;
    expect(keyObject.u).to.exist;
  });

  it('sign and verify using generated key params', async function() {
    const bits = util.getWebCryptoAll() ? 2048 : 1024;
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
    const bits = util.getWebCryptoAll() ? 2048 : 1024;
    const { publicParams, privateParams } = await crypto.generateParams(openpgp.enums.publicKey.rsaSign, bits);
    const { n, e, d, p, q, u } = { ...publicParams, ...privateParams };
    const message = await crypto.generateSessionKey('aes256');
    const encrypted = await crypto.publicKey.rsa.encrypt(message, n, e);
    const decrypted = await crypto.publicKey.rsa.decrypt(encrypted, n, e, d, p, q, u);
    expect(decrypted).to.deep.equal(message);
  });

  it('decrypt nodeCrypto by bnCrypto and vice versa', async function() {
    if (!util.getNodeCrypto()) {
      this.skip();
    }
    const bits = 1024;
    const { publicParams, privateParams } = await crypto.generateParams(openpgp.enums.publicKey.rsaSign, bits);
    const { n, e, d, p, q, u } = { ...publicParams, ...privateParams };
    const message = await crypto.generateSessionKey('aes256');
    const useNative = openpgp.config.useNative;
    try {
      openpgp.config.useNative = false;
      const encryptedBn = await crypto.publicKey.rsa.encrypt(message, n, e);
      openpgp.config.useNative = true;
      const decrypted1 = await crypto.publicKey.rsa.decrypt(encryptedBn, n, e, d, p, q, u);
      expect(decrypted1).to.deep.equal(message);
      const encryptedNode = await crypto.publicKey.rsa.encrypt(message, n, e);
      openpgp.config.useNative = false;
      const decrypted2 = await crypto.publicKey.rsa.decrypt(encryptedNode, n, e, d, p, q, u);
      expect(decrypted2).to.deep.equal(message);
    } finally {
      openpgp.config.useNative = useNative;
    }
  });

  it('compare native crypto and bn math sign', async function() {
    const bits = util.getWebCrypto() ? 2048 : 1024;
    const { publicParams, privateParams } = await crypto.generateParams(openpgp.enums.publicKey.rsaSign, bits);
    const { n, e, d, p, q, u } = { ...publicParams, ...privateParams };
    const message = await random.getRandomBytes(64);
    const hashName = 'sha256';
    const hash_algo = openpgp.enums.write(openpgp.enums.hash, hashName);
    const hashed = await crypto.hash.digest(hash_algo, message);
    const useNative = openpgp.config.useNative;
    try {
      openpgp.config.useNative = true;
      let signatureWeb;
      try {
        signatureWeb = await crypto.publicKey.rsa.sign(hash_algo, message, n, e, d, p, q, u, hashed);
      } catch (error) {
        util.printDebugError('web crypto error');
        this.skip();
      }
      openpgp.config.useNative = false;
      const signatureBN = await crypto.publicKey.rsa.sign(hash_algo, message, n, e, d, p, q, u, hashed);
      expect(util.uint8ArrayToHex(signatureWeb)).to.be.equal(util.uint8ArrayToHex(signatureBN));
    } finally {
      openpgp.config.useNative = useNative;
    }
  });

  it('compare native crypto and bn math verify', async function() {
    const bits = util.getWebCrypto() ? 2048 : 1024;
    const { publicParams, privateParams } = await crypto.generateParams(openpgp.enums.publicKey.rsaSign, bits);
    const { n, e, d, p, q, u } = { ...publicParams, ...privateParams };
    const message = await random.getRandomBytes(64);
    const hashName = 'sha256';
    const hash_algo = openpgp.enums.write(openpgp.enums.hash, hashName);
    const hashed = await crypto.hash.digest(hash_algo, message);
    let verifyWeb;
    let signature;
    const useNative = openpgp.config.useNative;
    try {
      openpgp.config.useNative = true;
      try {
        signature = await crypto.publicKey.rsa.sign(hash_algo, message, n, e, d, p, q, u, hashed);
        verifyWeb = await crypto.publicKey.rsa.verify(hash_algo, message, signature, n, e);
      } catch (error) {
        util.printDebugError('web crypto error');
        this.skip();
      }
      openpgp.config.useNative = false;
      const verifyBN = await crypto.publicKey.rsa.verify(hash_algo, message, signature, n, e, hashed);
      expect(verifyWeb).to.be.true;
      expect(verifyBN).to.be.true;
    } finally {
      openpgp.config.useNative = useNative;
    }
  });
});
