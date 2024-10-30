import sinon from 'sinon';
import { use as chaiUse, expect } from 'chai';
import chaiAsPromised from 'chai-as-promised'; // eslint-disable-line import/newline-after-import
chaiUse(chaiAsPromised);

import openpgp from '../initOpenpgp.js';
import crypto from '../../src/crypto';
import * as random from '../../src/crypto/random.js';
import util from '../../src/util.js';

/* eslint-disable no-invalid-this */
export default () => describe('basic RSA cryptography', function () {
  let sinonSandbox;
  let getWebCryptoStub;
  let getNodeCryptoStub;

  beforeEach(function () {
    sinonSandbox = sinon.createSandbox();
    enableNative();
  });

  afterEach(function () {
    sinonSandbox.restore();
  });

  const detectNative = () => !!(util.getWebCrypto() || util.getNodeCrypto());

  const disableNative = () => {
    enableNative();
    // stubbed functions return undefined
    getWebCryptoStub = sinonSandbox.stub(util, 'getWebCrypto');
    getNodeCryptoStub = sinonSandbox.stub(util, 'getNodeCrypto');
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
    expect(util.uint8ArrayBitLength(keyObject.n)).to.equal(bits);
  });

  it('generate rsa key - without native crypto', async function() {
    const bits = 1024;
    disableNative();
    const keyObject = await crypto.publicKey.rsa.generate(bits, 65537);
    enableNative();
    expect(keyObject.n).to.exist;
    expect(keyObject.e).to.exist;
    expect(keyObject.d).to.exist;
    expect(keyObject.p).to.exist;
    expect(keyObject.q).to.exist;
    expect(keyObject.u).to.exist;
    expect(util.uint8ArrayBitLength(keyObject.n)).to.equal(bits);
  });

  it('sign and verify using generated key params', async function() {
    const bits = 1024;
    const { publicParams, privateParams } = await crypto.generateParams(openpgp.enums.publicKey.rsaSign, bits);
    const message = random.getRandomBytes(64);
    const hashAlgo = openpgp.enums.write(openpgp.enums.hash, 'sha256');
    const hashed = await crypto.hash.digest(hashAlgo, message);
    const { n, e, d, p, q, u } = { ...publicParams, ...privateParams };
    const signature = await crypto.publicKey.rsa.sign(hashAlgo, message, n, e, d, p, q, u, hashed);
    expect(signature).to.exist;
    const verify = await crypto.publicKey.rsa.verify(hashAlgo, message, signature, n, e, hashed);
    expect(verify).to.be.true;
  });

  it('encrypt and decrypt using generated key params', async function() {
    const bits = 1024;
    const { publicParams, privateParams } = await crypto.generateParams(openpgp.enums.publicKey.rsaSign, bits);
    const { n, e, d, p, q, u } = { ...publicParams, ...privateParams };
    const message = crypto.generateSessionKey(openpgp.enums.symmetric.aes256);
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
    const message = crypto.generateSessionKey(openpgp.enums.symmetric.aes256);
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
    if (!detectNative()) { this.skip(); }

    const bits = 1024;
    const { publicParams, privateParams } = await crypto.generateParams(openpgp.enums.publicKey.rsaSign, bits);
    const { n, e, d, p, q, u } = { ...publicParams, ...privateParams };
    const message = random.getRandomBytes(64);
    const hashName = 'sha256';
    const hashAlgo = openpgp.enums.write(openpgp.enums.hash, hashName);
    const hashed = await crypto.hash.digest(hashAlgo, message);
    enableNative();
    const signatureNative = await crypto.publicKey.rsa.sign(hashAlgo, message, n, e, d, p, q, u, hashed);
    disableNative();
    const signatureBN = await crypto.publicKey.rsa.sign(hashAlgo, message, n, e, d, p, q, u, hashed);
    expect(util.uint8ArrayToHex(signatureNative)).to.be.equal(util.uint8ArrayToHex(signatureBN));
  });

  it('compare native crypto and bnSign: throw on key size shorter than digest size', async function() {
    if (!detectNative()) { this.skip(); }

    const bits = 512;
    const hashName = 'sha512'; // digest too long for a 512-bit key
    const { publicParams, privateParams } = await crypto.generateParams(openpgp.enums.publicKey.rsaSign, bits);
    const { n, e, d, p, q, u } = { ...publicParams, ...privateParams };
    const message = random.getRandomBytes(64);
    const hashAlgo = openpgp.enums.write(openpgp.enums.hash, hashName);
    const hashed = await crypto.hash.digest(hashAlgo, message);
    enableNative();
    await expect(crypto.publicKey.rsa.sign(hashAlgo, message, n, e, d, p, q, u, hashed)).to.be.rejectedWith(/Digest size cannot exceed key modulus size/);
    disableNative();
    await expect(crypto.publicKey.rsa.sign(hashAlgo, message, n, e, d, p, q, u, hashed)).to.be.rejectedWith(/Digest size cannot exceed key modulus size/);
  });

  it('compare native crypto and bnVerify', async function() {
    if (!detectNative()) { this.skip(); }

    const bits = 1024;
    const { publicParams, privateParams } = await crypto.generateParams(openpgp.enums.publicKey.rsaSign, bits);
    const { n, e, d, p, q, u } = { ...publicParams, ...privateParams };
    const message = random.getRandomBytes(64);
    const hashName = 'sha256';
    const hashAlgo = openpgp.enums.write(openpgp.enums.hash, hashName);
    const hashed = await crypto.hash.digest(hashAlgo, message);
    enableNative();
    const signatureNative = await crypto.publicKey.rsa.sign(hashAlgo, message, n, e, d, p, q, u, hashed);
    const verifyNative = await crypto.publicKey.rsa.verify(hashAlgo, message, signatureNative, n, e);
    disableNative();
    const verifyBN = await crypto.publicKey.rsa.verify(hashAlgo, message, signatureNative, n, e, hashed);
    expect(verifyNative).to.be.true;
    expect(verifyBN).to.be.true;
  });
});
