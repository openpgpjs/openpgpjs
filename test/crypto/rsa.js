const openpgp = typeof window !== 'undefined' && window.openpgp ? window.openpgp : require('../../dist/openpgp');
const chai = require('chai');

chai.use(require('chai-as-promised'));

const expect = chai.expect;

/* eslint-disable no-unused-expressions */
/* eslint-disable no-invalid-this */
const native = openpgp.util.getWebCrypto() || openpgp.util.getNodeCrypto();
(!native ? describe.skip : describe)('basic RSA cryptography with native crypto', function () {
  it('generate rsa key', async function() {
    const bits = openpgp.util.getWebCryptoAll() ? 2048 : 1024;
    const keyObject = await openpgp.crypto.publicKey.rsa.generate(bits, "10001");
    expect(keyObject.n).to.exist;
    expect(keyObject.e).to.exist;
    expect(keyObject.d).to.exist;
    expect(keyObject.p).to.exist;
    expect(keyObject.q).to.exist;
    expect(keyObject.u).to.exist;
  });

  it('sign and verify using generated key params', async function() {
    const bits = openpgp.util.getWebCryptoAll() ? 2048 : 1024;
    const keyParams = await openpgp.crypto.generateParams(openpgp.enums.publicKey.rsa_sign, bits);
    const message = await openpgp.crypto.random.getRandomBytes(64);
    const hash_algo = openpgp.enums.write(openpgp.enums.hash, 'sha256');
    const hashed = await openpgp.crypto.hash.digest(hash_algo, message);
    const n = keyParams[0].toUint8Array();
    const e = keyParams[1].toUint8Array();
    const d = keyParams[2].toUint8Array();
    const p = keyParams[3].toUint8Array();
    const q = keyParams[4].toUint8Array();
    const u = keyParams[5].toUint8Array();
    const signature = await openpgp.crypto.publicKey.rsa.sign(hash_algo, message, n, e, d, p, q, u, hashed);
    expect(signature).to.exist;
    const verify = await openpgp.crypto.publicKey.rsa.verify(hash_algo, message, signature, n, e, hashed);
    expect(verify).to.be.true;
  });

  it('encrypt and decrypt using generated key params', async function() {
    const bits = openpgp.util.getWebCryptoAll() ? 2048 : 1024;
    const keyParams = await openpgp.crypto.generateParams(openpgp.enums.publicKey.rsa_sign, bits);
    const n = keyParams[0].toUint8Array();
    const e = keyParams[1].toUint8Array();
    const d = keyParams[2].toUint8Array();
    const p = keyParams[3].toUint8Array();
    const q = keyParams[4].toUint8Array();
    const u = keyParams[5].toUint8Array();
    const message = openpgp.util.Uint8Array_to_str(await openpgp.crypto.generateSessionKey('aes256'));
    const encrypted = await openpgp.crypto.publicKey.rsa.encrypt(openpgp.util.str_to_Uint8Array(message), n, e);
    const result = new openpgp.MPI(encrypted);
    const decrypted = await openpgp.crypto.publicKey.rsa.decrypt(result.toUint8Array(), n, e, d, p, q, u);
    expect(decrypted).to.be.equal(message);
  });

  it('decrypt nodeCrypto by bnCrypto and vice versa', async function() {
    if (!openpgp.util.getNodeCrypto()) {
      this.skip();
    }
    const bits = 1024;
    const keyParams = await openpgp.crypto.generateParams(openpgp.enums.publicKey.rsa_sign, bits);
    const n = keyParams[0].toUint8Array();
    const e = keyParams[1].toUint8Array();
    const d = keyParams[2].toUint8Array();
    const p = keyParams[3].toUint8Array();
    const q = keyParams[4].toUint8Array();
    const u = keyParams[5].toUint8Array();
    const message = openpgp.util.Uint8Array_to_str(await openpgp.crypto.generateSessionKey('aes256'));
    const encryptedBn = await openpgp.crypto.publicKey.rsa.bnEncrypt(openpgp.util.str_to_Uint8Array(message), n, e);
    const resultBN = new openpgp.MPI(encryptedBn);
    const decrypted1 = await openpgp.crypto.publicKey.rsa.nodeDecrypt(resultBN.toUint8Array(), n, e, d, p, q, u);
    expect(decrypted1).to.be.equal(message);
    const encryptedNode = await openpgp.crypto.publicKey.rsa.nodeEncrypt(openpgp.util.str_to_Uint8Array(message), n, e);
    const resultNode = new openpgp.MPI(encryptedNode);
    const decrypted2 = await openpgp.crypto.publicKey.rsa.bnDecrypt(resultNode.toUint8Array(), n, e, d, p, q, u);
    expect(decrypted2).to.be.equal(message);
  });

  it('compare webCrypto and bn math sign', async function() {
    if (!openpgp.util.getWebCrypto()) {
      this.skip();
    }
    const bits = openpgp.util.getWebCrypto() ? 2048 : 1024;
    const keyParams = await openpgp.crypto.generateParams(openpgp.enums.publicKey.rsa_sign, bits);
    const n = keyParams[0].toUint8Array();
    const e = keyParams[1].toUint8Array();
    const d = keyParams[2].toUint8Array();
    const p = keyParams[3].toUint8Array();
    const q = keyParams[4].toUint8Array();
    const u = keyParams[5].toUint8Array();
    const message = await openpgp.crypto.random.getRandomBytes(64);
    const hashName = 'sha256';
    const hash_algo = openpgp.enums.write(openpgp.enums.hash, hashName);
    const hashed = await openpgp.crypto.hash.digest(hash_algo, message);
    let signatureWeb;
    try {
      signatureWeb = await openpgp.crypto.publicKey.rsa.webSign('SHA-256', message, n, e, d, p, q, u, hashed);
    } catch (error) {
      openpgp.util.print_debug_error('web crypto error');
      this.skip();
    }
    const signatureBN = await openpgp.crypto.publicKey.rsa.bnSign(hash_algo, n, d, hashed);
    expect(openpgp.util.Uint8Array_to_hex(signatureWeb)).to.be.equal(openpgp.util.Uint8Array_to_hex(signatureBN));
  });

  it('compare webCrypto and bn math verify', async function() {
    if (!openpgp.util.getWebCrypto()) {
      this.skip();
    }
    const bits = openpgp.util.getWebCrypto() ? 2048 : 1024;
    const keyParams = await openpgp.crypto.generateParams(openpgp.enums.publicKey.rsa_sign, bits);
    const n = keyParams[0].toUint8Array();
    const e = keyParams[1].toUint8Array();
    const d = keyParams[2].toUint8Array();
    const p = keyParams[3].toUint8Array();
    const q = keyParams[4].toUint8Array();
    const u = keyParams[5].toUint8Array();
    const message = await openpgp.crypto.random.getRandomBytes(64);
    const hashName = 'sha256';
    const hash_algo = openpgp.enums.write(openpgp.enums.hash, hashName);
    const hashed = await openpgp.crypto.hash.digest(hash_algo, message);
    let verifyWeb;
    let signature;
    try {
      signature = await openpgp.crypto.publicKey.rsa.webSign('SHA-256', message, n, e, d, p, q, u, hashed);
      verifyWeb = await openpgp.crypto.publicKey.rsa.webVerify('SHA-256', message, signature, n, e);
    } catch (error) {
      openpgp.util.print_debug_error('web crypto error');
      this.skip();
    }
    const verifyBN = await openpgp.crypto.publicKey.rsa.bnVerify(hash_algo, signature, n, e, hashed);
    expect(verifyWeb).to.be.true;
    expect(verifyBN).to.be.true;
  });

  it('compare nodeCrypto and bn math sign', async function() {
    if (!openpgp.util.getNodeCrypto()) {
      this.skip();
    }
    const bits = 1024;
    const keyParams = await openpgp.crypto.generateParams(openpgp.enums.publicKey.rsa_sign, bits);
    const n = keyParams[0].toUint8Array();
    const e = keyParams[1].toUint8Array();
    const d = keyParams[2].toUint8Array();
    const p = keyParams[3].toUint8Array();
    const q = keyParams[4].toUint8Array();
    const u = keyParams[5].toUint8Array();
    const message = await openpgp.crypto.random.getRandomBytes(64);
    const hashName = 'sha256';
    const hash_algo = openpgp.enums.write(openpgp.enums.hash, hashName);
    const hashed = await openpgp.crypto.hash.digest(hash_algo, message);
    const signatureNode = await openpgp.crypto.publicKey.rsa.nodeSign(hash_algo, message, n, e, d, p, q, u);
    const signatureBN = await openpgp.crypto.publicKey.rsa.bnSign(hash_algo, n, d, hashed);
    expect(openpgp.util.Uint8Array_to_hex(signatureNode)).to.be.equal(openpgp.util.Uint8Array_to_hex(signatureBN));
  });

  it('compare nodeCrypto and bn math verify', async function() {
    if (!openpgp.util.getNodeCrypto()) {
      this.skip();
    }
    const bits = openpgp.util.getWebCrypto() ? 2048 : 1024;
    const keyParams = await openpgp.crypto.generateParams(openpgp.enums.publicKey.rsa_sign, bits);
    const n = keyParams[0].toUint8Array();
    const e = keyParams[1].toUint8Array();
    const d = keyParams[2].toUint8Array();
    const p = keyParams[3].toUint8Array();
    const q = keyParams[4].toUint8Array();
    const u = keyParams[5].toUint8Array();
    const message = await openpgp.crypto.random.getRandomBytes(64);
    const hashName = 'sha256';
    const hash_algo = openpgp.enums.write(openpgp.enums.hash, hashName);
    const hashed = await openpgp.crypto.hash.digest(hash_algo, message);
    const signatureNode = await openpgp.crypto.publicKey.rsa.nodeSign(hash_algo, message, n, e, d, p, q, u);
    const verifyNode = await openpgp.crypto.publicKey.rsa.nodeVerify(hash_algo, message, signatureNode, n, e);
    const verifyBN = await openpgp.crypto.publicKey.rsa.bnVerify(hash_algo, signatureNode, n, e, hashed);
    expect(verifyNode).to.be.true;
    expect(verifyBN).to.be.true;
  });
});
