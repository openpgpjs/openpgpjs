const openpgp = typeof window !== 'undefined' && window.openpgp ? window.openpgp : require('../../dist/openpgp');
const chai = require('chai');

chai.use(require('chai-as-promised'));

const expect = chai.expect;

/* eslint-disable no-unused-expressions */
/* eslint-disable no-invalid-this */
describe('basic RSA cryptography', function () {
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
    const message = new Uint8Array(Array.from({ length: 64 }, () => Math.floor(Math.random() * 256)));
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

  it('compare webCrypto and bn math sign', async function() {
    if (!openpgp.util.getWebCryptoAll()) {
      this.skip();
    }
    const bits = openpgp.util.getWebCryptoAll() ? 2048 : 1024;
    const keyParams = await openpgp.crypto.generateParams(openpgp.enums.publicKey.rsa_sign, bits);
    const n = keyParams[0].toUint8Array();
    const e = keyParams[1].toUint8Array();
    const d = keyParams[2].toUint8Array();
    const p = keyParams[3].toUint8Array();
    const q = keyParams[4].toUint8Array();
    const u = keyParams[5].toUint8Array();
    const message = new Uint8Array(Array.from({ length: 64 }, () => Math.floor(Math.random() * 256)));
    const hashName = 'sha256';
    const hash_algo = openpgp.enums.write(openpgp.enums.hash, hashName);
    const hashed = await openpgp.crypto.hash.digest(hash_algo, message);
    const signatureWeb = await openpgp.crypto.publicKey.rsa.webCryptoSign('SHA-256', message, n, e, d, p, q, u, hashed);
    const signatureBN = await openpgp.crypto.publicKey.rsa.bnSign(hash_algo, n, d, hashed);
    expect(openpgp.util.Uint8Array_to_hex(signatureWeb)).to.be.equal(openpgp.util.Uint8Array_to_hex(signatureBN));
  });

  it('compare webCrypto and bn math verify', async function() {
    if (!openpgp.util.getWebCryptoAll()) {
      this.skip();
    }
    const bits = openpgp.util.getWebCryptoAll() ? 2048 : 1024;
    const keyParams = await openpgp.crypto.generateParams(openpgp.enums.publicKey.rsa_sign, bits);
    const n = keyParams[0].toUint8Array();
    const e = keyParams[1].toUint8Array();
    const d = keyParams[2].toUint8Array();
    const p = keyParams[3].toUint8Array();
    const q = keyParams[4].toUint8Array();
    const u = keyParams[5].toUint8Array();
    const message = new Uint8Array(Array.from({ length: 64 }, () => Math.floor(Math.random() * 256)));
    const hashName = 'sha256';
    const hash_algo = openpgp.enums.write(openpgp.enums.hash, hashName);
    const hashed = await openpgp.crypto.hash.digest(hash_algo, message);
    const signature1 = await openpgp.crypto.publicKey.rsa.webCryptoSign('SHA-256', message, n, e, d, p, q, u, hashed);
    const signature2 = await openpgp.crypto.publicKey.rsa.bnSign(hash_algo, n, d, hashed);
    expect(openpgp.util.Uint8Array_to_hex(signature1)).to.be.equal(openpgp.util.Uint8Array_to_hex(signature2));
    const verifyWeb = await openpgp.crypto.publicKey.rsa.webCryptoVerify('SHA-256', message, signature1, n, e);
    const verifyBN = await openpgp.crypto.publicKey.rsa.bnVerify(hash_algo, signature1, n, e, hashed);
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
    const message = new Uint8Array(Array.from({ length: 64 }, () => Math.floor(Math.random() * 256)));
    const hashName = 'sha256';
    const hash_algo = openpgp.enums.write(openpgp.enums.hash, hashName);
    const hashed = await openpgp.crypto.hash.digest(hash_algo, message);
    const signatureNode = await openpgp.crypto.publicKey.rsa.nodeCryptoSign(hash_algo, message, n, e, d, p, q, u);
    const signatureBN = await openpgp.crypto.publicKey.rsa.bnSign(hash_algo, n, d, hashed);
    expect(openpgp.util.Uint8Array_to_hex(signatureNode)).to.be.equal(openpgp.util.Uint8Array_to_hex(signatureBN));
  });

  it('compare nodeCrypto and bn math verify', async function() {
    if (!openpgp.util.getNodeCrypto()) {
      this.skip();
    }
    const bits = openpgp.util.getWebCryptoAll() ? 2048 : 1024;
    const keyParams = await openpgp.crypto.generateParams(openpgp.enums.publicKey.rsa_sign, bits);
    const n = keyParams[0].toUint8Array();
    const e = keyParams[1].toUint8Array();
    const d = keyParams[2].toUint8Array();
    const p = keyParams[3].toUint8Array();
    const q = keyParams[4].toUint8Array();
    const u = keyParams[5].toUint8Array();
    const message = new Uint8Array(Array.from({ length: 64 }, () => Math.floor(Math.random() * 256)));
    const hashName = 'sha256';
    const hash_algo = openpgp.enums.write(openpgp.enums.hash, hashName);
    const hashed = await openpgp.crypto.hash.digest(hash_algo, message);
    const signatureNode = await openpgp.crypto.publicKey.rsa.nodeCryptoSign(hash_algo, message, n, e, d, p, q, u);
    const verifyNode = await openpgp.crypto.publicKey.rsa.nodeCryptoVerify(hash_algo, message, signatureNode, n, e);
    const verifyBN = await openpgp.crypto.publicKey.rsa.bnVerify(hash_algo, signatureNode, n, e, hashed);
    expect(verifyNode).to.be.true;
    expect(verifyBN).to.be.true;
  });
});
