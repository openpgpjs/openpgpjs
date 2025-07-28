import sinon from 'sinon';
import { use as chaiUse, expect } from 'chai';
import chaiAsPromised from 'chai-as-promised'; // eslint-disable-line import/newline-after-import
chaiUse(chaiAsPromised);

import openpgp from '../initOpenpgp.js';
import * as elliptic_curves from '../../src/crypto/public_key/elliptic/index.js';
import { computeDigest } from '../../src/crypto/hash/index.js';
import config from '../../src/config/index.js';
import util from '../../src/util.js';

import elliptic_data from './elliptic_data.js';
import OID from '../../src/type/oid.js';
import { getRandomBytes } from '../../src/crypto/random.js';

/**
 * Test that the result of `signFunction` can be verified by `verifyFunction`
 * with and without native crypto support.
 * @param signFunction - `(data: Uint8Array) => signFunctionResult`
 * @param verifyFunction - `(encryptFunctionResult) => <decryption result>`
 * @param expectNative - whether native usage is expected for the algorithm
 */
const testRountripWithAndWithoutNative = async (
  { sinonSandbox, enableNative, disableNative },
  signFunction,
  verifyFunction, // (signFunctionResult) => verification result
  expectNative
) => {
  const nodeCrypto = util.getNodeCrypto();
  const webCrypto = util.getWebCrypto();
  const data = getRandomBytes(16);
  const dataDigest = await computeDigest(openpgp.enums.hash.sha512, data);

  const nativeSpySign = webCrypto ? sinonSandbox.spy(webCrypto, 'sign') : sinonSandbox.spy(nodeCrypto, 'createSign');
  const nativeResult = await signFunction(data, dataDigest);
  const expectedNativeSignCallCount = nativeSpySign.callCount;
  disableNative();
  const nonNativeResult = await signFunction(data, dataDigest);
  expect(nativeSpySign.callCount).to.equal(expectedNativeSignCallCount); // assert that fallback implementation was called
  if (expectNative) {
    expect(nativeSpySign.calledOnce).to.be.true;
  }

  const nativeSpyVerify = webCrypto ? sinonSandbox.spy(webCrypto, 'verify') : sinonSandbox.spy(nodeCrypto, 'createVerify');
  enableNative();
  expect(await verifyFunction(nativeResult, data, dataDigest)).to.be.true;
  expect(await verifyFunction(nonNativeResult, data, dataDigest)).to.be.true;
  const expectedNativeVerifyCallCount = nativeSpyVerify.callCount;
  disableNative();
  expect(await verifyFunction(nativeResult, data, dataDigest)).to.be.true;
  expect(await verifyFunction(nonNativeResult, data, dataDigest)).be.true;
  expect(nativeSpyVerify.callCount).to.equal(expectedNativeVerifyCallCount); // assert that fallback implementation was called
  if (expectNative) {
    expect(nativeSpyVerify.callCount).to.equal(2);
  }
};

const key_data = elliptic_data.key_data;
export default () => describe('ECC signatures', function () {
  const signature_data = {
    priv: new Uint8Array([
      0x14, 0x2B, 0xE2, 0xB7, 0x4D, 0xBD, 0x1B, 0x22,
      0x4D, 0xDF, 0x96, 0xA4, 0xED, 0x8E, 0x5B, 0xF9,
      0xBD, 0xD3, 0xFE, 0xAE, 0x3F, 0xB2, 0xCF, 0xEE,
      0xA7, 0xDB, 0xD0, 0x58, 0xA7, 0x47, 0xF8, 0x7C
    ]),
    pub: new Uint8Array([
      0x04,
      0xD3, 0x36, 0x11, 0xF9, 0xF9, 0xAB, 0x39, 0x23,
      0x15, 0xB9, 0x71, 0x7B, 0x2A, 0x0B, 0xA6, 0x6D,
      0x39, 0x6D, 0x64, 0x87, 0x22, 0x9A, 0xA3, 0x0A,
      0x55, 0x27, 0x14, 0x2E, 0x1C, 0x61, 0xA2, 0x8A,
      0xDA, 0x4E, 0x8F, 0xCE, 0x04, 0xBE, 0xE2, 0xC3,
      0x82, 0x0B, 0x21, 0x4C, 0xBC, 0xED, 0x0E, 0xE2,
      0xF1, 0x14, 0x33, 0x9A, 0x86, 0x5F, 0xC6, 0xF9,
      0x8E, 0x95, 0x24, 0x10, 0x1F, 0x0F, 0x13, 0xE4
    ]),
    message: new Uint8Array([
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
      0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    ]),
    hashed: new Uint8Array([
      0xbe, 0x45, 0xcb, 0x26, 0x05, 0xbf, 0x36, 0xbe,
      0xbd, 0xe6, 0x84, 0x84, 0x1a, 0x28, 0xf0, 0xfd,
      0x43, 0xc6, 0x98, 0x50, 0xa3, 0xdc, 0xe5, 0xfe,
      0xdb, 0xa6, 0x99, 0x28, 0xee, 0x3a, 0x89, 0x91
    ]),
    signature: {
      r: new Uint8Array([
        0xF1, 0x78, 0x1C, 0xA5, 0x13, 0x21, 0x0C, 0xBA,
        0x6F, 0x18, 0x5D, 0xB3, 0x01, 0xE2, 0x17, 0x1B,
        0x67, 0x65, 0x7F, 0xC6, 0x1F, 0x50, 0x12, 0xFB,
        0x2F, 0xD3, 0xA4, 0x29, 0xE3, 0xC2, 0x44, 0x9F
      ]),
      s: new Uint8Array([
        0x7F, 0x08, 0x69, 0x6D, 0xBB, 0x1B, 0x9B, 0xF2,
        0x62, 0x1C, 0xCA, 0x80, 0xC6, 0x15, 0xB2, 0xAE,
        0x60, 0x50, 0xD1, 0xA7, 0x1B, 0x32, 0xF3, 0xB1,
        0x01, 0x0B, 0xDF, 0xC6, 0xAB, 0xF0, 0xEB, 0x01
      ])
    }
  };
  describe('Basic Operations', function () {
    it('Creating curve from name or oid', function (done) {
      Object.keys(openpgp.enums.curve).forEach(function(name_or_oid) {
        expect(new elliptic_curves.CurveWithOID(name_or_oid)).to.exist;
      });
      Object.values(openpgp.enums.curve).forEach(function(name_or_oid) {
        expect(new elliptic_curves.CurveWithOID(name_or_oid)).to.exist;
      });
      done();
    });
    it('Creating KeyPair', function () {
      if (!config.useEllipticFallback && !util.getNodeCrypto()) {
        this.skip();
      }
      const names = config.useEllipticFallback ? ['nistP256', 'nistP384', 'nistP521', 'secp256k1', 'curve25519Legacy', 'brainpoolP256r1', 'brainpoolP384r1', 'brainpoolP512r1'] :
        ['nistP256', 'nistP384', 'nistP521', 'curve25519Legacy'];
      return Promise.all(names.map(function (name) {
        const curve = new elliptic_curves.CurveWithOID(name);
        return curve.genKeyPair().then(keyPair => {
          expect(keyPair).to.exist;
        });
      }));
    });
    it('Signature verification', async function () {
      const curve = new elliptic_curves.CurveWithOID('nistP256');
      await expect(
        elliptic_curves.ecdsa.verify(new OID(curve.oid), 8, signature_data.signature, signature_data.message, signature_data.pub, signature_data.hashed)
      ).to.eventually.be.true;
    });
    it('Invalid signature', async function () {
      const curve = new elliptic_curves.CurveWithOID('nistP256');
      await expect(
        elliptic_curves.ecdsa.verify(new OID(curve.oid), 8, signature_data.signature, signature_data.message, key_data.nistP256.pub, signature_data.hashed)
      ).to.eventually.be.false;
    });
    it('Signature generation', async function () {
      const curve = new elliptic_curves.CurveWithOID('nistP256');
      const oid = new OID(curve.oid);
      const signature = await elliptic_curves.ecdsa.sign(oid, 8, signature_data.message, key_data.nistP256.pub, key_data.nistP256.priv, signature_data.hashed);
      await expect(
        elliptic_curves.ecdsa.verify(oid, 8, signature, signature_data.message, key_data.nistP256.pub, signature_data.hashed)
      ).to.eventually.be.true;
    });
  });
  describe('ECDSA signature', function () {
    let sinonSandbox;
    let getWebCryptoStub;
    let getNodeCryptoStub;

    beforeEach(function () {
      sinonSandbox = sinon.createSandbox();
    });

    afterEach(function () {
      sinonSandbox.restore();
    });

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

    const testNativeAndFallback = async fn => {
      const webCrypto = util.getWebCrypto();
      const nodeCrypto = util.getNodeCrypto();
      const nativeSpy = webCrypto ? sinonSandbox.spy(webCrypto, 'importKey') : sinonSandbox.spy(nodeCrypto, 'createVerify'); // spy on function used on verification, since that's used by all tests calling `testNativeAndFallback`

      // if native not available, fallback will be tested twice (not possible to automatically check native algo availability)
      enableNative();
      await fn();
      const expectedNativeCallCount = nativeSpy.callCount;
      disableNative();
      await fn();
      expect(nativeSpy.callCount).to.equal(expectedNativeCallCount);
      enableNative();
    };

    const verify_signature = async function (curveName, hash, r, s, message, pub) {
      if (util.isString(message)) {
        message = util.stringToUint8Array(message);
      } else if (!util.isUint8Array(message)) {
        message = new Uint8Array(message);
      }
      const ecdsa = elliptic_curves.ecdsa;
      const curve = new elliptic_curves.CurveWithOID(curveName);
      const oid = new OID(curve.oid);
      return ecdsa.verify(
        oid, hash, { r: new Uint8Array(r), s: new Uint8Array(s) }, message, new Uint8Array(pub), await computeDigest(hash, message)
      );
    };
    const secp256k1_point = new Uint8Array([
      0x04,
      0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC,
      0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07,
      0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9,
      0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98,
      0x48, 0x3A, 0xDA, 0x77, 0x26, 0xA3, 0xC4, 0x65,
      0x5D, 0xA4, 0xFB, 0xFC, 0x0E, 0x11, 0x08, 0xA8,
      0xFD, 0x17, 0xB4, 0x48, 0xA6, 0x85, 0x54, 0x19,
      0x9C, 0x47, 0xD0, 0x8F, 0xFB, 0x10, 0xD4, 0xB8
    ]);
    const secp256k1_invalid_point = new Uint8Array([
      0x04,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ]);
    const secp256k1_invalid_point_format = new Uint8Array([
      0x04,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ]);
    it('Invalid curve oid', async function () {
      await expect(verify_signature(
        'invalid oid', 8, [], [], [], []
      )).to.be.rejectedWith(Error, /Unknown curve/);
      await expect(verify_signature(
        '\x00', 8, [], [], [], []
      )).to.be.rejectedWith(Error, /Unknown curve/);
    });
    it('secp256k1 - Invalid public key', async function () {
      if (!config.useEllipticFallback && !util.getNodeCrypto()) {
        this.skip(); // webcrypto does not implement secp256k1: JS fallback tested instead
      }
      await expect(verify_signature(
        'secp256k1', 8, [], [], [], []
      )).to.be.rejectedWith(/Invalid point encoding/);
      await expect(verify_signature(
        'secp256k1', 8, [], [], [], secp256k1_invalid_point_format
      )).to.be.rejectedWith(/Invalid point encoding/);
      await expect(verify_signature(
        'secp256k1', 8, [], [], [], secp256k1_invalid_point
      )).to.eventually.be.false;
    });
    it('secp256k1 - Invalid signature', function (done) {
      if (!config.useEllipticFallback && !util.getNodeCrypto()) {
        this.skip(); // webcrypto does not implement secp256k1: JS fallback tested instead
      }
      expect(verify_signature(
        'secp256k1', 8, [], [], [], secp256k1_point
      )).to.eventually.be.false.notify(done);
    });

    it('P-384 - Valid signature', async function () {
      const p384_r = new Uint8Array([
        0x9D, 0x07, 0xCA, 0xA5, 0x9F, 0xBE, 0xB8, 0x76,
        0xA9, 0xB9, 0x66, 0x0F, 0xA0, 0x64, 0x70, 0x5D,
        0xE6, 0x37, 0x40, 0x43, 0xD0, 0x8E, 0x40, 0xA8,
        0x8B, 0x37, 0x83, 0xE7, 0xBC, 0x1C, 0x4C, 0x86,
        0xCB, 0x3C, 0xD5, 0x9B, 0x68, 0xF0, 0x65, 0xEB,
        0x3A, 0xB6, 0xD6, 0xA6, 0xCF, 0x85, 0x3D, 0xA9
      ]);
      const p384_s = new Uint8Array([
        0x32, 0x85, 0x78, 0xCC, 0xEA, 0xC5, 0x22, 0x83,
        0x10, 0x73, 0x1C, 0xCF, 0x10, 0x8A, 0x52, 0x11,
        0x8E, 0x49, 0x9E, 0xCF, 0x7E, 0x17, 0x18, 0xC3,
        0x11, 0x11, 0xBC, 0x0F, 0x6D, 0x98, 0xE2, 0x16,
        0x68, 0x58, 0x23, 0x1D, 0x11, 0xEF, 0x3D, 0x21,
        0x30, 0x75, 0x24, 0x39, 0x48, 0x89, 0x03, 0xDC
      ]);
      const p384_message = new Uint8Array([
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
      ]);

      await testNativeAndFallback(
        () => expect(verify_signature('nistP384', 8, p384_r, p384_s, p384_message, key_data.nistP384.pub)).to.eventually.be.true
      );
    });
    const curves = ['secp256k1' , 'nistP256', 'nistP384', 'nistP521', 'brainpoolP256r1', 'brainpoolP384r1', 'brainpoolP512r1'];
    curves.forEach(curveName => it(`${curveName} - Sign and verify message with generated key`, async function () {
      const sinonState = { sinonSandbox, enableNative, disableNative };

      const curve = new elliptic_curves.CurveWithOID(curveName);
      const oid = new OID(curve.oid);
      const expectNativeWeb = new Set(['nistP256', 'nistP384']); // older versions of safari do not implement nistP521

      const nativeKey = await elliptic_curves.generate(curveName);
      await testRountripWithAndWithoutNative(
        sinonState,
        (data, dataDigest) => elliptic_curves.ecdsa.sign(oid, openpgp.enums.hash.sha512, data, nativeKey.Q, nativeKey.secret, dataDigest),
        (signature, data, dataDigest) => elliptic_curves.ecdsa.verify(oid, openpgp.enums.hash.sha512, signature, data, nativeKey.Q, dataDigest),
        expectNativeWeb.has(curveName)
      );

      sinonSandbox.restore(); // reset spies
      disableNative();
      const nonNativeKey = await elliptic_curves.generate(curveName);
      enableNative();
      await testRountripWithAndWithoutNative(
        sinonState,
        (data, dataDigest) => elliptic_curves.ecdsa.sign(oid, openpgp.enums.hash.sha512, data, nonNativeKey.Q, nonNativeKey.secret, dataDigest),
        (signature, data, dataDigest) => elliptic_curves.ecdsa.verify(oid, openpgp.enums.hash.sha512, signature, data, nonNativeKey.Q, dataDigest),
        expectNativeWeb.has(curveName)
      );
    }));
  });

  describe('EdDSA signature', function () {
    let sinonSandbox;
    let getWebCryptoStub;
    let getNodeCryptoStub;

    beforeEach(function () {
      sinonSandbox = sinon.createSandbox();
    });

    afterEach(function () {
      sinonSandbox.restore();
    });

    const disableNative = () => {
      enableNative();
      // stubbed functions return undefined
      getWebCryptoStub = sinonSandbox.stub(util, 'getWebCrypto').returns({
        generateKey: () => { const e = new Error('getWebCrypto is mocked'); e.name = 'NotSupportedError'; throw e; },
        importKey: () => { const e = new Error('getWebCrypto is mocked'); e.name = 'NotSupportedError'; throw e; }
      });
      getNodeCryptoStub = sinonSandbox.stub(util, 'getNodeCrypto');
    };
    const enableNative = () => {
      getWebCryptoStub && getWebCryptoStub.restore();
      getNodeCryptoStub && getNodeCryptoStub.restore();
    };

    it('ed25519Legacy - Sign and verify message with generated key', async function () {
      const sinonState = { sinonSandbox, enableNative, disableNative };
      const curve = new elliptic_curves.CurveWithOID(openpgp.enums.curve.ed25519Legacy);
      const oid = new OID(curve.oid);

      const nativeKey = await elliptic_curves.generate(openpgp.enums.curve.ed25519Legacy);
      await testRountripWithAndWithoutNative(
        sinonState,
        (data, dataDigest) => elliptic_curves.eddsaLegacy.sign(oid, openpgp.enums.hash.sha512, data, nativeKey.Q, nativeKey.secret, dataDigest),
        (signature, data, dataDigest) => elliptic_curves.eddsaLegacy.verify(oid, openpgp.enums.hash.sha512, signature, data, nativeKey.Q, dataDigest)
      );

      sinonSandbox.restore(); // reset spies
      disableNative();
      const nonNativeKey = await elliptic_curves.generate(openpgp.enums.curve.ed25519Legacy);
      enableNative();
      await testRountripWithAndWithoutNative(
        sinonState,
        (data, dataDigest) => elliptic_curves.eddsaLegacy.sign(oid, openpgp.enums.hash.sha512, data, nonNativeKey.Q, nonNativeKey.secret, dataDigest),
        (signature, data, dataDigest) => elliptic_curves.eddsaLegacy.verify(oid, openpgp.enums.hash.sha512, signature, data, nonNativeKey.Q, dataDigest)
      );
    });

    ['ed25519', 'ed448'].forEach(algoName => it(`${algoName} - Sign and verify message with native generated key`, async function () {
      const sinonState = { sinonSandbox, enableNative, disableNative };
      const algo = openpgp.enums.publicKey[algoName];
      const nativeKey = await elliptic_curves.eddsa.generate(algo);
      await testRountripWithAndWithoutNative(
        sinonState,
        (data, dataDigest) => elliptic_curves.eddsa.sign(algo, openpgp.enums.hash.sha512, data, nativeKey.A, nativeKey.seed, dataDigest),
        (signature, data, dataDigest) => elliptic_curves.eddsa.verify(algo, openpgp.enums.hash.sha512, signature, data, nativeKey.A, dataDigest)
      );

      sinonSandbox.restore(); // reset spies
      disableNative();
      const nonNativeKey = await elliptic_curves.eddsa.generate(algo);
      enableNative();
      await testRountripWithAndWithoutNative(
        sinonState,
        (data, dataDigest) => elliptic_curves.eddsa.sign(algo, openpgp.enums.hash.sha512, data, nonNativeKey.A, nonNativeKey.seed, dataDigest),
        (signature, data, dataDigest) => elliptic_curves.eddsa.verify(algo, openpgp.enums.hash.sha512, signature, data, nonNativeKey.A, dataDigest)
      );
    }));
  });
});
