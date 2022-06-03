const openpgp = typeof window !== 'undefined' && window.openpgp ? window.openpgp : require('../..');
const OID = require('../../src/type/oid');
const KDFParams = require('../../src/type/kdf_params');
const elliptic_curves = require('../../src/crypto/public_key/elliptic');
const util = require('../../src/util');

const sandbox = require('sinon/lib/sinon/sandbox');
const chai = require('chai');
const elliptic_data = require('./elliptic_data');

chai.use(require('chai-as-promised'));

const expect = chai.expect;
const key_data = elliptic_data.key_data;
/* eslint-disable no-invalid-this */
module.exports = () => describe('ECDH key exchange @lightweight', function () {
  const decrypt_message = function (oid, hash, cipher, priv, pub, ephemeral, data, fingerprint) {
    if (util.isString(data)) {
      data = util.stringToUint8Array(data);
    } else {
      data = new Uint8Array(data);
    }
    return Promise.resolve().then(() => {
      const curve = new elliptic_curves.Curve(oid);
      return elliptic_curves.ecdh.decrypt(
        new OID(curve.oid),
        new KDFParams({ cipher, hash }),
        new Uint8Array(ephemeral),
        data,
        new Uint8Array(pub),
        new Uint8Array(priv),
        new Uint8Array(fingerprint)
      );
    });
  };
  const secp256k1_value = new Uint8Array([
    0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  ]);
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
  const secp256k1_data = new Uint8Array([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  ]);

  it('Invalid curve oid', function (done) {
    expect(decrypt_message(
      '', 2, 7, [], [], [], [], []
    )).to.be.rejectedWith(Error, /Unknown curve/).notify(done);
  });
  it('Invalid ephemeral key', function (done) {
    if (!openpgp.config.useIndutnyElliptic && !util.getNodeCrypto()) {
      this.skip();
    }
    expect(decrypt_message(
      'secp256k1', 2, 7, [], [], [], [], []
    )).to.be.rejectedWith(Error, /Private key is not valid for specified curve|Unknown point format/).notify(done);
  });
  it('Invalid elliptic public key', function (done) {
    if (!openpgp.config.useIndutnyElliptic && !util.getNodeCrypto()) {
      this.skip();
    }
    expect(decrypt_message(
      'secp256k1', 2, 7, secp256k1_value, secp256k1_point, secp256k1_invalid_point, secp256k1_data, []
    )).to.be.rejectedWith(Error, /Public key is not valid for specified curve|Failed to translate Buffer to a EC_POINT|Invalid elliptic public key/).notify(done);
  });
  it('Invalid key data integrity', function (done) {
    if (!openpgp.config.useIndutnyElliptic && !util.getNodeCrypto()) {
      this.skip();
    }
    expect(decrypt_message(
      'secp256k1', 2, 7, secp256k1_value, secp256k1_point, secp256k1_point, secp256k1_data, []
    )).to.be.rejectedWith(Error, /Key Data Integrity failed/).notify(done);
  });

  const Q1 = new Uint8Array([
    64,
    48, 226, 162, 114, 194, 194, 67, 214,
    199, 10, 173, 22, 216, 240, 197, 202,
    114, 49, 127, 107, 152, 58, 119, 48,
    234, 194, 192, 66, 53, 165, 137, 93
  ]);
  const d1 = new Uint8Array([
    65, 200, 132, 198, 77, 86, 126, 196,
    247, 169, 156, 201, 32, 52, 3, 198,
    127, 144, 139, 47, 153, 239, 64, 235,
    61, 7, 17, 214, 64, 211, 215, 80
  ]);
  const Q2 = new Uint8Array([
    64,
    154, 115, 36, 108, 33, 153, 64, 184,
    25, 139, 67, 25, 178, 194, 227, 53,
    254, 40, 101, 213, 28, 121, 154, 62,
    27, 99, 92, 126, 33, 223, 122, 91
  ]);
  const d2 = new Uint8Array([
    123, 99, 163, 24, 201, 87, 0, 9,
    204, 21, 154, 5, 5, 5, 127, 157,
    237, 95, 76, 117, 89, 250, 64, 178,
    72, 69, 69, 58, 89, 228, 113, 112
  ]);
  const fingerprint1 = new Uint8Array([
    177, 183,
    116, 123, 76, 133, 245, 212, 151, 243, 236,
    71, 245, 86, 3, 168, 101, 56, 209, 105
  ]);
  const fingerprint2 = new Uint8Array([
    177, 83,
    123, 123, 76, 133, 245, 212, 151, 243, 236,
    71, 245, 86, 3, 168, 101, 74, 209, 105
  ]);

  describe('ECDHE key generation', function () {
    const ecdh = elliptic_curves.ecdh;

    it('Invalid curve', async function () {
      if (!openpgp.config.useIndutnyElliptic && !util.getNodeCrypto()) {
        this.skip();
      }
      const curve = new elliptic_curves.Curve('secp256k1');
      const oid = new OID(curve.oid);
      const kdfParams = new KDFParams({ hash: curve.hash, cipher: curve.cipher });
      const data = util.stringToUint8Array('test');
      expect(
        ecdh.encrypt(oid, kdfParams, data, Q1, fingerprint1)
      ).to.be.rejectedWith(Error, /Public key is not valid for specified curve|Failed to translate Buffer to a EC_POINT|Unknown point format/);
    });
    it('Different keys', async function () {
      const curve = new elliptic_curves.Curve('curve25519');
      const oid = new OID(curve.oid);
      const kdfParams = new KDFParams({ hash: curve.hash, cipher: curve.cipher });
      const data = util.stringToUint8Array('test');
      const { publicKey: V, wrappedKey: C } = await ecdh.encrypt(oid, kdfParams, data, Q1, fingerprint1);
      await expect(
        ecdh.decrypt(oid, kdfParams, V, C, Q2, d2, fingerprint1)
      ).to.be.rejectedWith(/Key Data Integrity failed/);
    });
    it('Invalid fingerprint', async function () {
      const curve = new elliptic_curves.Curve('curve25519');
      const oid = new OID(curve.oid);
      const kdfParams = new KDFParams({ hash: curve.hash, cipher: curve.cipher });
      const data = util.stringToUint8Array('test');
      const { publicKey: V, wrappedKey: C } = await ecdh.encrypt(oid, kdfParams, data, Q2, fingerprint1);
      await expect(
        ecdh.decrypt(oid, kdfParams, V, C, Q2, d2, fingerprint2)
      ).to.be.rejectedWith(/Key Data Integrity failed/);
    });
    it('Successful exchange curve25519', async function () {
      const curve = new elliptic_curves.Curve('curve25519');
      const oid = new OID(curve.oid);
      const kdfParams = new KDFParams({ hash: curve.hash, cipher: curve.cipher });
      const data = util.stringToUint8Array('test');
      const { publicKey: V, wrappedKey: C } = await ecdh.encrypt(oid, kdfParams, data, Q1, fingerprint1);
      expect(await ecdh.decrypt(oid, kdfParams, V, C, Q1, d1, fingerprint1)).to.deep.equal(data);
    });

    ['p256', 'p384', 'p521'].forEach(curveName => {
      it(`NIST ${curveName} - Successful exchange`, async function () {
        const curve = new elliptic_curves.Curve(curveName);
        const oid = new OID(curve.oid);
        const kdfParams = new KDFParams({ hash: curve.hash, cipher: curve.cipher });
        const data = util.stringToUint8Array('test');
        const Q = key_data[curveName].pub;
        const d = key_data[curveName].priv;
        const { publicKey: V, wrappedKey: C } = await ecdh.encrypt(oid, kdfParams, data, Q, fingerprint1);
        expect(await ecdh.decrypt(oid, kdfParams, V, C, Q, d, fingerprint1)).to.deep.equal(data);
      });
    });

    describe('Comparing decrypting with and without native crypto', () => {
      let sinonSandbox;
      let getWebCryptoStub;
      let getNodeCryptoStub;

      beforeEach(function () {
        sinonSandbox = sandbox.create();
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

      ['p256', 'p384', 'p521'].forEach(curveName => {
        it(`NIST ${curveName}`, async function () {
          const nodeCrypto = util.getNodeCrypto();
          const webCrypto = util.getWebCrypto();
          if (!nodeCrypto && !webCrypto) {
            this.skip();
          }

          const curve = new elliptic_curves.Curve(curveName);
          const oid = new OID(curve.oid);
          const kdfParams = new KDFParams({ hash: curve.hash, cipher: curve.cipher });
          const data = util.stringToUint8Array('test');
          const Q = key_data[curveName].pub;
          const d = key_data[curveName].priv;
          const { publicKey: V, wrappedKey: C } = await ecdh.encrypt(oid, kdfParams, data, Q, fingerprint1);

          const nativeDecryptSpy = webCrypto ? sinonSandbox.spy(webCrypto, 'deriveBits') : sinonSandbox.spy(nodeCrypto, 'createECDH');
          expect(await ecdh.decrypt(oid, kdfParams, V, C, Q, d, fingerprint1)).to.deep.equal(data);
          disableNative();
          expect(await ecdh.decrypt(oid, kdfParams, V, C, Q, d, fingerprint1)).to.deep.equal(data);
          if (curveName !== 'p521') { // safari does not implement p521 in webcrypto
            expect(nativeDecryptSpy.calledOnce).to.be.true;
          }
        });
      });
    });
  });
});
