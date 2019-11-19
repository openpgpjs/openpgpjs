const openpgp = typeof window !== 'undefined' && window.openpgp ? window.openpgp : require('../../dist/openpgp');
const chai = require('chai');

const elliptic_data = require('./elliptic_data');

chai.use(require('chai-as-promised'));

const expect = chai.expect;
const key_data = elliptic_data.key_data;
/* eslint-disable no-invalid-this */
describe('Elliptic Curve Cryptography @lightweight', function () {
  const elliptic_curves = openpgp.crypto.publicKey.elliptic;

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
        expect(new elliptic_curves.Curve(name_or_oid)).to.exist;
      });
      Object.values(openpgp.enums.curve).forEach(function(name_or_oid) {
        expect(new elliptic_curves.Curve(name_or_oid)).to.exist;
      });
      done();
    });
    it('Creating KeyPair', function () {
      if (!openpgp.config.use_indutny_elliptic && !openpgp.util.getNodeCrypto()) {
        this.skip();
      }
      const names = openpgp.config.use_indutny_elliptic ? ['p256', 'p384', 'p521', 'secp256k1', 'curve25519', 'brainpoolP256r1', 'brainpoolP384r1', 'brainpoolP512r1'] :
        ['p256', 'p384', 'p521', 'curve25519'];
      return Promise.all(names.map(function (name) {
        const curve = new elliptic_curves.Curve(name);
        return curve.genKeyPair().then(keyPair => {
          expect(keyPair).to.exist;
        });
      }));
    });
    it('Signature verification', function (done) {
      expect(
        elliptic_curves.ecdsa.verify('p256', 8, signature_data.signature, signature_data.message, signature_data.pub, signature_data.hashed)
      ).to.eventually.be.true.notify(done);
    });
    it('Invalid signature', function (done) {
      expect(
        elliptic_curves.ecdsa.verify('p256', 8, signature_data.signature, signature_data.message, key_data.p256.pub, signature_data.hashed)
      ).to.eventually.be.false.notify(done);
    });
    it('Signature generation', function () {
      return elliptic_curves.ecdsa.sign('p256', 8, signature_data.message, key_data.p256.pub, key_data.p256.priv, signature_data.hashed).then(async signature => {
        await expect(
          elliptic_curves.ecdsa.verify('p256', 8, signature, signature_data.message, key_data.p256.pub, signature_data.hashed)
        ).to.eventually.be.true;
      });
    });
    it('Shared secret generation', async function () {
      const curve = new elliptic_curves.Curve('p256');
      const { sharedKey: shared1 } = await elliptic_curves.ecdh.genPrivateEphemeralKey(curve, signature_data.pub, key_data.p256.pub, key_data.p256.priv);
      const { sharedKey: shared2 } = await elliptic_curves.ecdh.genPrivateEphemeralKey(curve, key_data.p256.pub, signature_data.pub, signature_data.priv);
      expect(shared1).to.deep.equal(shared2);
    });
  });
  describe('ECDSA signature', function () {
    const verify_signature = async function (oid, hash, r, s, message, pub) {
      if (openpgp.util.isString(message)) {
        message = openpgp.util.str_to_Uint8Array(message);
      } else if (!openpgp.util.isUint8Array(message)) {
        message = new Uint8Array(message);
      }
      const ecdsa = elliptic_curves.ecdsa;
      return ecdsa.verify(
        oid, hash, { r: new Uint8Array(r), s: new Uint8Array(s) }, message, new Uint8Array(pub), await openpgp.crypto.hash.digest(hash, message)
      );
    };
    const verify_signature_elliptic = async function (oid, hash, r, s, message, pub) {
      if (openpgp.util.isString(message)) {
        message = openpgp.util.str_to_Uint8Array(message);
      } else if (!openpgp.util.isUint8Array(message)) {
        message = new Uint8Array(message);
      }
      const ecdsa = elliptic_curves.ecdsa;
      return ecdsa.ellipticVerify(
        new elliptic_curves.Curve(oid), { r: new Uint8Array(r), s: new Uint8Array(s) }, await openpgp.crypto.hash.digest(hash, message), new Uint8Array(pub)
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
    it('Invalid curve oid', function () {
      return Promise.all([
        expect(verify_signature(
          'invalid oid', 8, [], [], [], []
        )).to.be.rejectedWith(Error, /Not valid curve/),
        expect(verify_signature(
          "\x00", 8, [], [], [], []
        )).to.be.rejectedWith(Error, /Not valid curve/)
      ]);
    });
    it('Invalid public key', async function () {
      if (!openpgp.config.use_indutny_elliptic && !openpgp.util.getNodeCrypto()) {
        this.skip();
      }
      if (openpgp.util.getNodeCrypto()) {
        await expect(verify_signature(
          'secp256k1', 8, [], [], [], []
        )).to.eventually.be.false;
        await expect(verify_signature(
          'secp256k1', 8, [], [], [], secp256k1_invalid_point_format
        )).to.eventually.be.false;
      }
      if (openpgp.config.use_indutny_elliptic) {
        return Promise.all([
          expect(verify_signature_elliptic(
            'secp256k1', 8, [], [], [], []
          )).to.be.rejectedWith(Error, /Unknown point format/),
          expect(verify_signature_elliptic(
            'secp256k1', 8, [], [], [], secp256k1_invalid_point_format
          )).to.be.rejectedWith(Error, /Unknown point format/)
        ]);
      }
    });
    it('Invalid point', function () {
      if (!openpgp.config.use_indutny_elliptic && !openpgp.util.getNodeCrypto()) {
        this.skip();
      }
      if (openpgp.util.getNodeCrypto()) {
        expect(verify_signature(
          'secp256k1', 8, [], [], [], secp256k1_invalid_point
        )).to.eventually.be.false;
      }
      if (openpgp.config.use_indutny_elliptic) {
        expect(verify_signature_elliptic(
          'secp256k1', 8, [], [], [], secp256k1_invalid_point
        )).to.be.rejectedWith(Error, /Invalid elliptic public key/);
      }
    });
    it('Invalid signature', function (done) {
      if (!openpgp.config.use_indutny_elliptic && !openpgp.util.getNodeCrypto()) {
        this.skip();
      }
      expect(verify_signature(
        'secp256k1', 8, [], [], [], secp256k1_point
      )).to.eventually.be.false.notify(done);
    });

    const p384_message = new Uint8Array([
      0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
      0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
    ]);
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
    it('Valid signature', function (done) {
      expect(verify_signature('p384', 8, p384_r, p384_s, p384_message, key_data.p384.pub))
        .to.eventually.be.true.notify(done);
    });
    it('Sign and verify message', function () {
      const curve = new elliptic_curves.Curve('p521');
      return curve.genKeyPair().then(async keyPair => {
        const keyPublic = new Uint8Array(keyPair.publicKey);
        const keyPrivate = new Uint8Array(keyPair.privateKey);
        const oid = curve.oid;
        const message = p384_message;
        return elliptic_curves.ecdsa.sign(oid, 10, message, keyPublic, keyPrivate, await openpgp.crypto.hash.digest(10, message)).then(async signature => {
          await expect(elliptic_curves.ecdsa.verify(oid, 10, signature, message, keyPublic, await openpgp.crypto.hash.digest(10, message)))
            .to.eventually.be.true;
        });
      });
    });
  });
});
