const openpgp = typeof window !== 'undefined' && window.openpgp ? window.openpgp : require('../../dist/openpgp');
const chai = require('chai');

chai.use(require('chai-as-promised'));

const expect = chai.expect;

describe('Elliptic Curve Cryptography @lightweight', function () {
  const elliptic_curves = openpgp.crypto.publicKey.elliptic;
  const key_data = {
    p256: {
      priv: new Uint8Array([
        0x2B, 0x48, 0x2B, 0xE9, 0x88, 0x74, 0xE9, 0x49,
        0x1F, 0x89, 0xCC, 0xFF, 0x0A, 0x26, 0x05, 0xA2,
        0x3C, 0x2A, 0x35, 0x25, 0x26, 0x11, 0xD7, 0xEA,
        0xA1, 0xED, 0x29, 0x95, 0xB5, 0xE1, 0x5F, 0x1D
      ]),
      pub: new Uint8Array([
        0x04,
        0x80, 0x2C, 0x40, 0x76, 0x31, 0x20, 0xB6, 0x9B,
        0x48, 0x3B, 0x05, 0xEB, 0x6C, 0x1E, 0x3F, 0x49,
        0x84, 0xF7, 0xD2, 0xAD, 0x16, 0xA1, 0x6F, 0x62,
        0xFD, 0xCA, 0xEC, 0xB4, 0xA0, 0xBD, 0x4C, 0x1A,
        0x6F, 0xAA, 0xE7, 0xFD, 0xC4, 0x7D, 0x89, 0xCC,
        0x06, 0xCA, 0xFE, 0xAE, 0xCD, 0x0E, 0x9E, 0x62,
        0x57, 0xA4, 0xC3, 0xE7, 0x5E, 0x69, 0x10, 0xEE,
        0x67, 0xC2, 0x09, 0xF9, 0xEF, 0xE7, 0x9E, 0x56
      ])
    },
    p384: {
      priv: new Uint8Array([
        0xB5, 0x38, 0xDA, 0xF3, 0x77, 0x58, 0x3F, 0x94,
        0x5B, 0xC2, 0xCA, 0xC6, 0xA9, 0xFC, 0xAA, 0x3F,
        0x97, 0xB0, 0x54, 0x26, 0x10, 0xB4, 0xEC, 0x2A,
        0xA7, 0xC1, 0xA3, 0x4B, 0xC0, 0xBD, 0xFE, 0x3E,
        0xF1, 0xBE, 0x76, 0xCB, 0xE8, 0xAB, 0x3B, 0xBD,
        0xB6, 0x84, 0xC7, 0x8B, 0x91, 0x2F, 0x76, 0x8B
      ]),
      pub: new Uint8Array([
        0x04,
        0x44, 0x83, 0xA0, 0x3E, 0x5B, 0x0A, 0x0D, 0x9B,
        0xA0, 0x06, 0xDF, 0x38, 0xC7, 0x64, 0xCD, 0x62,
        0x7D, 0x5E, 0x3D, 0x3B, 0x50, 0xF5, 0x06, 0xC7,
        0xF7, 0x9B, 0xF0, 0xDE, 0xB1, 0x0C, 0x64, 0x74,
        0x0D, 0x03, 0x67, 0x24, 0xA0, 0xFF, 0xD1, 0x3D,
        0x03, 0x96, 0x48, 0xE7, 0x73, 0x5E, 0xF1, 0xC0,
        0x62, 0xCC, 0x33, 0x5A, 0x2A, 0x66, 0xA7, 0xAB,
        0xCA, 0x77, 0x52, 0xB8, 0xCD, 0xB5, 0x91, 0x16,
        0xAF, 0x42, 0xBB, 0x79, 0x0A, 0x59, 0x51, 0x68,
        0x8E, 0xEA, 0x32, 0x7D, 0x4A, 0x4A, 0xBB, 0x26,
        0x13, 0xFB, 0x95, 0xC0, 0xB1, 0xA4, 0x54, 0xCA,
        0xFA, 0x85, 0x8A, 0x4B, 0x58, 0x7C, 0x61, 0x39])
    },
    p521: {
      priv: new Uint8Array([
        0x00, 0xBB, 0x35, 0x27, 0xBC, 0xD6, 0x7E, 0x35,
        0xD5, 0xC5, 0x99, 0xC9, 0xB4, 0x6C, 0xEE, 0xDE,
        0x79, 0x2D, 0x77, 0xBD, 0x0A, 0x08, 0x9A, 0xC2,
        0x21, 0xF8, 0x35, 0x1C, 0x49, 0x5C, 0x40, 0x11,
        0xAC, 0x95, 0x2A, 0xEE, 0x91, 0x3A, 0x60, 0x5A,
        0x25, 0x5A, 0x95, 0x38, 0xDC, 0xEB, 0x59, 0x8E,
        0x33, 0xAD, 0xC0, 0x0B, 0x56, 0xB1, 0x06, 0x8C,
        0x57, 0x48, 0xA3, 0x73, 0xDB, 0xE0, 0x19, 0x50,
        0x2E, 0x79
      ]),
      pub: new Uint8Array([
        0x04,
        0x01, 0x0D, 0xD5, 0xCA, 0xD8, 0xB0, 0xEF, 0x9F,
        0x2B, 0x7E, 0x58, 0x99, 0xDE, 0x05, 0xF6, 0xF6,
        0x64, 0x6B, 0xCD, 0x59, 0x2E, 0x39, 0xB8, 0x82,
        0xB3, 0x13, 0xE6, 0x7D, 0x50, 0x85, 0xC3, 0xFA,
        0x93, 0xA5, 0x3F, 0x92, 0x85, 0x42, 0x36, 0xC0,
        0x83, 0xC9, 0xA4, 0x38, 0xB3, 0xD1, 0x99, 0xDA,
        0xE1, 0x02, 0x37, 0x7A, 0x3A, 0xC2, 0xB4, 0x55,
        0xEC, 0x1C, 0x0F, 0x00, 0x97, 0xFC, 0x75, 0x93,
        0xFE, 0x87, 0x00, 0x7D, 0xBE, 0x1A, 0xF5, 0xF9,
        0x57, 0x5C, 0xF2, 0x50, 0x2D, 0x14, 0x32, 0xEE,
        0x9B, 0xBE, 0xB3, 0x0E, 0x12, 0x2F, 0xF8, 0x85,
        0x11, 0x1A, 0x4F, 0x88, 0x50, 0xA4, 0xDB, 0x37,
        0xA6, 0x53, 0x5C, 0xB7, 0x87, 0xA6, 0x06, 0x21,
        0x15, 0xCC, 0x12, 0xC0, 0x1C, 0x83, 0x6F, 0x7B,
        0x5A, 0x8A, 0x36, 0x4E, 0x46, 0x9E, 0x54, 0x3F,
        0xE2, 0xF7, 0xED, 0x63, 0xC9, 0x92, 0xA4, 0x38,
        0x2B, 0x9C, 0xE2, 0xB7])
    },
    secp256k1: {
      priv: new Uint8Array([
        0x9E, 0xB0, 0x30, 0xD6, 0xE1, 0xCE, 0xAA, 0x0B,
        0x7B, 0x8F, 0xDE, 0x5D, 0x91, 0x4D, 0xDC, 0xA0,
        0xAD, 0x05, 0xAB, 0x8F, 0x87, 0x9B, 0x57, 0x48,
        0xAE, 0x8A, 0xE0, 0xF9, 0x39, 0xBD, 0x24, 0x00
      ]),
      pub: new Uint8Array([
        0x04,
        0xA8, 0x02, 0x35, 0x2C, 0xB7, 0x24, 0x95, 0x51,
        0x0A, 0x65, 0x26, 0x7D, 0xDF, 0xEA, 0x64, 0xB3,
        0xA8, 0xE1, 0x4F, 0xDD, 0x12, 0x84, 0x7E, 0x59,
        0xDB, 0x81, 0x0F, 0x89, 0xED, 0xFB, 0x29, 0xFB,
        0x07, 0x60, 0x29, 0x7D, 0x39, 0x8F, 0xB8, 0x68,
        0xF0, 0xFD, 0xA6, 0x67, 0x83, 0x55, 0x75, 0x7D,
        0xB8, 0xFD, 0x0B, 0xDF, 0x76, 0xCE, 0xBC, 0x95,
        0x4B, 0x92, 0x26, 0xFC, 0xAA, 0x7A, 0x7C, 0x3F])
    }
  };
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
      0x8E, 0x95, 0x24, 0x10, 0x1F, 0x0F, 0x13, 0xE4]),
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
      for (let name_or_oid in openpgp.enums.curves) {
        expect(new elliptic_curves.Curve(name_or_oid)).to.exist;
      }
      done();
    });
    it('Creating KeyPair', function () {
      if (!openpgp.util.getFullBuild() && !openpgp.util.getNodeCrypto()) {
        this.skip();
      }
      const names = openpgp.util.getFullBuild ? ['p256', 'p384', 'p521', 'secp256k1', 'curve25519', 'brainpoolP256r1', 'brainpoolP384r1', 'brainpoolP512r1'] :
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
    const secp256k1_dummy_value = new Uint8Array([
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
      0x9C, 0x47, 0xD0, 0x8F, 0xFB, 0x10, 0xD4, 0xB8]);
    const secp256k1_invalid_point = new Uint8Array([
      0x04,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    const secp256k1_invalid_point_format = new Uint8Array([
      0x04,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
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
      if (!openpgp.util.getFullBuild() && !openpgp.util.getNodeCrypto()) {
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
      if (openpgp.util.getFullBuild()) {
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
      if (!openpgp.util.getFullBuild() && !openpgp.util.getNodeCrypto()) {
        this.skip();
      }
      if (openpgp.util.getNodeCrypto()) {
        expect(verify_signature(
          'secp256k1', 8, [], [], [], secp256k1_invalid_point
        )).to.eventually.be.false;
      }
      if(openpgp.util.getFullBuild()) {
        expect(verify_signature_elliptic(
          'secp256k1', 8, [], [], [], secp256k1_invalid_point
        )).to.be.rejectedWith(Error, /Invalid elliptic public key/);
      }
    });
    it('Invalid signature', function (done) {
      if (!openpgp.util.getFullBuild() && !openpgp.util.getNodeCrypto()) {
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
  describe('ECDH key exchange', function () {
    const decrypt_message = function (oid, hash, cipher, priv, pub, ephemeral, data, fingerprint) {
      if (openpgp.util.isString(data)) {
        data = openpgp.util.str_to_Uint8Array(data);
      } else {
        data = new Uint8Array(data);
      }
      return Promise.resolve().then(() => {
        const curve = new elliptic_curves.Curve(oid);
        return elliptic_curves.ecdh.decrypt(
          new openpgp.OID(curve.oid),
          cipher,
          hash,
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
      0x9C, 0x47, 0xD0, 0x8F, 0xFB, 0x10, 0xD4, 0xB8]);
    const secp256k1_invalid_point = new Uint8Array([
      0x04,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    const secp256k1_data = new Uint8Array([
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ]);

    it('Invalid curve oid', function (done) {
      expect(decrypt_message(
        '', 2, 7, [], [], [], [], []
      )).to.be.rejectedWith(Error, /Not valid curve/).notify(done);
    });
    it('Invalid ephemeral key', function (done) {
      if (!openpgp.util.getFullBuild() && !openpgp.util.getNodeCrypto()) {
        this.skip();
      }
      expect(decrypt_message(
        'secp256k1', 2, 7, [], [], [], [], []
      )).to.be.rejectedWith(Error, /Private key is not valid for specified curve|Unknown point format/).notify(done);
    });
    it('Invalid elliptic public key', function (done) {
      if (!openpgp.util.getFullBuild() && !openpgp.util.getNodeCrypto()) {
        this.skip();
      }
      expect(decrypt_message(
        'secp256k1', 2, 7, secp256k1_value, secp256k1_point, secp256k1_invalid_point, secp256k1_data, []
      )).to.be.rejectedWith(Error, /Public key is not valid for specified curve|Failed to translate Buffer to a EC_POINT|Invalid elliptic public key/).notify(done);
    });
    it('Invalid key data integrity', function (done) {
      if (!openpgp.util.getFullBuild() && !openpgp.util.getNodeCrypto()) {
        this.skip();
      }
      expect(decrypt_message(
        'secp256k1', 2, 7, secp256k1_value, secp256k1_point, secp256k1_point, secp256k1_data, []
      )).to.be.rejectedWith(Error, /Key Data Integrity failed/).notify(done);
    });
  });

  const Q1 = new Uint8Array([
      64,
      48,  226,  162,  114,  194,  194,  67, 214,
      199, 10,  173,  22,  216,  240,  197,  202,
      114,  49,  127, 107,  152,  58,  119,   48,
      234,  194,  192,  66,  53,  165,  137,  93 ]);
  const d1 = new Uint8Array ([
      65, 200,  132,  198,  77,  86,  126,  196,
      247, 169,  156,  201,  32,  52,   3,  198,
      127, 144,  139,  47,  153,  239, 64,  235,
      61,   7,  17,  214,  64,  211,  215,  80 ]);
  const Q2 = new Uint8Array([
      64,
      154,  115,  36,  108,  33,  153,  64,  184,
      25,  139,  67,  25,  178,  194,  227,  53,
      254,  40,  101,  213,  28,  121,  154,  62,
      27,  99,  92,  126,  33,  223,  122,  91 ]);
  const d2 = new Uint8Array([
      123,  99,  163,  24,  201,  87,  0,  9,
      204,  21,  154,  5,  5,  5,  127,  157,
      237,  95,  76,  117,  89,  250,  64,  178,
      72,  69,  69,  58,  89,  228,  113,  112 ]);
  const fingerprint1 = new Uint8Array([
      177, 183,
      116,  123,  76,  133,  245,  212, 151, 243, 236,
      71,  245,  86,  3,  168,  101,   74,  209,  105 ]);
  const fingerprint2 = new Uint8Array([
      177,  83,
      123,  123,  76,  133,  245, 212, 151, 243, 236,
      71,  245,  86,  3,  168,  101,  74,  209,  105 ]);
  async function genPublicEphemeralKey(curve, Q, fingerprint) {
    const curveObj = new openpgp.crypto.publicKey.elliptic.Curve(curve);
    const oid = new openpgp.OID(curveObj.oid);
    const { publicKey: V, sharedKey } = await openpgp.crypto.publicKey.elliptic.ecdh.genPublicEphemeralKey(
      curveObj, Q
    );
    let cipher_algo = curveObj.cipher;
    const hash_algo = curveObj.hash;
    const param = openpgp.crypto.publicKey.elliptic.ecdh.buildEcdhParam(
      openpgp.enums.publicKey.ecdh, oid, cipher_algo, hash_algo, fingerprint
    );
    cipher_algo = openpgp.enums.read(openpgp.enums.symmetric, cipher_algo);
    const Z = await openpgp.crypto.publicKey.elliptic.ecdh.kdf(
      hash_algo, sharedKey, openpgp.crypto.cipher[cipher_algo].keySize, param, curveObj, false
    );
    return { V, Z };
  }

  async function genPrivateEphemeralKey(curve, V, Q, d, fingerprint) {
    const curveObj = new openpgp.crypto.publicKey.elliptic.Curve(curve);
    const oid = new openpgp.OID(curveObj.oid);
    const { sharedKey } = await openpgp.crypto.publicKey.elliptic.ecdh.genPrivateEphemeralKey(
      curveObj, V, Q, d
    );
    let cipher_algo = curveObj.cipher;
    const hash_algo = curveObj.hash;
    const param = openpgp.crypto.publicKey.elliptic.ecdh.buildEcdhParam(
      openpgp.enums.publicKey.ecdh, oid, cipher_algo, hash_algo, fingerprint
    );
    cipher_algo = openpgp.enums.read(openpgp.enums.symmetric, cipher_algo);
    const Z = await openpgp.crypto.publicKey.elliptic.ecdh.kdf(
      hash_algo, sharedKey, openpgp.crypto.cipher[cipher_algo].keySize, param, curveObj, false
    );
    return Z;
  }

  async function genPrivateEphemeralKeySpecific(fun, curve, V, Q, d, fingerprint) {
    const curveObj = new openpgp.crypto.publicKey.elliptic.Curve(curve);
    const oid = new openpgp.OID(curveObj.oid);
    let result;
    switch (fun) {
      case 'webPrivateEphemeralKey': {
        result = await openpgp.crypto.publicKey.elliptic.ecdh[fun](
          curveObj, V, Q, d
        );
        break;
      }
      case 'nodePrivateEphemeralKey':
      case 'ellipticPrivateEphemeralKey': {
        result = await openpgp.crypto.publicKey.elliptic.ecdh[fun](
          curveObj, V, d
        );
        break;
      }
    }
    const sharedKey = result.sharedKey;
    let cipher_algo = curveObj.cipher;
    const hash_algo = curveObj.hash;
    const param = openpgp.crypto.publicKey.elliptic.ecdh.buildEcdhParam(
      openpgp.enums.publicKey.ecdh, oid, cipher_algo, hash_algo, fingerprint
    );
    cipher_algo = openpgp.enums.read(openpgp.enums.symmetric, cipher_algo);
    const Z = await openpgp.crypto.publicKey.elliptic.ecdh.kdf(
      hash_algo, sharedKey, openpgp.crypto.cipher[cipher_algo].keySize, param, curveObj, false
    );
    return Z;
  }

  describe('ECDHE key generation', function () {
    it('Invalid curve', function (done) {
      if (!openpgp.util.getFullBuild() && !openpgp.util.getNodeCrypto()) {
        this.skip();
      }
      expect(genPublicEphemeralKey("secp256k1", Q1, fingerprint1)
      ).to.be.rejectedWith(Error, /Public key is not valid for specified curve|Failed to translate Buffer to a EC_POINT|Unknown point format/).notify(done);
    });
    it('Invalid public part of ephemeral key and private key', async function () {
      const ECDHE_VZ1 = await genPublicEphemeralKey("curve25519", Q1, fingerprint1);
      const ECDHE_Z12 = await genPrivateEphemeralKey("curve25519", ECDHE_VZ1.V, Q2, d2, fingerprint1);
      expect(Array.from(ECDHE_Z12).join(' ') === Array.from(ECDHE_VZ1.Z).join(' ')).to.be.false;
    });
    it('Invalid fingerprint', async function () {
      const ECDHE_VZ2 = await genPublicEphemeralKey("curve25519", Q2, fingerprint1);
      const ECDHE_Z2 = await genPrivateEphemeralKey("curve25519", ECDHE_VZ2.V, Q2, d2, fingerprint2);
      expect(Array.from(ECDHE_Z2).join(' ') === Array.from(ECDHE_VZ2.Z).join(' ')).to.be.false;
    });
    it('Different keys', async function () {
      const ECDHE_VZ1 = await genPublicEphemeralKey("curve25519", Q1, fingerprint1);
      const ECDHE_VZ2 = await genPublicEphemeralKey("curve25519", Q2, fingerprint1);
      const ECDHE_Z1 = await genPrivateEphemeralKey("curve25519", ECDHE_VZ1.V, Q1, d1, fingerprint1);
      expect(Array.from(ECDHE_Z1).join(' ') === Array.from(ECDHE_VZ2.Z).join(' ')).to.be.false;
    });
    it('Successful exchange curve25519', async function () {
      const ECDHE_VZ1 = await genPublicEphemeralKey("curve25519", Q1, fingerprint1);
      const ECDHE_Z1 = await genPrivateEphemeralKey("curve25519", ECDHE_VZ1.V, Q1, d1, fingerprint1);
      expect(Array.from(ECDHE_Z1).join(' ') === Array.from(ECDHE_VZ1.Z).join(' ')).to.be.true;
    });
    it('Successful exchange NIST P256', async function () {
      const ECDHE_VZ1 = await genPublicEphemeralKey("p256", key_data.p256.pub, fingerprint1);
      const ECDHE_Z1 = await genPrivateEphemeralKey("p256", ECDHE_VZ1.V, key_data.p256.pub, key_data.p256.priv, fingerprint1);
      expect(Array.from(ECDHE_Z1).join(' ') === Array.from(ECDHE_VZ1.Z).join(' ')).to.be.true;
    });
    it('Successful exchange NIST P384', async function () {
      const ECDHE_VZ1 = await genPublicEphemeralKey("p384", key_data.p384.pub, fingerprint1);
      const ECDHE_Z1 = await genPrivateEphemeralKey("p384", ECDHE_VZ1.V, key_data.p384.pub, key_data.p384.priv, fingerprint1);
      expect(Array.from(ECDHE_Z1).join(' ') === Array.from(ECDHE_VZ1.Z).join(' ')).to.be.true;
    });
    it('Successful exchange NIST P521', async function () {
      const ECDHE_VZ1 = await genPublicEphemeralKey("p521", key_data.p521.pub, fingerprint1);
      const ECDHE_Z1 = await genPrivateEphemeralKey("p521", ECDHE_VZ1.V, key_data.p521.pub, key_data.p521.priv, fingerprint1);
      expect(Array.from(ECDHE_Z1).join(' ') === Array.from(ECDHE_VZ1.Z).join(' ')).to.be.true;
    });

    it('Comparing keys derived using webCrypto and elliptic', async function () {
      const names = ["p256", "p384", "p521"];
      if (!openpgp.util.getWebCrypto() || !openpgp.util.getFullBuild()) {
        this.skip();
      }
      return Promise.all(names.map(async function (name) {
        const curve = new elliptic_curves.Curve(name);
        try {
          await window.crypto.subtle.generateKey({
            name: "ECDSA",
            namedCurve: curve.web.web
          }, false, ["sign", "verify"]);
        } catch(err) {
          openpgp.util.print_debug_error(err);
          return;
        }
        const ECDHE_VZ1 = await genPublicEphemeralKey(name, key_data[name].pub, fingerprint1);
        const ECDHE_Z1 = await genPrivateEphemeralKeySpecific('ellipticPrivateEphemeralKey', name, ECDHE_VZ1.V, key_data[name].pub, key_data[name].priv, fingerprint1);
        const ECDHE_Z2 = await genPrivateEphemeralKeySpecific('webPrivateEphemeralKey', name, ECDHE_VZ1.V, key_data[name].pub, key_data[name].priv, fingerprint1);
        expect(Array.from(ECDHE_Z1).join(' ') === Array.from(ECDHE_VZ1.Z).join(' ')).to.be.true;
        expect(Array.from(ECDHE_Z1).join(' ') === Array.from(ECDHE_Z2).join(' ')).to.be.true;
      }));
    });
    it('Comparing keys derived using nodeCrypto and elliptic', async function () {
      const names = ["p256", "p384", "p521"];
      if (!openpgp.util.getNodeCrypto() || !openpgp.util.getFullBuild()) {
        this.skip();
      }
      return Promise.all(names.map(async function (name) {
        const ECDHE_VZ1 = await genPublicEphemeralKey(name, key_data[name].pub, fingerprint1);
        const ECDHE_Z1 = await genPrivateEphemeralKeySpecific('ellipticPrivateEphemeralKey', name, ECDHE_VZ1.V, key_data[name].pub, key_data[name].priv, fingerprint1);
        const ECDHE_Z2 = await genPrivateEphemeralKeySpecific('nodePrivateEphemeralKey', name, ECDHE_VZ1.V, key_data[name].pub, key_data[name].priv, fingerprint1);
        expect(Array.from(ECDHE_Z1).join(' ') === Array.from(ECDHE_VZ1.Z).join(' ')).to.be.true;
        expect(Array.from(ECDHE_Z1).join(' ') === Array.from(ECDHE_Z2).join(' ')).to.be.true;
      }));
    });
  });
});
