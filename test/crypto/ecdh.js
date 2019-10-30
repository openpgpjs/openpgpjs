const openpgp = typeof window !== 'undefined' && window.openpgp ? window.openpgp : require('../../dist/openpgp');
const chai = require('chai');
const mocha = require('mocha');

chai.use(require('chai-as-promised'));

const expect = chai.expect;

describe('ECDH key exchange', function () {
  const elliptic_curves = openpgp.crypto.publicKey.elliptic;
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
    )).to.be.rejectedWith(Error, /Not valid curve/).notify(done);
  });
  it('Invalid ephemeral key', function (done) {
    if (!openpgp.config.use_indutny_elliptic && !openpgp.util.getNodeCrypto()) {
      mocha.test.skip();
    }
    expect(decrypt_message(
      'secp256k1', 2, 7, [], [], [], [], []
    )).to.be.rejectedWith(Error, /Private key is not valid for specified curve|Unknown point format/).notify(done);
  });
  it('Invalid elliptic public key', function (done) {
    if (!openpgp.config.use_indutny_elliptic && !openpgp.util.getNodeCrypto()) {
      mocha.test.skip();
    }
    expect(decrypt_message(
      'secp256k1', 2, 7, secp256k1_value, secp256k1_point, secp256k1_invalid_point, secp256k1_data, []
    )).to.be.rejectedWith(Error, /Public key is not valid for specified curve|Failed to translate Buffer to a EC_POINT|Invalid elliptic public key/).notify(done);
  });
  it('Invalid key data integrity', function (done) {
    if (!openpgp.config.use_indutny_elliptic && !openpgp.util.getNodeCrypto()) {
      mocha.test.skip();
    }
    expect(decrypt_message(
      'secp256k1', 2, 7, secp256k1_value, secp256k1_point, secp256k1_point, secp256k1_data, []
    )).to.be.rejectedWith(Error, /Key Data Integrity failed/).notify(done);
  });
});
