const openpgp = typeof window !== 'undefined' && window.openpgp ? window.openpgp : require('../../dist/openpgp');
const chai = require('chai');
const elliptic_data = require('./elliptic_data');

chai.use(require('chai-as-promised'));

const expect = chai.expect;
const key_data = elliptic_data.key_data;
/* eslint-disable no-invalid-this */
describe('ECDH key exchange @lightweight', function () {
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
        new openpgp.KDFParams({ cipher, hash }),
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
      this.skip();
    }
    expect(decrypt_message(
      'secp256k1', 2, 7, [], [], [], [], []
    )).to.be.rejectedWith(Error, /Private key is not valid for specified curve|Unknown point format/).notify(done);
  });
  it('Invalid elliptic public key', function (done) {
    if (!openpgp.config.use_indutny_elliptic && !openpgp.util.getNodeCrypto()) {
      this.skip();
    }
    expect(decrypt_message(
      'secp256k1', 2, 7, secp256k1_value, secp256k1_point, secp256k1_invalid_point, secp256k1_data, []
    )).to.be.rejectedWith(Error, /Public key is not valid for specified curve|Failed to translate Buffer to a EC_POINT|Invalid elliptic public key/).notify(done);
  });
  it('Invalid key data integrity', function (done) {
    if (!openpgp.config.use_indutny_elliptic && !openpgp.util.getNodeCrypto()) {
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
    71, 245, 86, 3, 168, 101, 74, 209, 105
  ]);
  const fingerprint2 = new Uint8Array([
    177, 83,
    123, 123, 76, 133, 245, 212, 151, 243, 236,
    71, 245, 86, 3, 168, 101, 74, 209, 105
  ]);
  async function genPublicEphemeralKey(curve, Q, fingerprint) {
    const curveObj = new openpgp.crypto.publicKey.elliptic.Curve(curve);
    const oid = new openpgp.OID(curveObj.oid);
    const { publicKey: V, sharedKey } = await openpgp.crypto.publicKey.elliptic.ecdh.genPublicEphemeralKey(
      curveObj, Q
    );
    let cipher_algo = curveObj.cipher;
    const hash_algo = curveObj.hash;
    const kdfParams = new openpgp.KDFParams({ cipher: cipher_algo, hash: hash_algo });
    const param = openpgp.crypto.publicKey.elliptic.ecdh.buildEcdhParam(
      openpgp.enums.publicKey.ecdh, oid, kdfParams, fingerprint
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
    const kdfParams = new openpgp.KDFParams({ cipher: cipher_algo, hash: hash_algo });
    const param = openpgp.crypto.publicKey.elliptic.ecdh.buildEcdhParam(
      openpgp.enums.publicKey.ecdh, oid, kdfParams, fingerprint
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
    const kdfParams = new openpgp.KDFParams({ cipher: cipher_algo, hash: hash_algo });
    const param = openpgp.crypto.publicKey.elliptic.ecdh.buildEcdhParam(
      openpgp.enums.publicKey.ecdh, oid, kdfParams, fingerprint
    );
    cipher_algo = openpgp.enums.read(openpgp.enums.symmetric, cipher_algo);
    const Z = await openpgp.crypto.publicKey.elliptic.ecdh.kdf(
      hash_algo, sharedKey, openpgp.crypto.cipher[cipher_algo].keySize, param, curveObj, false
    );
    return Z;
  }

  describe('ECDHE key generation', function () {
    it('Invalid curve', function (done) {
      if (!openpgp.config.use_indutny_elliptic && !openpgp.util.getNodeCrypto()) {
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
      if (!openpgp.util.getWebCrypto() || !openpgp.config.use_indutny_elliptic) {
        // eslint-disable-next-line no-invalid-this
        this.skip();
      }
      return Promise.all(names.map(async function (name) {
        const curve = new elliptic_curves.Curve(name);
        try {
          await window.crypto.subtle.generateKey({
            name: "ECDSA",
            namedCurve: curve.web.web
          }, false, ["sign", "verify"]);
        } catch (err) {
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
      if (!openpgp.util.getNodeCrypto() || !openpgp.config.use_indutny_elliptic) {
        // eslint-disable-next-line no-invalid-this
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
