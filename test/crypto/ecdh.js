const openpgp = typeof window !== 'undefined' && window.openpgp ? window.openpgp : require('../..');
const chai = require('chai');
const elliptic_data = require('./elliptic_data');

chai.use(require('chai-as-promised'));

const expect = chai.expect;
const key_data = elliptic_data.key_data;
/* eslint-disable no-invalid-this */
module.exports = () => describe('ECDH key exchange @lightweight', function () {
  const elliptic_curves = openpgp.crypto.publicKey.elliptic;
  const decrypt_message = function (oid, hash, cipher, priv, pub, ephemeral, data, fingerprint) {
    if (openpgp.util.isString(data)) {
      data = openpgp.util.strToUint8Array(data);
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
    if (!openpgp.config.useIndutnyElliptic && !openpgp.util.getNodeCrypto()) {
      this.skip();
    }
    expect(decrypt_message(
      'secp256k1', 2, 7, [], [], [], [], []
    )).to.be.rejectedWith(Error, /Private key is not valid for specified curve|Unknown point format/).notify(done);
  });
  it('Invalid elliptic public key', function (done) {
    if (!openpgp.config.useIndutnyElliptic && !openpgp.util.getNodeCrypto()) {
      this.skip();
    }
    expect(decrypt_message(
      'secp256k1', 2, 7, secp256k1_value, secp256k1_point, secp256k1_invalid_point, secp256k1_data, []
    )).to.be.rejectedWith(Error, /Public key is not valid for specified curve|Failed to translate Buffer to a EC_POINT|Invalid elliptic public key/).notify(done);
  });
  it('Invalid key data integrity', function (done) {
    if (!openpgp.config.useIndutnyElliptic && !openpgp.util.getNodeCrypto()) {
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

  describe('ECDHE key generation', function () {
    it('Invalid curve', async function () {
      if (!openpgp.config.useIndutnyElliptic && !openpgp.util.getNodeCrypto()) {
        this.skip();
      }
      const { key: publicKey } = await openpgp.generateKey({ curve: "secp256k1", userIds: [{ name: 'Test' }] });
      publicKey.subKeys[0].keyPacket.publicParams.Q = Q1;
      publicKey.subKeys[0].keyPacket.fingerprint = fingerprint1;
      await expect(
        openpgp.encrypt({ publicKeys: [publicKey], message: openpgp.Message.fromText('test') })
      ).to.be.rejectedWith(Error, /Public key is not valid for specified curve|Failed to translate Buffer to a EC_POINT|Unknown point format/);
    });
    it('Invalid public part of ephemeral key and private key', async function () {
      const { key: publicKey } = await openpgp.generateKey({ curve: "curve25519", userIds: [{ name: 'Test' }] });
      publicKey.subKeys[0].keyPacket.publicParams.Q = Q1;
      publicKey.subKeys[0].keyPacket.fingerprint = fingerprint1;
      const { key: privateKey } = await openpgp.generateKey({ curve: "curve25519", userIds: [{ name: 'Test' }] });
      privateKey.subKeys[0].keyPacket.publicParams.Q = Q2;
      privateKey.subKeys[0].keyPacket.privateParams.d = d2;
      privateKey.subKeys[0].keyPacket.fingerprint = fingerprint1;
      const message = await openpgp.encrypt({ publicKeys: [publicKey], message: openpgp.Message.fromText('test') });
      await expect(
        openpgp.decrypt({ privateKeys: [privateKey], message: await openpgp.readArmoredMessage(message) })
      ).to.be.rejectedWith('Error decrypting message: Key Data Integrity failed');
    });
    it('Invalid fingerprint', async function () {
      const { key: publicKey } = await openpgp.generateKey({ curve: "curve25519", userIds: [{ name: 'Test' }] });
      publicKey.subKeys[0].keyPacket.publicParams.Q = Q1;
      publicKey.subKeys[0].keyPacket.fingerprint = fingerprint1;
      const { key: privateKey } = await openpgp.generateKey({ curve: "curve25519", userIds: [{ name: 'Test' }] });
      privateKey.subKeys[0].keyPacket.publicParams.Q = Q2;
      privateKey.subKeys[0].keyPacket.privateParams.d = d2;
      privateKey.subKeys[0].keyPacket.fingerprint = fingerprint2;
      const message = await openpgp.encrypt({ publicKeys: [publicKey], message: openpgp.Message.fromText('test') });
      await expect(
        openpgp.decrypt({ privateKeys: [privateKey], message: await openpgp.readArmoredMessage(message) })
      ).to.be.rejectedWith('Error decrypting message: Session key decryption failed');
    });
    it('Different keys', async function () {
      const { key: publicKey } = await openpgp.generateKey({ curve: "curve25519", userIds: [{ name: 'Test' }] });
      publicKey.subKeys[0].keyPacket.publicParams.Q = Q2;
      publicKey.subKeys[0].keyPacket.fingerprint = fingerprint1;
      const { key: privateKey } = await openpgp.generateKey({ curve: "curve25519", userIds: [{ name: 'Test' }] });
      privateKey.subKeys[0].keyPacket.publicParams.Q = Q1;
      privateKey.subKeys[0].keyPacket.privateParams.d = d1;
      privateKey.subKeys[0].keyPacket.fingerprint = fingerprint1;
      const message = await openpgp.encrypt({ publicKeys: [publicKey], message: openpgp.Message.fromText('test') });
      await expect(
        openpgp.decrypt({ privateKeys: [privateKey], message: await openpgp.readArmoredMessage(message) })
      ).to.be.rejectedWith('Error decrypting message: Key Data Integrity failed');
    });
    it('Successful exchange curve25519', async function () {
      const { key: publicKey } = await openpgp.generateKey({ curve: "curve25519", userIds: [{ name: 'Test' }] });
      publicKey.subKeys[0].keyPacket.publicParams.Q = Q1;
      publicKey.subKeys[0].keyPacket.fingerprint = fingerprint1;
      const { key: privateKey } = await openpgp.generateKey({ curve: "curve25519", userIds: [{ name: 'Test' }] });
      privateKey.subKeys[0].keyPacket.publicParams.Q = Q1;
      privateKey.subKeys[0].keyPacket.privateParams.d = d1;
      privateKey.subKeys[0].keyPacket.fingerprint = fingerprint1;
      const message = await openpgp.encrypt({ publicKeys: [publicKey], message: openpgp.Message.fromText('test') });
      expect((
        await openpgp.decrypt({ privateKeys: [privateKey], message: await openpgp.readArmoredMessage(message) })
      ).data).to.equal('test');
    });
    it('Successful exchange NIST P256', async function () {
      const { key: publicKey } = await openpgp.generateKey({ curve: "p256", userIds: [{ name: 'Test' }] });
      publicKey.subKeys[0].keyPacket.publicParams.Q = key_data.p256.pub;
      publicKey.subKeys[0].keyPacket.fingerprint = fingerprint1;
      const { key: privateKey } = await openpgp.generateKey({ curve: "p256", userIds: [{ name: 'Test' }] });
      privateKey.subKeys[0].keyPacket.publicParams.Q = key_data.p256.pub;
      privateKey.subKeys[0].keyPacket.privateParams.d = key_data.p256.priv;
      privateKey.subKeys[0].keyPacket.fingerprint = fingerprint1;
      const message = await openpgp.encrypt({ publicKeys: [publicKey], message: openpgp.Message.fromText('test') });
      expect((
        await openpgp.decrypt({ privateKeys: [privateKey], message: await openpgp.readArmoredMessage(message) })
      ).data).to.equal('test');
    });
    it('Successful exchange NIST P384', async function () {
      const { key: publicKey } = await openpgp.generateKey({ curve: "p384", userIds: [{ name: 'Test' }] });
      publicKey.subKeys[0].keyPacket.publicParams.Q = key_data.p384.pub;
      publicKey.subKeys[0].keyPacket.fingerprint = fingerprint1;
      const { key: privateKey } = await openpgp.generateKey({ curve: "p384", userIds: [{ name: 'Test' }] });
      privateKey.subKeys[0].keyPacket.publicParams.Q = key_data.p384.pub;
      privateKey.subKeys[0].keyPacket.privateParams.d = key_data.p384.priv;
      privateKey.subKeys[0].keyPacket.fingerprint = fingerprint1;
      const message = await openpgp.encrypt({ publicKeys: [publicKey], message: openpgp.Message.fromText('test') });
      expect((
        await openpgp.decrypt({ privateKeys: [privateKey], message: await openpgp.readArmoredMessage(message) })
      ).data).to.equal('test');
    });
    it('Successful exchange NIST P521', async function () {
      const { key: publicKey } = await openpgp.generateKey({ curve: "p521", userIds: [{ name: 'Test' }] });
      publicKey.subKeys[0].keyPacket.publicParams.Q = key_data.p521.pub;
      publicKey.subKeys[0].keyPacket.fingerprint = fingerprint1;
      const { key: privateKey } = await openpgp.generateKey({ curve: "p521", userIds: [{ name: 'Test' }] });
      privateKey.subKeys[0].keyPacket.publicParams.Q = key_data.p521.pub;
      privateKey.subKeys[0].keyPacket.privateParams.d = key_data.p521.priv;
      privateKey.subKeys[0].keyPacket.fingerprint = fingerprint1;
      const message = await openpgp.encrypt({ publicKeys: [publicKey], message: openpgp.Message.fromText('test') });
      expect((
        await openpgp.decrypt({ privateKeys: [privateKey], message: await openpgp.readArmoredMessage(message) })
      ).data).to.equal('test');
    });

    it('Comparing decrypting with useNative = true and false', async function () {
      const names = ["p256", "p384", "p521"];
      return Promise.all(names.map(async function (name) {
        const { key: publicKey } = await openpgp.generateKey({ curve: name, userIds: [{ name: 'Test' }] });
        publicKey.subKeys[0].keyPacket.publicParams.Q = key_data[name].pub;
        publicKey.subKeys[0].keyPacket.fingerprint = fingerprint1;
        const { key: privateKey } = await openpgp.generateKey({ curve: name, userIds: [{ name: 'Test' }] });
        privateKey.subKeys[0].keyPacket.publicParams.Q = key_data[name].pub;
        privateKey.subKeys[0].keyPacket.privateParams.d = key_data[name].priv;
        privateKey.subKeys[0].keyPacket.fingerprint = fingerprint1;
        const message = await openpgp.encrypt({ publicKeys: [publicKey], message: openpgp.Message.fromText('test') });
        expect((
          await openpgp.decrypt({ privateKeys: [privateKey], message: await openpgp.readArmoredMessage(message) })
        ).data).to.equal('test');
        const useNative = openpgp.config.useNative;
        openpgp.config.useNative = !useNative;
        try {
          expect((
            await openpgp.decrypt({ privateKeys: [privateKey], message: await openpgp.readArmoredMessage(message) })
          ).data).to.equal('test');
        } finally {
          openpgp.config.useNative = useNative;
        }
      }));
    });
  });
});
