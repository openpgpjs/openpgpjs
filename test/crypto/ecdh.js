import x25519 from '@openpgp/tweetnacl';
import sinon from 'sinon';
import { use as chaiUse, expect } from 'chai';
import chaiAsPromised from 'chai-as-promised'; // eslint-disable-line import/newline-after-import
chaiUse(chaiAsPromised);

import openpgp from '../initOpenpgp.js';
import OID from '../../src/type/oid.js';
import KDFParams from '../../src/type/kdf_params.js';
import * as elliptic_curves from '../../src/crypto/public_key/elliptic';
import util from '../../src/util.js';
import elliptic_data from './elliptic_data.js';
import * as random from '../../src/crypto/random.js';

const key_data = elliptic_data.key_data;
/* eslint-disable no-invalid-this */
export default () => describe('ECDH key exchange @lightweight', function () {
  const decrypt_message = function (oid, hash, cipher, priv, pub, ephemeral, data, fingerprint) {
    if (util.isString(data)) {
      data = util.stringToUint8Array(data);
    } else {
      data = new Uint8Array(data);
    }
    return Promise.resolve().then(() => {
      const curve = new elliptic_curves.CurveWithOID(oid);
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
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  ]);

  it('Generated legacy x25519 secret scalar is stored clamped', async function () {
    const curve = new elliptic_curves.CurveWithOID(openpgp.enums.curve.curve25519Legacy);
    const { privateKey, publicKey } = await curve.genKeyPair();
    const clampedKey = privateKey.slice();
    clampedKey[0] = (clampedKey[0] & 127) | 64;
    clampedKey[31] &= 248;
    expect(privateKey).to.deep.equal(clampedKey);
    const { publicKey: expectedPublicKey } = x25519.box.keyPair.fromSecretKey(privateKey.slice().reverse());
    expect(publicKey.subarray(1)).to.deep.equal(expectedPublicKey);
  });
  it('Invalid curve oid', function (done) {
    expect(decrypt_message(
      '', 2, 7, [], [], [], [], []
    )).to.be.rejectedWith(Error, /Unknown curve/).notify(done);
  });
  it('Invalid elliptic public key', function (done) {
    if (!openpgp.config.useEllipticFallback && !util.getNodeCrypto()) {
      this.skip();
    }
    expect(decrypt_message(
      'secp256k1', 2, 7, secp256k1_value, secp256k1_point, secp256k1_invalid_point, secp256k1_data, []
    )).to.be.rejectedWith(/Public key is not valid for specified curve|Failed to translate Buffer to a EC_POINT|bad point/).notify(done);
  });
  it('Invalid key data integrity', async function () {
    if (!openpgp.config.useEllipticFallback && !util.getNodeCrypto()) {
      this.skip();
    }
    await expect(decrypt_message(
      'secp256k1', 2, 7, secp256k1_value, secp256k1_point, secp256k1_point, secp256k1_data, []
    )).to.be.rejectedWith(/Key Data Integrity faile|Invalid padding/); // invalid padding thrown by webkit on Windows
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

  const ecdh = elliptic_curves.ecdh;

  it('Invalid curve', async function () {
    if (!openpgp.config.useEllipticFallback && !util.getNodeCrypto()) {
      this.skip();
    }
    const curve = new elliptic_curves.CurveWithOID('secp256k1');
    const oid = new OID(curve.oid);
    const kdfParams = new KDFParams({ hash: curve.hash, cipher: curve.cipher });
    const data = random.getRandomBytes(16);
    await expect(
      ecdh.encrypt(oid, kdfParams, data, Q1, fingerprint1)
    ).to.be.rejectedWith(/Invalid point encoding/);
  });

  it('Different keys', async function () {
    const curve = new elliptic_curves.CurveWithOID(openpgp.enums.curve.curve25519Legacy);
    const oid = new OID(curve.oid);
    const kdfParams = new KDFParams({ hash: curve.hash, cipher: curve.cipher });
    const data = random.getRandomBytes(16);
    const { publicKey: V, wrappedKey: C } = await ecdh.encrypt(oid, kdfParams, data, Q1, fingerprint1);
    await expect(
      ecdh.decrypt(oid, kdfParams, V, C, Q2, d2, fingerprint1)
    ).to.be.rejectedWith(/Key Data Integrity failed|Invalid padding/); // invalid padding thrown by webkit on Windows
  });

  it('Invalid fingerprint', async function () {
    const curve = new elliptic_curves.CurveWithOID(openpgp.enums.curve.curve25519Legacy);
    const oid = new OID(curve.oid);
    const kdfParams = new KDFParams({ hash: curve.hash, cipher: curve.cipher });
    const data = random.getRandomBytes(16);
    const { publicKey: V, wrappedKey: C } = await ecdh.encrypt(oid, kdfParams, data, Q2, fingerprint1);
    await expect(
      ecdh.decrypt(oid, kdfParams, V, C, Q2, d2, fingerprint2)
    ).to.be.rejectedWith(/Key Data Integrity failed|Invalid padding/); // invalid padding thrown by webkit on Windows
  });

  it('Successful exchange x25519 (legacy)', async function () {
    const curve = new elliptic_curves.CurveWithOID(openpgp.enums.curve.curve25519Legacy);
    const oid = new OID(curve.oid);
    const kdfParams = new KDFParams({ hash: curve.hash, cipher: curve.cipher });
    const data = random.getRandomBytes(16);
    const { publicKey: V, wrappedKey: C } = await ecdh.encrypt(oid, kdfParams, data, Q1, fingerprint1);
    expect(await ecdh.decrypt(oid, kdfParams, V, C, Q1, d1, fingerprint1)).to.deep.equal(data);
  });

  it('Successful exchange x25519', async function () {
    const { ecdhX } = elliptic_curves;
    const data = random.getRandomBytes(32);
    // Bob's keys from https://www.rfc-editor.org/rfc/rfc7748#section-6.1
    const b = util.hexToUint8Array('5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb');
    const K_B = util.hexToUint8Array('de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f');
    const { ephemeralPublicKey, wrappedKey } = await ecdhX.encrypt(openpgp.enums.publicKey.x25519, data, K_B);
    expect(await ecdhX.decrypt(openpgp.enums.publicKey.x25519, ephemeralPublicKey, wrappedKey, K_B, b)).to.deep.equal(data);
  });

  it('Successful exchange x448', async function () {
    const { ecdhX } = elliptic_curves;
    const data = random.getRandomBytes(16);
    // Bob's keys from https://www.rfc-editor.org/rfc/rfc7748#section-6.2
    const b = util.hexToUint8Array('1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d');
    const K_B = util.hexToUint8Array('3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609');
    const { ephemeralPublicKey, wrappedKey } = await ecdhX.encrypt(openpgp.enums.publicKey.x448, data, K_B);
    expect(await ecdhX.decrypt(openpgp.enums.publicKey.x448, ephemeralPublicKey, wrappedKey, K_B, b)).to.deep.equal(data);
  });

  it('Detect small order points in x25519', async () => {
    const vectors = [
      {
        'order': '0',
        'vector': '0000000000000000000000000000000000000000000000000000000000000000'
      },
      {
        'order': '1',
        'vector': '0100000000000000000000000000000000000000000000000000000000000000'
      },
      {
        'order': '8',
        'vector': 'e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800'
      },
      {
        'order': 'p-1 (order 2)',
        'vector': 'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f'
      },
      {
        'order': 'p (=0, order 4)',
        'vector': 'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f'
      },
      {
        'order': 'p+1 (=1, order 1)',
        'vector': 'eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f'
      }
    ];
    const data = random.getRandomBytes(16);
    for (const { vector } of vectors) {
      const lowOrderPoint = util.hexToUint8Array(vector);
      const { A: K_A, k: a } = await elliptic_curves.ecdhX.generate(openpgp.enums.publicKey.x25519);
      await expect(elliptic_curves.ecdhX.encrypt(openpgp.enums.publicKey.x25519, data, lowOrderPoint)).to.be.rejected; // OperationError, DataError or 'low order point', depending on platform
      const dummyWrappedKey = new Uint8Array(32); // expected to be unused
      await expect(elliptic_curves.ecdhX.decrypt(openpgp.enums.publicKey.x25519, lowOrderPoint, dummyWrappedKey, K_A, a)).to.be.rejected; // OperationError, DataError or 'low order point', depending on platform
    }
  });

  it('Detect small order points in x448', async () => {
    const vectors = [
      {
        'order': '0',
        'vector': '0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
      },
      {
        'order': '1',
        'vector': '0100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
      },
      {
        'order': 'p-1 (order 2)',
        'vector': 'fefffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffff'
      },
      {
        'order': 'p (=0, order 4)',
        'vector': 'fffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffff'
      },
      {
        'order': 'p+1 (=1, order 1)',
        'vector': '00000000000000000000000000000000000000000000000000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
      }
    ];
    const data = random.getRandomBytes(16);
    for (const { vector } of vectors) {
      const lowOrderPoint = util.hexToUint8Array(vector);
      const { A: K_A, k: a } = await elliptic_curves.ecdhX.generate(openpgp.enums.publicKey.x448);
      await expect(elliptic_curves.ecdhX.encrypt(openpgp.enums.publicKey.x448, data, lowOrderPoint)).to.be.rejectedWith(/invalid private or public key received|expected valid u|low order point/);
      const dummyWrappedKey = new Uint8Array(32); // expected to be unused
      await expect(elliptic_curves.ecdhX.decrypt(openpgp.enums.publicKey.x448, lowOrderPoint, dummyWrappedKey, K_A, a)).to.be.rejectedWith(/invalid private or public key received|expected valid u|low order point/);
    }
  });

  const allCurves = ['secp256k1', 'nistP256', 'nistP384', 'nistP521', 'brainpoolP256r1', 'brainpoolP384r1', 'brainpoolP512r1'];
  allCurves.forEach(curveName => {
    it(`${curveName} - Successful exchange`, async function () {
      const curve = new elliptic_curves.CurveWithOID(curveName);
      const oid = new OID(curve.oid);
      const kdfParams = new KDFParams({ hash: curve.hash, cipher: curve.cipher });
      const data = random.getRandomBytes(16);
      const Q = key_data[curveName].pub;
      const d = key_data[curveName].priv;
      const { publicKey: V, wrappedKey: C } = await ecdh.encrypt(oid, kdfParams, data, Q, fingerprint1);
      expect(await ecdh.decrypt(oid, kdfParams, V, C, Q, d, fingerprint1)).to.deep.equal(data);
    });

    it(`${curveName} - Detect invalid PKESK public point encoding on decryption`, async function () {
      const curve = new elliptic_curves.CurveWithOID(curveName);
      const oid = new OID(curve.oid);
      const kdfParams = new KDFParams({ hash: curve.hash, cipher: curve.cipher });
      const data = random.getRandomBytes(16);
      const Q = key_data[curveName].pub;
      const d = key_data[curveName].priv;
      const { publicKey: V, wrappedKey: C } = await ecdh.encrypt(oid, kdfParams, data, Q, fingerprint1);

      const publicPointWithoutPrefixByte = V.subarray(1);
      const publicPointWithUnexpectedPrefixByte = new Uint8Array([0x1, ...publicPointWithoutPrefixByte]);
      const publicPointWithUnexpectedSize = V.subarray(0, V.length - 1);

      const expectedError = /Invalid point encoding/;
      await expect(ecdh.decrypt(oid, kdfParams, publicPointWithoutPrefixByte, C, Q, d, fingerprint1)).to.be.rejectedWith(expectedError);
      await expect(ecdh.decrypt(oid, kdfParams, publicPointWithUnexpectedPrefixByte, C, Q, d, fingerprint1)).to.be.rejectedWith(expectedError);
      await expect(ecdh.decrypt(oid, kdfParams, publicPointWithUnexpectedSize, C, Q, d, fingerprint1)).to.be.rejectedWith(expectedError);

    });
  });

  describe('Comparing decrypting with and without native crypto', () => {
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

    /**
     * Test that the result of `encryptFunction` can be decrypted by `decryptFunction`
     * with and without native crypto support.
     * @param encryptFunction - `(data: Uint8Array) => encryptFunctionResult`
     * @param decryptFunction - `(encryptFunctionResult) => <decryption result>`
     * @param expectNative - whether native usage is expected for the algorithm
     */
    const testRountripWithAndWithoutNative = async (
      encryptFunction,
      decryptFunction, // (encryptFunctionResult) => decryption result
      expectNative
    ) => {
      const nodeCrypto = util.getNodeCrypto();
      const webCrypto = util.getWebCrypto();
      const data = random.getRandomBytes(16);

      const nativeSpy = webCrypto ? sinonSandbox.spy(webCrypto, 'deriveBits') : sinonSandbox.spy(nodeCrypto, 'createECDH'); // functions used both for encryption and decryption
      const nativeResult = await encryptFunction(data);
      const expectedNativeEncryptCallCount = nativeSpy.callCount;
      disableNative();
      const nonNativeResult = await encryptFunction(data);
      expect(nativeSpy.callCount).to.equal(expectedNativeEncryptCallCount); // assert that fallback implementation was called
      if (expectNative) {
        expect(nativeSpy.calledOnce).to.be.true;
      }

      enableNative();
      expect(await decryptFunction(nativeResult)).to.deep.equal(data);
      expect(await decryptFunction(nonNativeResult)).to.deep.equal(data);
      const expectedNativeCallCount = nativeSpy.callCount;
      disableNative();
      expect(await decryptFunction(nativeResult)).to.deep.equal(data);
      expect(await decryptFunction(nonNativeResult)).to.deep.equal(data);
      expect(nativeSpy.callCount).to.equal(expectedNativeCallCount); // assert that fallback implementation was called
      if (expectNative) {
        expect(nativeSpy.callCount).to.equal(3); // one encryption + two decryptions
      }
    };


    allCurves.forEach(curveName => {
      it(`${curveName}`, async function () {
        const nodeCrypto = util.getNodeCrypto();
        const webCrypto = util.getWebCrypto();
        if (!nodeCrypto && !webCrypto) {
          this.skip();
        }

        const expectNativeWeb = new Set(['nistP256', 'nistP384']); // older versions of safari do not implement nistP521

        const curve = new elliptic_curves.CurveWithOID(curveName);
        const oid = new OID(curve.oid);
        const kdfParams = new KDFParams({ hash: curve.hash, cipher: curve.cipher });
        const Q = key_data[curveName].pub;
        const d = key_data[curveName].priv;

        await testRountripWithAndWithoutNative(
          data => ecdh.encrypt(oid, kdfParams, data, Q, fingerprint1),
          encryptResult => ecdh.decrypt(oid, kdfParams, encryptResult.publicKey, encryptResult.wrappedKey, Q, d, fingerprint1),
          expectNativeWeb.has(curveName) // all major browsers implement x25519
        );
      });
    });

    it('Successful exchange x25519 (legacy)', async function () {
      const curve = new elliptic_curves.CurveWithOID(openpgp.enums.curve.curve25519Legacy);
      const oid = new OID(curve.oid);
      const kdfParams = new KDFParams({ hash: curve.hash, cipher: curve.cipher });

      await testRountripWithAndWithoutNative(
        data => ecdh.encrypt(oid, kdfParams, data, Q1, fingerprint1),
        encryptResult => ecdh.decrypt(oid, kdfParams, encryptResult.publicKey, encryptResult.wrappedKey, Q1, d1, fingerprint1),
        false // all major browsers implement x25519, but webkit linux falls back due to bugs
      );
    });
  });
});
