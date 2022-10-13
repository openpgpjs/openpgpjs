/* eslint-disable no-console,new-cap,one-var */

// Nitrokey WebCrypt integration tests
// Start this test by opening below:
// http://localhost:8080/test/unittests.html
// or running `make test` in the main directory
// note: using 127.0.0.1 will not work

const openpgp = typeof window !== 'undefined' && window.openpgp ? window.openpgp : require('../..');
const webcrypt = require('nitrokey_webcrypt/dist/webcrypt.min');
const chai = require('chai');
chai.use(require('chai-as-promised'));

const {
  hexStringToByte,
  WEBCRYPT_STATUS,
  WEBCRYPT_OPENPGP_GENERATE,
  Webcrypt_Logout,
  Webcrypt_FactoryReset,
  WEBCRYPT_OPENPGP_DECRYPT,
  WEBCRYPT_OPENPGP_SIGN,
  WEBCRYPT_OPENPGP_INFO,
  WEBCRYPT_OPENPGP_IMPORT,
  CommandLoginParams,
  Webcrypt_Login,
  WEBCRYPT_LOGIN, Webcrypt_SetPin, CommandSetPinParams
} = webcrypt;
const { enums } = openpgp;
const { expect } = chai;

const WEBCRYPT_DEFAULT_PIN = '12345678';


module.exports = () => describe('OpenPGP.js webcrypt public api tests', function () {

  describe('WebCrypt general - unit tests', function () {

    let webcrypt_privateKey,
      webcrypt_publicKey;
    const statusCallback = s => (console.log(s));

    const plugin = {
      date: function () {
        return this.webcrypt_date ? new Date(this.webcrypt_date) : new Date(2019, 1, 1);
      }, // the default WebCrypt date for the created keys

      init: async function () {
        if (this.public_sign === undefined) {
          await WEBCRYPT_LOGIN(WEBCRYPT_DEFAULT_PIN, statusCallback);
          const res = await WEBCRYPT_OPENPGP_INFO(statusCallback);
          this.public_encr = res.encr_pubkey;
          this.public_sign = res.sign_pubkey;
          this.webcrypt_date = res.date;
          console.log({
            sign: this.public_sign,
            enc: this.public_encr,
            date: this.webcrypt_date,
            date_comp: this.date()
          }, 'info call results');
        }
      },
      agree: async function ({ curve, V, Q, d }) {
        console.log({ curve, V, Q, d });
        // @returns {Promise<{secretKey, sharedKey}>}
        const agreed_secret = await WEBCRYPT_OPENPGP_DECRYPT(statusCallback, V);
        return { secretKey: d, sharedKey: agreed_secret };
      },
      decrypt: async function ({ oid, kdfParams, V, Cdata, Q, d, fingerprint }) {
        // unused
        // @returns {Promise<Uint8Array>} Decrypted data.
        console.log({ oid, kdfParams, V, Cdata, Q, d, fingerprint, name: 'decrypt plugin' });
      },
      sign: async function ({ oid, hashAlgo, data, Q, d, hashed }) {
        console.log('sign', { oid, hashAlgo, data, Q, d, hashed, plugin: this, name: 'sign' });
        // TODO investigate, why data/message is used for signing and verification, and not the hash
        // TODO investigate, why signatures during key generation and use are not verified
        // const res = await WEBCRYPT_OPENPGP_SIGN(statusCallback, hashed);
        const res = await WEBCRYPT_OPENPGP_SIGN(statusCallback, data);
        const resb = hexStringToByte(res);
        const r = resb.slice(0, 32);
        const s = resb.slice(32, 64);
        const reso = { r, s };
        console.log('sign results', { resb, reso, oid, hashAlgo, data, Q, d, hashed, plugin: this, name: 'sign res' });
        console.log(`Using key for signing: ${Q}`);
        return reso;
      },
      /**
       * Function to wrap the hardware keys into a new key
       *
       * @param {Object} obj - An object argument for destructuring
       * @param {enums.publicKey} obj.algorithmName - Type of the algorithm
       * @param {string} obj.curveName - Curve name
       * @param {number} obj.rsaBits - RSA key length in bits
       */
      generate: async function ({ algorithmName, curveName, rsaBits }) {
        console.log({ keyType:curveName, name: 'genkey', plugin: this }, { algorithmName, curveName, rsaBits });
        let selected_pk = this.public_sign;
        if (algorithmName === openpgp.enums.publicKey.ecdh) {
          selected_pk = this.public_encr;
          console.warn(`Selecting subkey: ${selected_pk} for encryption`);
        } else if (algorithmName === openpgp.enums.publicKey.ecdsa) {
          console.warn(`Selecting main: ${selected_pk} for signing`);
        } else {
          console.error(`Not supported algorithm: ${algorithmName}`);
          throw new Error(`Not supported algorithm: ${algorithmName}`);
        }
        return { publicKey: selected_pk, privateKey: new Uint8Array(32).fill(42) };
      }
    };


    it('Status test', async function () {
      await Webcrypt_Logout(statusCallback);
      await Webcrypt_FactoryReset(statusCallback);
      const res = await WEBCRYPT_STATUS(statusCallback);
      expect(res.UNLOCKED).to.be.false;
      await Webcrypt_SetPin(statusCallback, new CommandSetPinParams(WEBCRYPT_DEFAULT_PIN));
      await Webcrypt_Login(statusCallback, new CommandLoginParams(WEBCRYPT_DEFAULT_PIN));
      expect(res).to.have.any.keys('UNLOCKED', 'VERSION', 'ATTEMPTS');
      console.log('Webcrypt status output, including version', {
        res,
        version: new TextDecoder().decode(hexStringToByte(res.VERSION_STRING))
      });
      return true;
    });


    it('plugin based key generation', async function () {

      await plugin.init();
      console.log('test plugin based key generation');
      const { privateKey: lwebcrypt_privateKey, publicKey: lwebcrypt_publicKey } = await openpgp.generateKey({
        curve: 'p256',
        userIDs: [{ name: 'Jon Smith', email: 'jon@example.com' }],
        format: 'object',
        date: plugin.date(),
        config: { hardwareKeys: plugin }
      });
      console.log({ lwebcrypt_privateKey, lwebcrypt_publicKey });
      webcrypt_privateKey = lwebcrypt_privateKey;
      webcrypt_publicKey = lwebcrypt_publicKey;

      return true;
    });

    it('Check cache', async function () {
      console.log('Check cache', { webcrypt_privateKey, webcrypt_publicKey });
      expect(webcrypt_privateKey).to.be.ok;
      expect(webcrypt_publicKey).to.be.ok;
    });

    it('Check stub properties', async function () {
      expect(webcrypt_privateKey.keyPacket.isStoredInHardware()).to.be.true;
      await webcrypt_privateKey.validate(); // throws on failed validation
    });

    it('Do not operate on stub keys with unset plugin - signing', async function () {
      const sign_promise = openpgp.sign({
        message: await openpgp.createMessage({ text: 'Hello, World!' }),
        signingKeys: webcrypt_privateKey,
        detached: true
      });
      expect(sign_promise).to.eventually.be.rejectedWith('Cannot use gnu-divert-to-card key without config.hardwareKeys set.');
    });


    it('Check generated public key', async function () {
      expect(webcrypt_publicKey.getFingerprint()).to.be.ok;
      return true;
    });

    it('Encrypting and decrypting message against Webcrypt key', async function () {
      const plaintext = 'Hello, World!';
      const encrypted = await openpgp.encrypt({
        message: await openpgp.createMessage({ text: plaintext }),
        encryptionKeys: webcrypt_publicKey,
        format: 'binary'
      });
      expect(encrypted).to.be.a('Uint8Array');
      const message = await openpgp.readMessage({
        binaryMessage: encrypted
      });
      const { data: decrypted, signatures } = await openpgp.decrypt({
        message,
        decryptionKeys: webcrypt_privateKey,
        config: { hardwareKeys: plugin }
      });
      expect(decrypted).to.be.equal(plaintext);
      return true;
    });

    it('Signing message', async function () {
      const message = await openpgp.createMessage({ text: 'Hello, World!' });
      const detachedSignature = await openpgp.sign({
        message,
        signingKeys: webcrypt_privateKey,
        config: { hardwareKeys: plugin },
        detached: true
      });
      console.log({ detachedSignature });
      expect(detachedSignature).to.be.ok;

      const signature = await openpgp.readSignature({
        armoredSignature: detachedSignature
      });

      const verificationResult = await openpgp.verify({
        message,
        signature,
        verificationKeys: webcrypt_publicKey
      });

      const { verified, keyID } = verificationResult.signatures[0];
      await verified; // throws on invalid signature
      console.log('webcrypt detached signature, signed by key id ' + keyID.toHex());
      expect(keyID.toHex()).to.be.equal(webcrypt_publicKey.keyPacket.keyID.toHex());
    });


    it('Signing message webcrypt non-detached', async function () {
      const unsignedMessage = await openpgp.createCleartextMessage({ text: 'Hello, World!' });
      const cleartextMessage = await openpgp.sign({
        message: unsignedMessage, // CleartextMessage or Message object
        signingKeys: webcrypt_privateKey,
        config: { hardwareKeys: plugin }
      });
      // console.log('after signing', { cleartextMessage }); // '-----BEGIN PGP SIGNED MESSAGE ... END PGP SIGNATURE-----'
      expect(cleartextMessage).to.be.ok;
      expect(cleartextMessage).to.have.string('BEGIN PGP SIGNED MESSAGE');

      const signedMessage = await openpgp.readCleartextMessage({
        cleartextMessage // parse armored message
      });
      const verificationResult = await openpgp.verify({
        message: signedMessage,
        verificationKeys: webcrypt_publicKey
      });
      const { verified, keyID } = verificationResult.signatures[0];
      await verified; // throws on invalid signature
      expect(keyID.toHex()).to.be.equal(webcrypt_publicKey.keyPacket.keyID.toHex());
    });


    it('Signing big message webcrypt non-detached 900', async function () {
      const clearText = 'Hello, World!'.padEnd(900, '='); // 900, 500 works; 980,1100 does not,
      const unsignedMessage = await openpgp.createCleartextMessage({ text: clearText });
      const cleartextMessage = await openpgp.sign({
        message: unsignedMessage,
        signingKeys: webcrypt_privateKey,
        config: { hardwareKeys: plugin }
      });

      const signedMessage = await openpgp.readCleartextMessage({
        cleartextMessage // parse armored message
      });
      const verificationResult = await openpgp.verify({
        message: signedMessage,
        verificationKeys: webcrypt_publicKey
      });
      const { verified, keyID } = verificationResult.signatures[0];
      await verified; // throws on invalid signature
      expect(keyID.toHex()).to.be.equal(webcrypt_publicKey.keyPacket.keyID.toHex());
    });

    it('OpenPGPjs key import to WebCrypt', async function () {
      // software key
      const { privateKey, publicKey } = await openpgp.generateKey({
        curve: 'p256',
        userIDs: [{ name: 'Jon Smith', email: 'jon@example.com' }],
        format: 'object'
      });

      await WEBCRYPT_OPENPGP_IMPORT(statusCallback, {
        sign_privkey: privateKey.keyPacket.privateParams.d,
        encr_privkey: privateKey.subkeys[0].keyPacket.privateParams.d,
        date: privateKey.getCreationTime()
      });
      const webcrypt_openpgp_keys_current = await WEBCRYPT_OPENPGP_INFO(statusCallback);
      console.log({ sw: publicKey.keyPacket.publicParams.Q, wc: webcrypt_openpgp_keys_current.sign_pubkey });
      expect(publicKey.keyPacket.publicParams.Q, 'Main key public key check').to.be.deep.equal(webcrypt_openpgp_keys_current.sign_pubkey);
      expect(publicKey.subkeys[0].keyPacket.publicParams.Q, 'Subkey public key check').to.be.deep.equal(webcrypt_openpgp_keys_current.encr_pubkey);
    });

    it('OpenPGPjs imported key import to WebCrypt', async function () {
      // reset plugin cached info
      await plugin.init();

      const { privateKey: lwebcrypt_privateKey, publicKey: lwebcrypt_publicKey } = await openpgp.generateKey({
        curve: 'p256',
        userIDs: [{ name: 'Jon Smith', email: 'jon@example.com' }],
        format: 'object',
        date: plugin.date(),
        config: { hardwareKeys: plugin }
      });
      console.log({ lwebcrypt_privateKey, lwebcrypt_publicKey });
      webcrypt_privateKey = lwebcrypt_privateKey;
      webcrypt_publicKey = lwebcrypt_publicKey;
    });


    it('WebCrypt OpenPGP factory reset', async function () {
      const webcrypt_openpgp_keys_before = await WEBCRYPT_OPENPGP_INFO(statusCallback);
      await WEBCRYPT_OPENPGP_GENERATE(statusCallback);
      const webcrypt_openpgp_keys_current = await WEBCRYPT_OPENPGP_INFO(statusCallback);
      console.log('Current webcrypt keys and the regenerated key after WEBCRYPT_OPENPGP_GENERATE()', {
        webcrypt_openpgp_keys_before,
        webcrypt_openpgp_keys_current
      });
      expect(webcrypt_openpgp_keys_before).to.be.not.equal(webcrypt_openpgp_keys_current);
      await plugin.init();
    });

    // it('Next test', async function () {
    //   return true;
    // });


  });

});
