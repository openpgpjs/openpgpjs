import PublicKey from './public_key';
import { armor } from '../encoding/armor';
import {
  PacketList,
  PublicKeyPacket,
  PublicSubkeyPacket
} from '../packet';
import defaultConfig from '../config';
import enums from '../enums';
import * as helper from './helper';

/**
 * Class that represents an OpenPGP Private key
 */
class PrivateKey extends PublicKey {
  /**
 * @param {PacketList} packetlist - The packets that form this key
 */
  constructor(packetlist) {
    super();
    this.packetListToStructure(packetlist, new Set([enums.packet.publicKey, enums.packet.publicSubkey]));
    if (!this.keyPacket) {
      throw new Error('Invalid key: missing private-key packet');
    }
  }

  /**
   * Returns true if this is a private key
   * @returns {Boolean}
   */
  isPrivate() {
    return true;
  }

  /**
   * Returns key as public key (shallow copy)
   * @returns {PublicKey} New public Key
   */
  toPublic() {
    const packetlist = new PacketList();
    const keyPackets = this.toPacketList();
    for (const keyPacket of keyPackets) {
      switch (keyPacket.constructor.tag) {
        case enums.packet.secretKey: {
          const pubKeyPacket = PublicKeyPacket.fromSecretKeyPacket(keyPacket);
          packetlist.push(pubKeyPacket);
          break;
        }
        case enums.packet.secretSubkey: {
          const pubSubkeyPacket = PublicSubkeyPacket.fromSecretSubkeyPacket(keyPacket);
          packetlist.push(pubSubkeyPacket);
          break;
        }
        default:
          packetlist.push(keyPacket);
      }
    }
    return new PublicKey(packetlist);
  }

  /**
   * Returns ASCII armored text of key
   * @param {Object} [config] - Full configuration, defaults to openpgp.config
   * @returns {ReadableStream<String>} ASCII armor.
   */
  armor(config = defaultConfig) {
    return armor(enums.armor.privateKey, this.toPacketList().write(), undefined, undefined, undefined, config);
  }

  /**
   * Returns all keys that are available for decryption, matching the keyID when given
   * This is useful to retrieve keys for session key decryption
   * @param  {module:type/keyid~KeyID} keyID, optional
   * @param  {Date}              date, optional
   * @param  {String}            userID, optional
   * @param {Object} [config] - Full configuration, defaults to openpgp.config
   * @returns {Promise<Array<Key|Subkey>>} Array of decryption keys.
   * @async
   */
  async getDecryptionKeys(keyID, date = new Date(), userID = {}, config = defaultConfig) {
    const primaryKey = this.keyPacket;
    const keys = [];
    for (let i = 0; i < this.subkeys.length; i++) {
      if (!keyID || this.subkeys[i].getKeyID().equals(keyID, true)) {
        try {
          const dataToVerify = { key: primaryKey, bind: this.subkeys[i].keyPacket };
          const bindingSignature = await helper.getLatestValidSignature(this.subkeys[i].bindingSignatures, primaryKey, enums.signature.subkeyBinding, dataToVerify, date, config);
          if (helper.isValidDecryptionKeyPacket(bindingSignature, config)) {
            keys.push(this.subkeys[i]);
          }
        } catch (e) {}
      }
    }

    // evaluate primary key
    const selfCertification = await this.getPrimarySelfSignature(date, userID, config);
    if ((!keyID || primaryKey.getKeyID().equals(keyID, true)) &&
        helper.isValidDecryptionKeyPacket(selfCertification, config)) {
      keys.push(this);
    }

    return keys;
  }

  /**
   * Returns true if the primary key or any subkey is decrypted.
   * A dummy key is considered encrypted.
   */
  isDecrypted() {
    return this.getKeys().some(({ keyPacket }) => keyPacket.isDecrypted());
  }

  /**
   * Check whether the private and public primary key parameters correspond
   * Together with verification of binding signatures, this guarantees key integrity
   * In case of gnu-dummy primary key, it is enough to validate any signing subkeys
   *   otherwise all encryption subkeys are validated
   * If only gnu-dummy keys are found, we cannot properly validate so we throw an error
   * @param {Object} [config] - Full configuration, defaults to openpgp.config
   * @throws {Error} if validation was not successful and the key cannot be trusted
   * @async
   */
  async validate(config = defaultConfig) {
    if (!this.isPrivate()) {
      throw new Error('Cannot validate a public key');
    }

    let signingKeyPacket;
    if (!this.keyPacket.isDummy()) {
      signingKeyPacket = this.keyPacket;
    } else {
      /**
       * It is enough to validate any signing keys
       * since its binding signatures are also checked
       */
      const signingKey = await this.getSigningKey(null, null, undefined, { ...config, rejectPublicKeyAlgorithms: new Set(), minRSABits: 0 });
      // This could again be a dummy key
      if (signingKey && !signingKey.keyPacket.isDummy()) {
        signingKeyPacket = signingKey.keyPacket;
      }
    }

    if (signingKeyPacket) {
      return signingKeyPacket.validate();
    } else {
      const keys = this.getKeys();
      const allDummies = keys.map(key => key.keyPacket.isDummy()).every(Boolean);
      if (allDummies) {
        throw new Error('Cannot validate an all-gnu-dummy key');
      }

      return Promise.all(keys.map(async key => key.keyPacket.validate()));
    }
  }

  /**
   * Clear private key parameters
   */
  clearPrivateParams() {
    this.getKeys().forEach(({ keyPacket }) => {
      if (keyPacket.isDecrypted()) {
        keyPacket.clearPrivateParams();
      }
    });
  }

  /**
   * Revokes the key
   * @param {Object} reasonForRevocation - optional, object indicating the reason for revocation
   * @param  {module:enums.reasonForRevocation} reasonForRevocation.flag optional, flag indicating the reason for revocation
   * @param  {String} reasonForRevocation.string optional, string explaining the reason for revocation
   * @param {Date} date - optional, override the creationtime of the revocation signature
   * @param {Object} [config] - Full configuration, defaults to openpgp.config
   * @returns {Promise<PrivateKey>} New key with revocation signature.
   * @async
   */
  async revoke(
    {
      flag: reasonForRevocationFlag = enums.reasonForRevocation.noReason,
      string: reasonForRevocationString = ''
    } = {},
    date = new Date(),
    config = defaultConfig
  ) {
    if (!this.isPrivate()) {
      throw new Error('Need private key for revoking');
    }
    const dataToSign = { key: this.keyPacket };
    const key = this.clone();
    key.revocationSignatures.push(await helper.createSignaturePacket(dataToSign, null, this.keyPacket, {
      signatureType: enums.signature.keyRevocation,
      reasonForRevocationFlag: enums.write(enums.reasonForRevocation, reasonForRevocationFlag),
      reasonForRevocationString
    }, date, undefined, undefined, undefined, config));
    return key;
  }


  /**
   * Generates a new OpenPGP subkey, and returns a clone of the Key object with the new subkey added.
   * Supports RSA and ECC keys. Defaults to the algorithm and bit size/curve of the primary key. DSA primary keys default to RSA subkeys.
   * @param {ecc|rsa} options.type       The subkey algorithm: ECC or RSA
   * @param {String}  options.curve      (optional) Elliptic curve for ECC keys
   * @param {Integer} options.rsaBits    (optional) Number of bits for RSA subkeys
   * @param {Number}  options.keyExpirationTime (optional) Number of seconds from the key creation time after which the key expires
   * @param {Date}    options.date       (optional) Override the creation date of the key and the key signatures
   * @param {Boolean} options.sign       (optional) Indicates whether the subkey should sign rather than encrypt. Defaults to false
   * @param {Object}  options.config     (optional) custom configuration settings to overwrite those in [config]{@link module:config}
   * @returns {Promise<PrivateKey>}
   * @async
   */
  async addSubkey(options = {}) {
    const config = { ...defaultConfig, ...options.config };
    if (options.passphrase) {
      throw new Error('Subkey could not be encrypted here, please encrypt whole key');
    }
    if (options.rsaBits < config.minRSABits) {
      throw new Error(`rsaBits should be at least ${config.minRSABits}, got: ${options.rsaBits}`);
    }
    const secretKeyPacket = this.keyPacket;
    if (secretKeyPacket.isDummy()) {
      throw new Error('Cannot add subkey to gnu-dummy primary key');
    }
    if (!secretKeyPacket.isDecrypted()) {
      throw new Error('Key is not decrypted');
    }
    const defaultOptions = secretKeyPacket.getAlgorithmInfo();
    defaultOptions.type = defaultOptions.curve ? 'ecc' : 'rsa'; // DSA keys default to RSA
    defaultOptions.rsaBits = defaultOptions.bits || 4096;
    defaultOptions.curve = defaultOptions.curve || 'curve25519';
    options = helper.sanitizeKeyOptions(options, defaultOptions);
    const keyPacket = await helper.generateSecretSubkey(options);
    helper.checkKeyRequirements(keyPacket, config);
    const bindingSignature = await helper.createBindingSignature(keyPacket, secretKeyPacket, options, config);
    const packetList = this.toPacketList();
    packetList.push(keyPacket, bindingSignature);
    return new PrivateKey(packetList);
  }
}

export default PrivateKey;
