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
    // An ASCII-armored Transferable Public Key packet sequence of a v6 key MUST NOT contain a CRC24 footer.
    const emitChecksum = this.keyPacket.version !== 6;
    return armor(enums.armor.privateKey, this.toPacketList().write(), undefined, undefined, undefined, emitChecksum, config);
  }

  /**
   * Returns all keys that are available for decryption, matching the keyID when given
   * This is useful to retrieve keys for session key decryption
   * @param  {module:type/keyid~KeyID} keyID, optional
   * @param  {Date}              date, optional
   * @param  {String}            userID, optional
   * @param {Object} [config] - Full configuration, defaults to openpgp.config
   * @returns {Promise<Array<Key|Subkey>>} Array of decryption keys.
   * @throws {Error} if no decryption key is found
   * @async
   */
  async getDecryptionKeys(keyID, date = new Date(), userID = {}, config = defaultConfig) {
    const primaryKey = this.keyPacket;
    const keys = [];
    let exception = null;
    for (let i = 0; i < this.subkeys.length; i++) {
      if (!keyID || this.subkeys[i].getKeyID().equals(keyID, true)) {
        if (this.subkeys[i].keyPacket.isDummy()) {
          exception = exception || new Error('Gnu-dummy key packets cannot be used for decryption');
          continue;
        }

        try {
          const dataToVerify = { key: primaryKey, bind: this.subkeys[i].keyPacket };
          const bindingSignature = await helper.getLatestValidSignature(this.subkeys[i].bindingSignatures, primaryKey, enums.signature.subkeyBinding, dataToVerify, date, config);
          if (helper.validateDecryptionKeyPacket(this.subkeys[i].keyPacket, bindingSignature, config)) {
            keys.push(this.subkeys[i]);
          }
        } catch (e) {
          exception = e;
        }
      }
    }

    // evaluate primary key
    const selfCertification = await this.getPrimarySelfSignature(date, userID, config);
    if ((!keyID || primaryKey.getKeyID().equals(keyID, true)) && helper.validateDecryptionKeyPacket(primaryKey, selfCertification, config)) {
      if (primaryKey.isDummy()) {
        exception = exception || new Error('Gnu-dummy key packets cannot be used for decryption');
      } else {
        keys.push(this);
      }
    }

    if (keys.length === 0) {
      // eslint-disable-next-line @typescript-eslint/only-throw-error
      throw exception || new Error('No decryption key packets found');
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

      return Promise.all(keys.map(key => key.keyPacket.validate()));
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
    key.revocationSignatures.push(await helper.createSignaturePacket(dataToSign, [], this.keyPacket, {
      signatureType: enums.signature.keyRevocation,
      reasonForRevocationFlag: enums.write(enums.reasonForRevocation, reasonForRevocationFlag),
      reasonForRevocationString
    }, date, undefined, undefined, undefined, config));
    return key;
  }


  /**
   * Generates a new OpenPGP subkey, and returns a clone of the Key object with the new subkey added.
   * Supports RSA and ECC keys, as well as the newer Curve448 and Curve25519.
   * Defaults to the algorithm and bit size/curve of the primary key. DSA primary keys default to RSA subkeys.
   * @param {ecc|rsa|curve25519|curve448} options.type The subkey algorithm: ECC, RSA, Curve448 or Curve25519 (new format).
   *                                                   Note: Curve448 and Curve25519 are not widely supported yet.
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
    defaultOptions.type = getDefaultSubkeyType(defaultOptions.algorithm);
    defaultOptions.rsaBits = defaultOptions.bits || 4096;
    defaultOptions.curve = defaultOptions.curve || 'curve25519Legacy';
    options = helper.sanitizeKeyOptions(options, defaultOptions);
    // Every subkey for a v4 primary key MUST be a v4 subkey.
    // Every subkey for a v6 primary key MUST be a v6 subkey.
    // For v5 keys, since we dropped generation support, a v4 subkey is added.
    // The config is always overwritten since we cannot tell if the defaultConfig was changed by the user.
    const keyPacket = await helper.generateSecretSubkey(options, { ...config, v6Keys: this.keyPacket.version === 6 });
    helper.checkKeyRequirements(keyPacket, config);
    const bindingSignature = await helper.createBindingSignature(keyPacket, secretKeyPacket, options, config);
    const packetList = this.toPacketList();
    packetList.push(keyPacket, bindingSignature);
    return new PrivateKey(packetList);
  }
}

function getDefaultSubkeyType(algoName) {
  const algo = enums.write(enums.publicKey, algoName);
  // NB: no encryption-only algos, since they cannot be in primary keys
  switch (algo) {
    case enums.publicKey.rsaEncrypt:
    case enums.publicKey.rsaEncryptSign:
    case enums.publicKey.rsaSign:
    case enums.publicKey.dsa:
      return 'rsa';
    case enums.publicKey.ecdsa:
    case enums.publicKey.eddsaLegacy:
      return 'ecc';
    case enums.publicKey.ed25519:
      return 'curve25519';
    case enums.publicKey.ed448:
      return 'curve448';
    default:
      throw new Error('Unsupported algorithm');
  }
}

export default PrivateKey;
