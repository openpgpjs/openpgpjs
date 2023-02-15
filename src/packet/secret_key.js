// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

import PublicKeyPacket from './public_key';
import S2K from '../type/s2k';
import crypto from '../crypto';
import enums from '../enums';
import util from '../util';
import defaultConfig from '../config';
import { UnsupportedError } from './packet';

/**
 * A Secret-Key packet contains all the information that is found in a
 * Public-Key packet, including the public-key material, but also
 * includes the secret-key material after all the public-key fields.
 * @extends PublicKeyPacket
 */
class SecretKeyPacket extends PublicKeyPacket {
  static get tag() {
    return enums.packet.secretKey;
  }

  /**
   * @param {Date} [date] - Creation date
   * @param {Object} [config] - Full configuration, defaults to openpgp.config
   */
  constructor(date = new Date(), config = defaultConfig) {
    super(date, config);
    /**
     * Secret-key data
     */
    this.keyMaterial = null;
    /**
     * Indicates whether secret-key data is encrypted. `this.isEncrypted === false` means data is available in decrypted form.
     */
    this.isEncrypted = null;
    /**
     * S2K usage
     * @type {enums.symmetric}
     */
    this.s2kUsage = 0;
    /**
     * S2K object
     * @type {type/s2k}
     */
    this.s2k = null;
    /**
     * Symmetric algorithm to encrypt the key with
     * @type {enums.symmetric}
     */
    this.symmetric = null;
    /**
     * AEAD algorithm to encrypt the key with (if AEAD protection is enabled)
     * @type {enums.aead}
     */
    this.aead = null;
    /**
     * Decrypted private parameters, referenced by name
     * @type {Object}
     */
    this.privateParams = null;

    /**
     * The IV used for S2K operations.
     * Dubbed as a 16B serial number container for the stub keys for external access (as in GnuPG C implementation).
     * @type {Uint8Array}
     */
    this.iv = null;
  }

  // 5.5.3.  Secret-Key Packet Formats

  /**
   * Internal parser for private keys as specified in
   * {@link https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-04#section-5.5.3|RFC4880bis-04 section 5.5.3}
   * @param {Uint8Array} bytes - Input string to read the packet from
   * @async
   */
  async read(bytes) {
    // - A Public-Key or Public-Subkey packet, as described above.
    let i = await this.readPublicKey(bytes);

    // - One octet indicating string-to-key usage conventions.  Zero
    //   indicates that the secret-key data is not encrypted.  255 or 254
    //   indicates that a string-to-key specifier is being given.  Any
    //   other value is a symmetric-key encryption algorithm identifier.
    this.s2kUsage = bytes[i++];

    // - Only for a version 5 packet, a one-octet scalar octet count of
    //   the next 4 optional fields.
    if (this.version === 5) {
      i++;
    }

    // - [Optional] If string-to-key usage octet was 255, 254, or 253, a
    //   one-octet symmetric encryption algorithm.
    if (this.s2kUsage === 255 || this.s2kUsage === 254 || this.s2kUsage === 253) {
      this.symmetric = bytes[i++];

      // - [Optional] If string-to-key usage octet was 253, a one-octet
      //   AEAD algorithm.
      if (this.s2kUsage === 253) {
        this.aead = bytes[i++];
      }

      // - [Optional] If string-to-key usage octet was 255, 254, or 253, a
      //   string-to-key specifier.  The length of the string-to-key
      //   specifier is implied by its type, as described above.
      this.s2k = new S2K();
      i += this.s2k.read(bytes.subarray(i, bytes.length));

      if (this.s2k.type === 'gnu-dummy') {
        return;
      }
    } else if (this.s2kUsage) {
      this.symmetric = this.s2kUsage;
    }

    // - [Optional] If secret data is encrypted (string-to-key usage octet
    //   not zero), an Initial Vector (IV) of the same length as the
    //   cipher's block size.
    if (this.s2kUsage && this.isStoredInHardware()) {
      const ivlen = bytes[i++];
      this.iv = bytes.subarray(i, i + ivlen);
      i += this.iv.length;
    } else if (this.s2kUsage) {
      this.iv = bytes.subarray(
        i,
        i + crypto.getCipher(this.symmetric).blockSize
      );

      i += this.iv.length;
    }

    // - Only for a version 5 packet, a four-octet scalar octet count for
    //   the following key material.
    if (this.version === 5) {
      i += 4;
    }

    // - Plain or encrypted multiprecision integers comprising the secret
    //   key data.  These algorithm-specific fields are as described
    //   below.
    this.keyMaterial = bytes.subarray(i);
    this.isEncrypted = !!this.s2kUsage;

    if (!this.isEncrypted) {
      const cleartext = this.keyMaterial.subarray(0, -2);
      if (!util.equalsUint8Array(util.writeChecksum(cleartext), this.keyMaterial.subarray(-2))) {
        throw new Error('Key checksum mismatch');
      }
      try {
        const { privateParams } = crypto.parsePrivateKeyParams(this.algorithm, cleartext, this.publicParams);
        this.privateParams = privateParams;
      } catch (err) {
        if (err instanceof UnsupportedError) throw err;
        // avoid throwing potentially sensitive errors
        throw new Error('Error reading MPIs');
      }
    }
  }

  /**
   * Creates an OpenPGP key packet for the given key.
   * @returns {Uint8Array} A string of bytes containing the secret key OpenPGP packet.
   */
  write() {
    const arr = [this.writePublicKey()];

    arr.push(new Uint8Array([this.s2kUsage]));

    const optionalFieldsArr = [];
    // - [Optional] If string-to-key usage octet was 255, 254, or 253, a
    //   one- octet symmetric encryption algorithm.
    if (this.s2kUsage === 255 || this.s2kUsage === 254 || this.s2kUsage === 253) {
      optionalFieldsArr.push(this.symmetric);

      // - [Optional] If string-to-key usage octet was 253, a one-octet
      //   AEAD algorithm.
      if (this.s2kUsage === 253) {
        optionalFieldsArr.push(this.aead);
      }

      // - [Optional] If string-to-key usage octet was 255, 254, or 253, a
      //   string-to-key specifier.  The length of the string-to-key
      //   specifier is implied by its type, as described above.
      optionalFieldsArr.push(...this.s2k.write());
    }

    // - [Optional] If secret data is encrypted (string-to-key usage octet
    //   not zero), an Initial Vector (IV) of the same length as the
    //   cipher's block size.
    if (this.s2kUsage && this.s2k.type !== 'gnu-dummy') {
      if (this.isStoredInHardware()){
        // Inserting length of the serial number here as per spec (kept in the IV field, as in GnuPG C implementation)
        // Details: GnuPG's DETAILS file, GNU extensions to the S2K algorithm
        optionalFieldsArr.push(util.writeNumber(this.iv.length, 1));
      }
      optionalFieldsArr.push(...this.iv);
    }

    if (this.version === 5) {
      arr.push(new Uint8Array([optionalFieldsArr.length]));
    }
    arr.push(new Uint8Array(optionalFieldsArr));

    if (!this.isDummy() && !this.isStoredInHardware()) {
      if (!this.s2kUsage) {
        this.keyMaterial = crypto.serializeParams(this.algorithm, this.privateParams);
      }

      if (this.version === 5) {
        arr.push(util.writeNumber(this.keyMaterial.length, 4));
      }
      arr.push(this.keyMaterial);

      if (!this.s2kUsage) {
        arr.push(util.writeChecksum(this.keyMaterial));
      }
    }

    return util.concatUint8Array(arr);
  }

  /**
   * Check whether secret-key data is available in decrypted form.
   * Returns false for gnu-dummy keys and null for public keys.
   * @returns {Boolean|null}
   */
  isDecrypted() {
    return this.isEncrypted === false;
  }

  /**
   * Check whether this is a gnu-dummy key
   * @returns {Boolean}
   */
  isDummy() {
    return !!(this.s2k && this.s2k.type === 'gnu-dummy');
  }

  /**
   * Check whether this is a gnu-stub key
   * @returns {Boolean}
   */
  isStoredInHardware() {
    return !!(this.s2k && this.s2k.type === 'gnu-divert-to-card');
  }

  /**
   * Remove private key material, converting the key to a dummy one.
   * The resulting key cannot be used for signing/decrypting but can still verify signatures.
   * @param {Object} [config] - Full configuration, defaults to openpgp.config
   */
  makeDummy(config = defaultConfig) {
    if (this.isDummy()) {
      return;
    }
    if (this.isDecrypted()) {
      this.clearPrivateParams();
    }
    this.isEncrypted = null;
    this.keyMaterial = null;
    this.s2k = new S2K(config);
    this.s2k.algorithm = 0;
    this.s2k.c = 0;
    this.s2k.type = 'gnu-dummy';
    this.s2kUsage = 254;
    this.symmetric = enums.symmetric.aes256;
  }

  /**
   * Remove private key material, converting the key to a gnu-divert-to-card one.
   * The resulting key refers to hardware for the private key operations.
   * Does nothing if the key is marked as stub already.
   * @param {Uint8Array} [serialNumber] - Serial number of the hardware device, keeping the secret key. Must be no longer than 16 bytes.
   * @param {Object} [config] - Full configuration, defaults to openpgp.config
   */
  setStoredInHardware(serialNumber, config = defaultConfig) {
    if (this.isStoredInHardware()) {
      return;
    }
    this.isEncrypted = null;
    this.keyMaterial = null;
    this.s2k = new S2K(config);
    this.s2k.algorithm = 0;
    this.s2k.c = 0;
    this.s2k.type = 'gnu-divert-to-card';
    this.s2kUsage = 254;
    this.symmetric = enums.symmetric.aes256;
    this.setSerialNumber(serialNumber);
  }

  /**
   * Set serial number of the device, which stores the secret key
   * @param {Uint8Array} [serialNumber] - Serial number, not longer than 16 bytes
   */
  setSerialNumber(serialNumber){
    if (!this.isStoredInHardware() || !serialNumber || serialNumber.length > 16) {
      throw new Error('Not a stub key or invalid serial number set on the IV field');
    }
    this.iv = serialNumber;
  }

  /**
   * Return the serial number of the hardware device keeping the secret value
   * @returns {Uint8Array} Serial number of the device keeping the private key
   */
  getSerialNumber() {
    if (!this.isStoredInHardware() || !this.iv || this.iv.length > 16) {
      throw new Error('Not a stub key or invalid serial number set on the IV field');
    }

    return this.iv;
  }

  /**
   * Encrypt the payload. By default, we use aes256 and iterated, salted string
   * to key specifier. If the key is in a decrypted state (isEncrypted === false)
   * and the passphrase is empty or undefined, the key will be set as not encrypted.
   * This can be used to remove passphrase protection after calling decrypt().
   * @param {String} passphrase
   * @param {Object} [config] - Full configuration, defaults to openpgp.config
   * @throws {Error} if encryption was not successful
   * @async
   */
  async encrypt(passphrase, config = defaultConfig) {
    if (this.isDummy() || this.isStoredInHardware()) {
      return;
    }

    if (!this.isDecrypted()) {
      throw new Error('Key packet is already encrypted');
    }

    if (!passphrase) {
      throw new Error('A non-empty passphrase is required for key encryption.');
    }

    this.s2k = new S2K(config);
    this.s2k.salt = crypto.random.getRandomBytes(8);
    const cleartext = crypto.serializeParams(this.algorithm, this.privateParams);
    this.symmetric = enums.symmetric.aes256;
    const key = await produceEncryptionKey(this.s2k, passphrase, this.symmetric);

    const { blockSize } = crypto.getCipher(this.symmetric);
    this.iv = crypto.random.getRandomBytes(blockSize);

    if (config.aeadProtect) {
      this.s2kUsage = 253;
      this.aead = enums.aead.eax;
      const mode = crypto.getAEADMode(this.aead);
      const modeInstance = await mode(this.symmetric, key);
      this.keyMaterial = await modeInstance.encrypt(cleartext, this.iv.subarray(0, mode.ivLength), new Uint8Array());
    } else {
      this.s2kUsage = 254;
      this.keyMaterial = await crypto.mode.cfb.encrypt(this.symmetric, key, util.concatUint8Array([
        cleartext,
        await crypto.hash.sha1(cleartext, config)
      ]), this.iv, config);
    }
  }

  /**
   * Decrypts the private key params which are needed to use the key.
   * Successful decryption does not imply key integrity, call validate() to confirm that.
   * {@link SecretKeyPacket.isDecrypted} should be false, as
   * otherwise calls to this function will throw an error.
   * @param {String} passphrase - The passphrase for this private key as string
   * @throws {Error} if the key is already decrypted, or if decryption was not successful
   * @async
   */
  async decrypt(passphrase) {
    if (this.isDummy() || this.isStoredInHardware()) {
      return false;
    }

    if (this.isDecrypted()) {
      throw new Error('Key packet is already decrypted.');
    }

    let key;
    if (this.s2kUsage === 254 || this.s2kUsage === 253) {
      key = await produceEncryptionKey(this.s2k, passphrase, this.symmetric);
    } else if (this.s2kUsage === 255) {
      throw new Error('Encrypted private key is authenticated using an insecure two-byte hash');
    } else {
      throw new Error('Private key is encrypted using an insecure S2K function: unsalted MD5');
    }

    let cleartext;
    if (this.s2kUsage === 253) {
      const mode = crypto.getAEADMode(this.aead);
      const modeInstance = await mode(this.symmetric, key);
      try {
        cleartext = await modeInstance.decrypt(this.keyMaterial, this.iv.subarray(0, mode.ivLength), new Uint8Array());
      } catch (err) {
        if (err.message === 'Authentication tag mismatch') {
          throw new Error('Incorrect key passphrase: ' + err.message);
        }
        throw err;
      }
    } else {
      const cleartextWithHash = await crypto.mode.cfb.decrypt(this.symmetric, key, this.keyMaterial, this.iv);

      cleartext = cleartextWithHash.subarray(0, -20);
      const hash = await crypto.hash.sha1(cleartext);

      if (!util.equalsUint8Array(hash, cleartextWithHash.subarray(-20))) {
        throw new Error('Incorrect key passphrase');
      }
    }

    try {
      const { privateParams } = crypto.parsePrivateKeyParams(this.algorithm, cleartext, this.publicParams);
      this.privateParams = privateParams;
    } catch (err) {
      throw new Error('Error reading MPIs');
    }
    this.isEncrypted = false;
    this.keyMaterial = null;
    this.s2kUsage = 0;
  }

  /**
   * Checks that the key parameters are consistent
   * @throws {Error} if validation was not successful
   * @async
   */
  async validate() {
    if (this.isDummy()) {
      return;
    }

    if (this.isStoredInHardware()) {
      // do not validate private parts of the gnu-divert-to-card stub
      return;
    }

    if (!this.isDecrypted()) {
      throw new Error('Key is not decrypted');
    }

    let validParams;
    try {
      // this can throw if some parameters are undefined
      validParams = await crypto.validateParams(this.algorithm, this.publicParams, this.privateParams);
    } catch (_) {
      validParams = false;
    }
    if (!validParams) {
      throw new Error('Key is invalid');
    }
  }

  /**
   * @param {{hardwareKeys: HardwareKeys, algo: number}} [hardwareKeys_with_data]
   */
  async generate(bits, curve, hardwareKeys_with_data) {
    const { privateParams, publicParams } = await crypto.generateParams(this.algorithm, bits, curve, hardwareKeys_with_data);
    if (hardwareKeys_with_data) {
      const serialNumber = await hardwareKeys_with_data.hardwareKeys.serialNumber();
      this.setStoredInHardware(serialNumber);
    }
    this.privateParams = privateParams;
    this.publicParams = publicParams;
    this.isEncrypted = false;
  }

  /**
   * Clear private key parameters
   */
  clearPrivateParams() {
    if (this.isDummy() || this.isStoredInHardware()) {
      return;
    }

    Object.keys(this.privateParams).forEach(name => {
      const param = this.privateParams[name];
      param.fill(0);
      delete this.privateParams[name];
    });
    this.privateParams = null;
    this.isEncrypted = true;
  }
}

async function produceEncryptionKey(s2k, passphrase, algorithm) {
  const { keySize } = crypto.getCipher(algorithm);
  return s2k.produceKey(passphrase, keySize);
}

export default SecretKeyPacket;
