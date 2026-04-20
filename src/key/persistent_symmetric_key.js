/** @access public */

import PrivateKey from './private_key';

/**
 * Class that represents a persistent symmetric key
 */
class PersistentSymmetricKey extends PrivateKey {
  /**
   * Verify primary key. Checks for revocation signatures, expiration time
   * and valid self signature. Throws if the primary key is invalid.
   * @param {Date} [date] - Use the given date for verification instead of the current time
   * @param {Object} [userID] - User ID
   * @param {Object} [config] - Full configuration, defaults to openpgp.config
   * @throws {Error} If key verification failed
   * @async
   */
  async verifyPrimaryKey(_date, _userID, _config) {
    // Nothing to do as a persistent symmetric key can't be revoked or expired.
  }

  /**
   * Returns last created key or key by given keyID that is available for signing and verification
   * @param  {module:type/keyid~KeyID} [keyID] - key ID of a specific key to retrieve
   * @param  {Date} [date] - use the fiven date date to  to check key validity instead of the current date
   * @param  {Object} [userID] - filter keys for the given user ID
   * @param  {Object} [config] - Full configuration, defaults to openpgp.config
   * @returns {Promise<Key|Subkey>} signing key
   * @throws if no valid signing key was found
   * @async
   */
  // eslint-disable-next-line @typescript-eslint/require-await
  async getSigningKey(keyID = null, _date, _userID, _config) {
    const primaryKey = this.keyPacket;
    if (!keyID || primaryKey.getKeyID().equals(keyID)) {
      if (!this.isDecrypted()) {
        // Persistent Symmetric Keys need to be decrypted even for verifying
        throw new Error('Persistent Symmetric Key is not decrypted');
      }
      return this;
    }
    throw new Error('Could not find matching signing key packet in key ' + this.getKeyID().toHex());
  }

  /**
   * Returns last created key or key by given keyID that is available for encryption or decryption
   * @param  {module:type/keyid~KeyID} [keyID] - key ID of a specific key to retrieve
   * @param  {Date}   [date] - use the fiven date date to  to check key matchingity instead of the current date
   * @param  {Object} [userID] - filter keys for the given user ID
   * @param  {Object} [config] - Full configuration, defaults to openpgp.config
   * @returns {Promise<Key|Subkey>} encryption key
   * @throws if no valid encryption key was found
   * @async
   */
  // eslint-disable-next-line @typescript-eslint/require-await
  async getEncryptionKey(keyID = null, _date, _userID, _config) {
    const primaryKey = this.keyPacket;
    if (!keyID || primaryKey.getKeyID().equals(keyID)) {
      if (!this.isDecrypted()) {
        // Persistent Symmetric Keys need to be decrypted even for encrypting
        throw new Error('Persistent Symmetric Key is not decrypted');
      }
      return this;
    }
    throw new Error('Could not find matching encryption key packet in key ' + this.getKeyID().toHex());
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
  // eslint-disable-next-line @typescript-eslint/require-await
  async getDecryptionKeys(keyID = null, _date, _userID, _config) {
    const primaryKey = this.keyPacket;
    if (!keyID || primaryKey.getKeyID().equals(keyID, true)) {
      if (primaryKey.isDummy()) {
        throw new Error('Gnu-dummy key packets cannot be used for decryption');
      } else {
        return [this];
      }
    }
    return [];
  }

  /**
   * Check whether the private and public primary key parameters correspond
   * @param {Object} [config] - Full configuration, defaults to openpgp.config
   * @throws {Error} if validation was not successful and the key cannot be trusted
   * @async
   */
  // eslint-disable-next-line @typescript-eslint/require-await
  async validate(_config) {
    // Nothing to do as a persistent symmetric key must use modern AEAD.
  }

  // eslint-disable-next-line @typescript-eslint/require-await
  async revoke(_reasonForRevocation, _date, _config) {
    throw new Error('Persistent Symmetric Keys cannot be revoked');
  }

  // eslint-disable-next-line @typescript-eslint/require-await
  async addSubkey(_options = {}) {
    throw new Error('Persistent Symmetric Keys cannot have subkeys');
  }

  toPublic() {
    throw new Error('Persistent Symmetric Keys do not have a public key');
  }
}

export default PersistentSymmetricKey;
