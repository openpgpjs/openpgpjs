/**
 * @fileoverview This module contains the template for hardware keys implementation.
 * @see module:config/config
 * @module hardwareKeys
 */

/* eslint-disable no-unused-vars */

/**
 * The abstract class with callbacks to implement for the on-hardware keys processing.
 */
export class HardwareKeys {
  constructor() {
    if (this.constructor === HardwareKeys) {
      throw new Error('Abstract classes can\'t be instantiated.');
    }
  }

  /**
   * Return serial number of the device containing the private keys. Only the first 16 bytes will be used.
   * @returns {Promise<Uint8Array>} The serial number, 16 bytes
   * @async
   */
  async serialNumber() {
    throw new Error('Method must be implemented.');
  }

  /**
   * Return the creation date of the keys
   * @returns {Date} The keys creation date
   */
  date() {
    throw new Error('Method must be implemented.');
  }


  /**
   * Generate ECDHE secret from private key and public part of ephemeral key
   *
   * @param {Object} obj - An object argument for destructuring
   // * @param {string} obj.curveName - Elliptic curve name
   * @param {EllipticCurveName} obj.curveName - Elliptic curve name -
   *    any of 'ed25519' | 'curve25519' | 'p256' | 'p384' | 'p521' | 'secp256k1' | 'brainpoolP256r1' |
   *    'brainpoolP384r1' | 'brainpoolP512r1'
   * @param {Uint8Array} obj.publicEphemeral - Public part of ephemeral key
   * @param {Uint8Array} obj.publicKey - Recipient public key
   * @param {Uint8Array} obj.privateKey - Recipient private key
   * @returns {Promise<Uint8Array>} the shared key
   * @async
   */
  async deriveKey({ curveName, publicEphemeral, publicKey, privateKey }) {
    throw new Error('Method must be implemented.');
  }

  /**
   * Sign a message using the provided key
   *
   * @param {Object} obj - An object argument for destructuring
   * @param {module:type/oid} obj.oid - Elliptic curve object identifier
   * @param {module:enums.hash} obj.hashAlgo - Hash algorithm
   * @param {Uint8Array} obj.data - Message to sign
   * @param {Uint8Array} obj.Q - Recipient public key
   * @param {Uint8Array} obj.d - Recipient private key
   * @param {Uint8Array} obj.hashed - The hashed message
   * @returns {Promise<{
   *   r: Uint8Array,
   *   s: Uint8Array
   * }>} Generated signature, 32 bytes in each field
   * @async
   */
  async sign({ oid, hashAlgo, data, Q, d, hashed }) {
    throw new Error('Method must be implemented.');
  }

  /**
   * Wrap the hardware keys into a new key.
   *
   * The secret key material is not present in the result. Instead, the IV field contains the serial number of the device,
   * to which the secret key material processing is delegated to. The privateKey field is returned for the backwards
   * compatibility.
   *
   * @param {Object} obj - An object argument for destructuring
   * @param {enums.publicKey} obj.algorithmName - Type of the algorithm
   * @param {string} obj.curveName - Curve name
   * @param {number} obj.rsaBits - RSA key length in bits
   * @returns {Promise<{
   *   publicKey: Uint8Array,
   *   privateKey: Uint8Array
   * }>} Generated key material
   * @async
   */
  async generate({ algorithmName, curveName, rsaBits }) {
    throw new Error('Method must be implemented.');
  }
}

export default { HardwareKeys };
