import defaultConfig from '../../config';
import enums from '../../enums';
import util from '../../util';
import crypto from '../../crypto';

const ARGON2_TYPE = 0x02; // id
const ARGON2_VERSION = 0x13;
const ARGON2_SALT_SIZE = 16;

export class Argon2OutOfMemoryError extends Error {
  constructor(...params) {
    super(...params);

    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, Argon2OutOfMemoryError);
    }

    this.name = 'Argon2OutOfMemoryError';
  }
}

// cache argon wasm module
let loadArgonWasmModule;
let argon2Promise;
// reload wasm module above this treshold, to deallocated used memory
const ARGON2_WASM_MEMORY_THRESHOLD_RELOAD = 2 << 19;

class Argon2S2K {
  /**
  * @param {Object} [config] - Full configuration, defaults to openpgp.config
  */
  constructor(config = defaultConfig) {
    const { passes, parallelism, memoryExponent } = config.s2kArgon2Params;

    this.type = 'argon2';
    /**  @type {Uint8Array} 16 bytes of salt */
    this.salt = null;
    /** @type {Integer} number of passes */
    this.t = passes;
    /** @type {Integer} degree of parallelism (lanes) */
    this.p = parallelism;
    /** @type {Integer} exponent indicating memory size */
    this.encodedM = memoryExponent;
  }

  generateSalt() {
    this.salt = crypto.random.getRandomBytes(ARGON2_SALT_SIZE);
  }

  /**
  * Parsing function for argon2 string-to-key specifier.
  * @param {Uint8Array} bytes - Payload of argon2 string-to-key specifier
  * @returns {Integer} Actual length of the object.
  */
  read(bytes) {
    let i = 0;

    this.salt = bytes.subarray(i, i + 16);
    i += 16;

    this.t = bytes[i++];
    this.p = bytes[i++];
    this.encodedM = bytes[i++]; // memory size exponent, one-octect

    return i;
  }

  /**
  * Serializes s2k information
  * @returns {Uint8Array} Binary representation of s2k.
  */
  write() {
    const arr = [
      new Uint8Array([enums.write(enums.s2k, this.type)]),
      this.salt,
      new Uint8Array([this.t, this.p, this.encodedM])
    ];

    return util.concatUint8Array(arr);
  }

  /**
  * Produces a key using the specified passphrase and the defined
  * hashAlgorithm
  * @param {String} passphrase - Passphrase containing user input
  * @returns {Promise<Uint8Array>} Produced key with a length corresponding to `keySize`
  * @throws {Argon2OutOfMemoryError|Errors}
  * @async
  */
  async produceKey(passphrase, keySize) {
    const decodedM = 2 << (this.encodedM - 1);
    if (decodedM < 8 * this.p || this.encodedM > 31) {
      throw new Error('Memory size and parallelism settings are incompatible.');
    }

    try {
      if (!argon2Promise) { // first load
        loadArgonWasmModule = loadArgonWasmModule || (await import('argon2id')).default;
        argon2Promise = loadArgonWasmModule();
      }
      // important to keep local ref to argon2 in case the module is reloaded by another instance
      const argon2 = await argon2Promise;

      const passwordBytes = util.encodeUTF8(passphrase);
      const hash = argon2({
        version: ARGON2_VERSION,
        type: ARGON2_TYPE,
        password: passwordBytes,
        salt: this.salt,
        tagLength: keySize,
        memorySize: decodedM,
        parallelism: this.p,
        passes: this.t
      });

      // a lot of memory was used, reload to deallocate
      if (decodedM > ARGON2_WASM_MEMORY_THRESHOLD_RELOAD) {
        // it will be awaited if needed at the next `produceKey` invocation
        argon2Promise = loadArgonWasmModule();
      }
      return hash;
    } catch (e) {
      if (e.message && (
        e.message.includes('Unable to grow instance memory') || // Chrome
        e.message.includes('failed to grow memory') || // Firefox
        e.message.includes('WebAssembly.Memory.grow') || // Safari
        e.message.includes('Out of memory') // Safari iOS
      )) {
        throw new Argon2OutOfMemoryError('Could not allocate required memory for Argon2');
      } else {
        throw e;
      }
    }
  }
}

export default Argon2S2K;
