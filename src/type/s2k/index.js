import defaultConfig from '../../config';
import Argon2S2k, { Argon2OutOfMemoryError } from './argon2';
import OtherS2K from './generic';
import enums from '../../enums';

const allowedDefaultS2KTypes = new Set([enums.s2k.argon2, enums.s2k.iterated]);

/**
 * Instantiate a new S2K instance of the given type
 * @param {module:enums.s2k} [type] - If not specified, `config.s2kTypes` is used
 * @oaram {Object} [config]
 * @returns {Object} New s2k object
 * @throws {Error} for unknown or unsupported types
 */
export function newS2KFromType(maybeType, config = defaultConfig) {
  if (!maybeType && !allowedDefaultS2KTypes.has(config.s2kType)) {
    throw new Error('The provided `config.s2kType` value is not allowed');
  }

  const type = maybeType || config.s2kType;

  switch (type) {
    case enums.s2k.argon2:
      return new Argon2S2k(config);
    case enums.s2k.iterated:
    case enums.s2k.gnu:
    case enums.s2k.salted:
    case enums.s2k.simple:
      return new OtherS2K(type, config);
    default:
      throw new Error(`Unsupported S2K type ${type}`);
  }
}

export { Argon2OutOfMemoryError };
