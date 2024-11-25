import enums from '../../../../enums';
import util from '../../../../util';
import { getRandomBytes } from '../../../random';

export async function generate(algo) {
  switch (algo) {
    case enums.publicKey.pqc_mldsa_ed25519: {
      const mldsaSeed = getRandomBytes(32);
      const { mldsaSecretKey, mldsaPublicKey } = await expandSecretSeed(algo, mldsaSeed);

      return { mldsaSeed, mldsaSecretKey, mldsaPublicKey };
    }
    default:
      throw new Error('Unsupported signature algorithm');
  }
}

/**
 * Expand ML-DSA secret seed and retrieve the secret and public key material
 * @param {module:enums.publicKey} algo - Public key algorithm
 * @param {Uint8Array} seed - secret seed to expand
 * @returns {Promise<{ mldsaPublicKey: Uint8Array, mldsaSecretKey: Uint8Array }>}
 */
export async function expandSecretSeed(algo, seed) {
  switch (algo) {
    case enums.publicKey.pqc_mldsa_ed25519: {
      const { ml_dsa65 } = await import('../noble_post_quantum');
      const { secretKey: mldsaSecretKey, publicKey: mldsaPublicKey } = ml_dsa65.keygen(seed);

      return { mldsaSecretKey, mldsaPublicKey };
    }
    default:
      throw new Error('Unsupported signature algorithm');
  }
}

export async function sign(algo, mldsaSecretKey, dataDigest) {
  switch (algo) {
    case enums.publicKey.pqc_mldsa_ed25519: {
      const { ml_dsa65 } = await import('../noble_post_quantum');
      const mldsaSignature = ml_dsa65.sign(mldsaSecretKey, dataDigest);
      return { mldsaSignature };
    }
    default:
      throw new Error('Unsupported signature algorithm');
  }
}

export async function verify(algo, mldsaPublicKey, dataDigest, mldsaSignature) {
  switch (algo) {
    case enums.publicKey.pqc_mldsa_ed25519: {
      const { ml_dsa65 } = await import('../noble_post_quantum');
      return ml_dsa65.verify(mldsaPublicKey, dataDigest, mldsaSignature);
    }
    default:
      throw new Error('Unsupported signature algorithm');
  }
}

export async function validateParams(algo, mldsaPublicKey, mldsaSeed) {
  switch (algo) {
    case enums.publicKey.pqc_mldsa_ed25519: {
      const { mldsaPublicKey: expectedPublicKey } = await expandSecretSeed(algo, mldsaSeed);
      return util.equalsUint8Array(mldsaPublicKey, expectedPublicKey);
    }
    default:
      throw new Error('Unsupported signature algorithm');
  }
}
