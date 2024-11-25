import enums from '../../../../enums';
import util from '../../../../util';
import { getRandomBytes } from '../../../random';

export async function generate(algo) {
  switch (algo) {
    case enums.publicKey.pqc_mlkem_x25519: {
      const mlkemSeed = getRandomBytes(64);
      const { mlkemSecretKey, mlkemPublicKey } = await expandSecretSeed(algo, mlkemSeed);

      return { mlkemSeed, mlkemSecretKey, mlkemPublicKey };
    }
    default:
      throw new Error('Unsupported KEM algorithm');
  }
}

/**
 * Expand ML-KEM secret seed and retrieve the secret and public key material
 * @param {module:enums.publicKey} algo - Public key algorithm
 * @param {Uint8Array} seed - secret seed to expand
 * @returns {Promise<{ mlkemPublicKey: Uint8Array, mlkemSecretKey: Uint8Array }>}
 */
export async function expandSecretSeed(algo, seed) {
  switch (algo) {
    case enums.publicKey.pqc_mlkem_x25519: {
      const { ml_kem768 } = await import('../noble_post_quantum');
      const { publicKey: encapsulationKey, secretKey: decapsulationKey } = ml_kem768.keygen(seed);

      return { mlkemPublicKey: encapsulationKey, mlkemSecretKey: decapsulationKey };
    }
    default:
      throw new Error('Unsupported KEM algorithm');
  }
}

export async function encaps(algo, mlkemRecipientPublicKey) {
  switch (algo) {
    case enums.publicKey.pqc_mlkem_x25519: {
      const { ml_kem768 } = await import('../noble_post_quantum');
      const { cipherText: mlkemCipherText, sharedSecret: mlkemKeyShare } = ml_kem768.encapsulate(mlkemRecipientPublicKey);

      return { mlkemCipherText, mlkemKeyShare };
    }
    default:
      throw new Error('Unsupported KEM algorithm');
  }
}

export async function decaps(algo, mlkemCipherText, mlkemSecretKey) {
  switch (algo) {
    case enums.publicKey.pqc_mlkem_x25519: {
      const { ml_kem768 } = await import('../noble_post_quantum');
      const mlkemKeyShare = ml_kem768.decapsulate(mlkemCipherText, mlkemSecretKey);

      return mlkemKeyShare;
    }
    default:
      throw new Error('Unsupported KEM algorithm');
  }
}

export async function validateParams(algo, mlkemPublicKey, mlkemSeed) {
  switch (algo) {
    case enums.publicKey.pqc_mlkem_x25519: {
      const { mlkemPublicKey: expectedPublicKey } = await expandSecretSeed(algo, mlkemSeed);
      return util.equalsUint8Array(mlkemPublicKey, expectedPublicKey);
    }
    default:
      throw new Error('Unsupported KEM algorithm');
  }
}
