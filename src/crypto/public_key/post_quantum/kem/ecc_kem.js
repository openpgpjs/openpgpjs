/** @access private */

import * as ecdhX from '../../elliptic/ecdh_x.js';
import enums from '../../../../enums.ts';

export async function generate(algo) {
  switch (algo) {
    case enums.publicKey.mlkem768X25519: {
      const { A, k } = await ecdhX.generate(enums.publicKey.x25519);
      return {
        eccPublicKey: A,
        eccSecretKey: k
      };
    }
    case enums.publicKey.mlkem1024X448: {
      const { A, k } = await ecdhX.generate(enums.publicKey.x448);
      return {
        eccPublicKey: A,
        eccSecretKey: k
      };
    }
    default:
      throw new Error('Unsupported KEM algorithm');
  }
}

export async function encaps(eccAlgo, eccRecipientPublicKey) {
  switch (eccAlgo) {
    case enums.publicKey.mlkem768X25519: {
      const { ephemeralPublicKey: eccCipherText, sharedSecret: eccKeyShare } = await ecdhX.generateEphemeralEncryptionMaterial(enums.publicKey.x25519, eccRecipientPublicKey);

      return {
        eccCipherText,
        eccKeyShare
      };
    }
    case enums.publicKey.mlkem1024X448: {
      const { ephemeralPublicKey: eccCipherText, sharedSecret: eccKeyShare } = await ecdhX.generateEphemeralEncryptionMaterial(enums.publicKey.x448, eccRecipientPublicKey);

      return {
        eccCipherText,
        eccKeyShare
      };
    }
    default:
      throw new Error('Unsupported KEM algorithm');
  }
}

export async function decaps(eccAlgo, eccCipherText, eccSecretKey, eccPublicKey) {
  switch (eccAlgo) {
    case enums.publicKey.mlkem768X25519: {
      const eccKeyShare = await ecdhX.recomputeSharedSecret(enums.publicKey.x25519, eccCipherText, eccPublicKey, eccSecretKey);
      return eccKeyShare;
    }
    case enums.publicKey.mlkem1024X448: {
      const eccKeyShare = await ecdhX.recomputeSharedSecret(enums.publicKey.x448, eccCipherText, eccPublicKey, eccSecretKey);
      return eccKeyShare;
    }
    default:
      throw new Error('Unsupported KEM algorithm');
  }
}

export async function validateParams(algo, eccPublicKey, eccSecretKey) {
  switch (algo) {
    case enums.publicKey.mlkem768X25519:
      return ecdhX.validateParams(enums.publicKey.x25519, eccPublicKey, eccSecretKey);
    case enums.publicKey.mlkem1024X448:
      return ecdhX.validateParams(enums.publicKey.x448, eccPublicKey, eccSecretKey);
    default:
      throw new Error('Unsupported KEM algorithm');
  }
}
