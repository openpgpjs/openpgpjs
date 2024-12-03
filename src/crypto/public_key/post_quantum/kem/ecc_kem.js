import * as ecdhX from '../../elliptic/ecdh_x';
import enums from '../../../../enums';

export async function generate(algo) {
  switch (algo) {
    case enums.publicKey.pqc_mlkem_x25519: {
      const { A, k } = await ecdhX.generate(enums.publicKey.x25519);
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
    case enums.publicKey.pqc_mlkem_x25519: {
      const { ephemeralPublicKey: eccCipherText, sharedSecret: eccKeyShare } = await ecdhX.generateEphemeralEncryptionMaterial(enums.publicKey.x25519, eccRecipientPublicKey);

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
    case enums.publicKey.pqc_mlkem_x25519: {
      const eccKeyShare = await ecdhX.recomputeSharedSecret(enums.publicKey.x25519, eccCipherText, eccPublicKey, eccSecretKey);
      return eccKeyShare;
    }
    default:
      throw new Error('Unsupported KEM algorithm');
  }
}

export async function validateParams(algo, eccPublicKey, eccSecretKey) {
  switch (algo) {
    case enums.publicKey.pqc_mlkem_x25519:
      return ecdhX.validateParams(enums.publicKey.x25519, eccPublicKey, eccSecretKey);
    default:
      throw new Error('Unsupported KEM algorithm');
  }
}
