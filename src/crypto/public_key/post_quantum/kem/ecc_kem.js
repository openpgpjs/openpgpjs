import * as ecdhX from '../../elliptic/ecdh_x';
import { computeDigest } from '../../../hash';
import util from '../../../../util';
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
      const { ephemeralPublicKey: eccCipherText, sharedSecret: eccSharedSecret } = await ecdhX.generateEphemeralEncryptionMaterial(enums.publicKey.x25519, eccRecipientPublicKey);
      const eccKeyShare = await computeDigest(enums.hash.sha3_256, util.concatUint8Array([
        eccSharedSecret,
        eccCipherText,
        eccRecipientPublicKey
      ]));
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
      const eccSharedSecret = await ecdhX.recomputeSharedSecret(enums.publicKey.x25519, eccCipherText, eccPublicKey, eccSecretKey);
      const eccKeyShare = await computeDigest(enums.hash.sha3_256, util.concatUint8Array([
        eccSharedSecret,
        eccCipherText,
        eccPublicKey
      ]));
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
