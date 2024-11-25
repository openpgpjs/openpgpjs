import * as eddsa from '../../elliptic/eddsa';
import enums from '../../../../enums';

export async function generate(algo) {
  switch (algo) {
    case enums.publicKey.pqc_mldsa_ed25519: {
      const { A, seed } = await eddsa.generate(enums.publicKey.ed25519);
      return {
        eccPublicKey: A,
        eccSecretKey: seed
      };
    }
    default:
      throw new Error('Unsupported signature algorithm');
  }
}

export async function sign(signatureAlgo, hashAlgo, eccSecretKey, eccPublicKey, dataDigest) {
  switch (signatureAlgo) {
    case enums.publicKey.pqc_mldsa_ed25519: {
      const { RS: eccSignature } = await eddsa.sign(enums.publicKey.ed25519, hashAlgo, null, eccPublicKey, eccSecretKey, dataDigest);

      return { eccSignature };
    }
    default:
      throw new Error('Unsupported signature algorithm');
  }
}

export async function verify(signatureAlgo, hashAlgo, eccPublicKey, dataDigest, eccSignature) {
  switch (signatureAlgo) {
    case enums.publicKey.pqc_mldsa_ed25519:
      return eddsa.verify(enums.publicKey.ed25519, hashAlgo, { RS: eccSignature }, null, eccPublicKey, dataDigest);
    default:
      throw new Error('Unsupported signature algorithm');
  }
}

export async function validateParams(algo, eccPublicKey, eccSecretKey) {
  switch (algo) {
    case enums.publicKey.pqc_mldsa_ed25519:
      return eddsa.validateParams(enums.publicKey.ed25519, eccPublicKey, eccSecretKey);
    default:
      throw new Error('Unsupported signature algorithm');
  }
}
