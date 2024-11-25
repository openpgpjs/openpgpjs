import enums from '../../../../enums';
import * as mldsa from './ml_dsa';
import * as eccdsa from './ecc_dsa';

export async function generate(algo) {
  switch (algo) {
    case enums.publicKey.pqc_mldsa_ed25519: {
      const { eccSecretKey, eccPublicKey } = await eccdsa.generate(algo);
      const { mldsaSeed, mldsaSecretKey, mldsaPublicKey } = await mldsa.generate(algo);
      return { eccSecretKey, eccPublicKey, mldsaSeed, mldsaSecretKey, mldsaPublicKey };
    }
    default:
      throw new Error('Unsupported signature algorithm');
  }
}

export async function sign(signatureAlgo, hashAlgo, eccSecretKey, eccPublicKey, mldsaSecretKey, dataDigest) {
  if (hashAlgo !== getRequiredHashAlgo(signatureAlgo)) {
    // The signature hash algo MUST be set to the specified algorithm, see
    // https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-pqc#section-5.2.1.
    throw new Error('Unexpected hash algorithm for PQC signature');
  }

  switch (signatureAlgo) {
    case enums.publicKey.pqc_mldsa_ed25519: {
      const { eccSignature } = await eccdsa.sign(signatureAlgo, hashAlgo, eccSecretKey, eccPublicKey, dataDigest);
      const { mldsaSignature } = await mldsa.sign(signatureAlgo, mldsaSecretKey, dataDigest);

      return { eccSignature, mldsaSignature };
    }
    default:
      throw new Error('Unsupported signature algorithm');
  }
}

export async function verify(signatureAlgo, hashAlgo, eccPublicKey, mldsaPublicKey, dataDigest, { eccSignature, mldsaSignature }) {
  if (hashAlgo !== getRequiredHashAlgo(signatureAlgo)) {
    // The signature hash algo MUST be set to the specified algorithm, see
    // https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-pqc#section-5.2.1.
    throw new Error('Unexpected hash algorithm for PQC signature');
  }

  switch (signatureAlgo) {
    case enums.publicKey.pqc_mldsa_ed25519: {
      const eccVerifiedPromise = eccdsa.verify(signatureAlgo, hashAlgo, eccPublicKey, dataDigest, eccSignature);
      const mldsaVerifiedPromise = mldsa.verify(signatureAlgo, mldsaPublicKey, dataDigest, mldsaSignature);
      const verified = await eccVerifiedPromise && await mldsaVerifiedPromise;
      return verified;
    }
    default:
      throw new Error('Unsupported signature algorithm');
  }
}

export function getRequiredHashAlgo(signatureAlgo) {
  // See https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-pqc#section-5.2.1.
  switch (signatureAlgo) {
    case enums.publicKey.pqc_mldsa_ed25519:
      return enums.hash.sha3_256;
    default:
      throw new Error('Unsupported signature algorithm');
  }
}

export async function validateParams(algo, eccPublicKey, eccSecretKey, mldsaPublicKey, mldsaSeed) {
  const eccValidationPromise = eccdsa.validateParams(algo, eccPublicKey, eccSecretKey);
  const mldsaValidationPromise = mldsa.validateParams(algo, mldsaPublicKey, mldsaSeed);
  const valid = await eccValidationPromise && await mldsaValidationPromise;
  return valid;
}
