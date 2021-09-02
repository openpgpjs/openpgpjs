import enums from '../../enums';
import util from '../../util';

const supportedHashAlgos = new Set([enums.hash.sha1, enums.hash.sha256, enums.hash.sha512]);

const webCrypto = util.getWebCrypto();
const nodeCrypto = util.getNodeCrypto();

export async function generate(hashAlgo) {
  if (!supportedHashAlgos.has(hashAlgo)) {
    throw new Error('Unsupported hash algorithm.');
  }
  const hashName = enums.read(enums.webHash, hashAlgo);

  const crypto = webCrypto || nodeCrypto.webcrypto.subtle;
  const key = await crypto.generateKey(
    {
      name: 'HMAC',
      hash: { name: hashName }
    },
    true,
    ['sign', 'verify']
  );
  const exportedKey = await crypto.exportKey('raw', key);
  return new Uint8Array(exportedKey);
}

export async function sign(hashAlgo, key, data) {
  if (!supportedHashAlgos.has(hashAlgo)) {
    throw new Error('Unsupported hash algorithm.');
  }
  const hashName = enums.read(enums.webHash, hashAlgo);

  const crypto = webCrypto || nodeCrypto.webcrypto.subtle;
  const importedKey = await crypto.importKey(
    'raw',
    key,
    {
      name: 'HMAC',
      hash: { name: hashName }
    },
    false,
    ['sign']
  );
  const mac = await crypto.sign('HMAC', importedKey, data);
  return new Uint8Array(mac);
}

export async function verify(hashAlgo, key, mac, data) {
  if (!supportedHashAlgos.has(hashAlgo)) {
    throw new Error('Unsupported hash algorithm.');
  }
  const hashName = enums.read(enums.webHash, hashAlgo);

  const crypto = webCrypto || nodeCrypto.webcrypto.subtle;
  const importedKey = await crypto.importKey(
    'raw',
    key,
    {
      name: 'HMAC',
      hash: { name: hashName }
    },
    false,
    ['verify']
  );
  return crypto.verify('HMAC', importedKey, mac, data);
}
