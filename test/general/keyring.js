const openpgp = typeof window !== 'undefined' && window.openpgp ? window.openpgp : require('../../dist/openpgp');

const chai = require('chai');

const { expect } = chai;

const keyring = new openpgp.Keyring();

describe("Keyring", async function() {
  const user = 'whiteout.test@t-online.de';
  const passphrase = 'asdf';
  const keySize = 512;
  const keyId = 'f6f60e9b42cdff4c';
  const keyFingerP = '5856cef789c3a307e8a1b976f6f60e9b42cdff4c';
  const pubkey = '-----BEGIN PGP PUBLIC KEY BLOCK-----\n' +
      'Version: OpenPGP.js v.1.20131011\n' +
      'Comment: https://openpgpjs.org\n' +
      '\n' +
      'xk0EUlhMvAEB/2MZtCUOAYvyLFjDp3OBMGn3Ev8FwjzyPbIF0JUw+L7y2XR5\n' +
      'RVGvbK88unV3cU/1tOYdNsXI6pSp/Ztjyv7vbBUAEQEAAc0pV2hpdGVvdXQg\n' +
      'VXNlciA8d2hpdGVvdXQudGVzdEB0LW9ubGluZS5kZT7CXAQQAQgAEAUCUlhM\n' +
      'vQkQ9vYOm0LN/0wAAAW4Af9C+kYW1AvNWmivdtr0M0iYCUjM9DNOQH1fcvXq\n' +
      'IiN602mWrkd8jcEzLsW5IUNzVPLhrFIuKyBDTpLnC07Loce1\n' +
      '=6XMW\n' +
      '-----END PGP PUBLIC KEY BLOCK-----';
  const privkey = '-----BEGIN PGP PRIVATE KEY BLOCK-----\n' +
      'Version: OpenPGP.js v.1.20131011\n' +
      'Comment: https://openpgpjs.org\n' +
      '\n' +
      'xcBeBFJYTLwBAf9jGbQlDgGL8ixYw6dzgTBp9xL/BcI88j2yBdCVMPi+8tl0\n' +
      'eUVRr2yvPLp1d3FP9bTmHTbFyOqUqf2bY8r+72wVABEBAAH+AwMIhNB4ivtv\n' +
      'Y2xg6VeMcjjHxZayESHACV+nQx5Tx6ev6xzIF1Qh72fNPDppLhFSFOuTTMsU\n' +
      'kTN4c+BVYt29spH+cA1jcDAxQ2ULrNAXo+hheOqhpedTs8aCbcLFkJAS16hk\n' +
      'YSk4OnJgp/z24rVju1SHRSFbgundPzmNgXeX9e8IkviGhhQ11Wc5YwVkx03t\n' +
      'Z3MdDMF0jyhopbPIoBdyJB0dhvBh98w3JmwpYh9wjUA9MBHD1tvHpRmSZ3BM\n' +
      'UCmATn2ZLWBRWiYqFbgDnL1GM80pV2hpdGVvdXQgVXNlciA8d2hpdGVvdXQu\n' +
      'dGVzdEB0LW9ubGluZS5kZT7CXAQQAQgAEAUCUlhMvQkQ9vYOm0LN/0wAAAW4\n' +
      'Af9C+kYW1AvNWmivdtr0M0iYCUjM9DNOQH1fcvXqIiN602mWrkd8jcEzLsW5\n' +
      'IUNzVPLhrFIuKyBDTpLnC07Loce1\n' +
      '=ULta\n' +
      '-----END PGP PRIVATE KEY BLOCK-----';
  const keyId2 = 'ba993fc2aee18a3a';
  const keyFingerP2 = '560b7a7f3f9ab516b233b299ba993fc2aee18a3a';
  const subkeyId2 = 'f47c5210a8cc2740';
  const subkeyFingerP2 = '2a20c371141e000833848d85f47c5210a8cc2740';
  const pubkey2 =
      ['-----BEGIN PGP PUBLIC KEY BLOCK-----',
      'Version: GnuPG v2.0.22 (GNU/Linux)',
      '',
      'mQMuBFLVgdQRCACOlpq0cd1IazNjOEpWPZvx/O3JMbdDs3B3iCG0Mo5OUZ8lpKU5',
      'EslVgTd8IcUU14ZMOO7y91dw0KP4q61b4OIy7oVxzfFfKCC1s0Dc7GTay+qo5afJ',
      'wbWcgTyCIahTRmi5UepU7xdRHRMlqAclOwY2no8fw0JRQfFwRFCjbMdmvzC/k+Wo',
      'A42nn8YaSAG2v7OqF3rkYjkv/7iak48PO/l0Q13USAJLIWdHvRTir78mQUsEY0qR',
      'VoNqz5sMqakzhTvTav07EVy/1xC6GKoWXA9sdB/4r7+blVuu9M4yD40GkE69oAXO',
      'mz6tG3lRq41S0OSzNyDWtUQgMVF6wYqVxUGrAQDJM5A1rF1RKzFiHdkyy57E8LC1',
      'SIJyIXWJ0c5b8/olWQf9G5a17fMjkRTC3FO+ZHwFE1jIM6znYOF2GltDToLuJPq9',
      'lWrI7zVP9AJPwrUt7FK2MBNAvd1jKyIhdU98PBQ2pr+jmyqIycl9iDGXLDO7D7E/',
      'TBnxwQzoL/5b7UnPImuXOwv5JhVmyV2t003xjzb1EGggOnpKugUtVLps8JiLl9n+',
      'Nkj5wpU7NXbuHj2XGkkGmKkCIz4l0dJQR9V6svJV9By0RPgfGPXlN1VR6f2ounNy',
      '6REnDCQP9S3Li5eNcxlSGDIxIZL22j63sU/68GVlzqhVdGXxofv5jGtajiNSpPot',
      'ElZU0dusna4PzYmiBCsyN8jENWSzHLJ37N4ScN4b/gf6Axf9FU0PjzPBN1o9W6zj',
      'kpfhlSWDjE3BK8jJ7KvzecM2QE/iJsbuyKEsklw1v0MsRDsox5QlQJcKOoUHC+OT',
      'iKm8cnPckLQNPOw/kb+5Auz7TXBQ63dogDuqO8QGGOpjh8SIYbblYQI5ueo1Tix3',
      'PlSU36SzOQfxSOCeIomEmaFQcU57O1CLsRl//+5lezMFDovJyQHQZfiTxSGfPHij',
      'oQzEUyEWYHKQhIRV6s5VGvF3hN0t8fo0o57bzhV6E7IaSz2Cnm0O0S2PZt8DBN9l',
      'LYNw3cFgzMb/qdFJGR0JXz+moyAYh/fYMiryb6d8ghhvrRy0CrRlC3U5K6qiYfKu',
      'lLQURFNBL0VMRyA8ZHNhQGVsZy5qcz6IewQTEQgAIwUCUtWB1AIbAwcLCQgHAwIB',
      'BhUIAgkKCwQWAgMBAh4BAheAAAoJELqZP8Ku4Yo6Aa0A/1Kz5S8d9czLiDbrhSa/',
      'C1rQ5qiWpFq9UNTFg2P/gASvAP92TzUMLK2my8ew1xXShtrfXked5fkSuFrPlZBs',
      'b4Ta67kCDQRS1YHUEAgAxOKx4y5QD78uPLlgNBHXrcncUNBIt4IXBGjQTxpFcn5j',
      'rSuj+ztvXJQ8wCkx+TTb2yuL5M+nXd7sx4s+M4KZ/MZfI6ZX4lhcoUdAbB9FWiV7',
      'uNntyeFo8qgGM5at/Q0EsyzMSqbeBxk4bpd5MfYGThn0Ae2xaw3X94KaZ3LjtHo2',
      'V27FD+jvmmoAj9b1+zcO/pJ8SuojQmcnS4VDVV+Ba5WPTav0LzDdQXyGMZI9PDxC',
      'jAI2f1HjTuxIt8X8rAQSQdoMIcQRYEjolsXS6iob1eVigyL86hLJjI3VPn6kBCv3',
      'Tb+WXX+9LgSAt9yvv4HMwBLK33k6IH7M72SqQulZywADBQgAt2xVTMjdVyMniMLj',
      'Ed4HbUgwyCPkVkcA4zTXqfKu+dAe4dK5tre0clkXZVtR1V8RDAD0zaVyM030e2zb',
      'zn4cGKDL2dmwk2ZBeXWZDgGKoKvGKYf8PRpTAYweFzol3OUdfXH5SngOylCD4OCL',
      's4RSVkSsllIWqLpnS5IJFgt6PDVcQgGXo2ZhVYkoLNhWTIEBuJWIyc4Vj20YpTms',
      'lgHnjeq5rP6781MwAJQnViyJ2SziGK4/+3CoDiQLO1zId42otXBvsbUuLSL5peX4',
      'v2XNVMLJMY5iSfzbBWczecyapiQ3fbVtWgucgrqlrqM3546v+GdATBhGOu8ppf5j',
      '7d1A7ohhBBgRCAAJBQJS1YHUAhsMAAoJELqZP8Ku4Yo6SgoBAIVcZstwz4lyA2et',
      'y61IhKbJCOlQxyem+kepjNapkhKDAQDIDL38bZWU4Rm0nq82Xb4yaI0BCWDcFkHV',
      'og2umGfGng==',
      '=v3+L',
      '-----END PGP PUBLIC KEY BLOCK-----'].join('\n');
  const user3 = 'plain@email.org';
  const keyFingerP3 = 'f9972bf320a86a93c6614711ed241e1de755d53c';
  const pubkey3 =
      ['-----BEGIN PGP PUBLIC KEY BLOCK-----',
      '',
      'xo0EVe6wawEEAKG4LDE9946jdvvbfVTF9qWtOyxHYjb40z7hgcZsPEGd6QfN',
      'XbfNJBeQ5S9j/2jRu8NwBgdXIpMp4QwB2Q/cEp1rbw5kUVuRbhfsb2BzuiBr',
      'Q5jHa5oZSGbbLWRoOXTvJH8VE2gbKSj/km1VaXzq2Qmv+YIHxav1it7vNmg5',
      'E2kBABEBAAHND3BsYWluQGVtYWlsLm9yZ8K1BBABCAApBQJV7rBrBgsJCAcD',
      'AgkQ7SQeHedV1TwEFQgCCgMWAgECGQECGwMCHgEAAGJmBACVJPoFtW96UkIW',
      'GX1bgW99c4K87Me+5ZCHqPOdXFpRinAPBdJT9vkBWLb/aOQQCDWJvdVXKFLD',
      'FCbSBjcohR71n6145F5im8b0XzXnKh+MRRv/0UHiHGtB/Pkg38jbLeXbVfCM',
      '9JJm+s+PFef+8wN84sEtD/MX2cj61teuPf2VEs6NBFXusGsBBACoJW/0y5Ea',
      'FH0nJOuoenrEBZkFtGbdwo8A4ufCCrm9ppFHVVnw4uTPH9dOjw8IAnNy7wA8',
      '8yZCkreQ491em09knR7k2YdJccWwW8mGRILHQDDEPetZO1dSVW+MA9X7Pcle',
      'wbFEHCIkWEgymn3zenie1LXIljPzizHje5vWBrSlFwARAQABwp8EGAEIABMF',
      'AlXusGsJEO0kHh3nVdU8AhsMAACB2AP/eRJFAVTyiP5MnMjsSBuNMNBp1X0Y',
      '+RrWDpO9H929+fm9oFTedohf/Ja5w9hsRk2VzjLOXe/uHdrcgaBmAdFunbvv',
      'IWneczohBvLOarevZj1J+H3Ej/DVF2W7kJZLpvPfh7eo0biClS/GQUVw1rlE',
      'ph10hhUaSJ326LsFJccT3jk=',
      '=4jat',
      '-----END PGP PUBLIC KEY BLOCK-----'].join('\n');

  it('Import key pair', async function() {
    await keyring.load();
    // clear any keys already in the keychain
    keyring.clear();
    await keyring.store();
    await keyring.publicKeys.importKey(pubkey);
    await keyring.publicKeys.importKey(pubkey2);
    await keyring.privateKeys.importKey(privkey);
  });

  it('getKeysForId() - unknown id', function() {
    const keys = keyring.getKeysForId('01234567890123456');
    expect(keys).to.be.null;
  });

  it('getKeysForId() - valid id', function() {
    const keys = keyring.getKeysForId(keyId);
    // we get public and private key
    expect(keys).to.exist.and.have.length(2);
    expect(keys[0].getKeyId().toHex()).equals(keyId);
  });

  it('publicKeys.getForId() - unknown id', function() {
    const key = keyring.publicKeys.getForId('01234567890123456');
    expect(key).to.be.null;
  });

  it('publicKeys.getForId() - valid id', function() {
    const key = keyring.publicKeys.getForId(keyId);
    expect(key).to.exist.and.be.an.instanceof(openpgp.key.Key);
    expect(key.getKeyId().toHex()).equals(keyId);
  });

  it('privateKeys.getForId() - unknown id', function() {
    const key = keyring.privateKeys.getForId('01234567890123456');
    expect(key).to.be.null;
  });

  it('privateKeys.getForId() - valid id', function() {
    const key = keyring.privateKeys.getForId(keyId);
    expect(key).to.exist.and.be.an.instanceof(openpgp.key.Key);
    expect(key.getKeyId().toHex()).equals(keyId);
  });

  it('publicKeys.getForId() - subkey id', function() {
    const key = keyring.publicKeys.getForId(subkeyId2);
    expect(key).to.be.null;
  });

  it('publicKeys.getForId() - deep, including subkeys - subkey id', function() {
    const key = keyring.publicKeys.getForId(subkeyId2, true);
    expect(key).to.exist.and.be.an.instanceof(openpgp.key.Key);
    expect(key.getKeyId().toHex()).equals(keyId2);
  });

  it('getKeysForId() - unknown fingerprint', function() {
    const keys = keyring.getKeysForId('71130e8383bef9526e062600d5e9f93acbbc7275');
    expect(keys).to.be.null;
  });

  it('getKeysForId() - valid fingerprint', function() {
    const keys = keyring.getKeysForId(keyFingerP2);
    expect(keys).to.exist.and.have.length(1);
    expect(keys[0].getKeyId().toHex()).equals(keyId2);
  });

  it('publicKeys.getForId() - unknown fingerprint', function() {
    const key = keyring.publicKeys.getForId('71130e8383bef9526e062600d5e9f93acbbc7275');
    expect(key).to.be.null;
  });

  it('publicKeys.getForId() - valid fingerprint', function() {
    const key = keyring.publicKeys.getForId(keyFingerP2);
    expect(key).to.exist.and.be.an.instanceof(openpgp.key.Key);
    expect(key.getKeyId().toHex()).equals(keyId2);
  });

  it('publicKeys.getForId() - subkey fingerprint', function() {
    const key = keyring.publicKeys.getForId(subkeyFingerP2);
    expect(key).to.be.null;
  });

  it('publicKeys.getForId() - deep, including subkeys - subkey fingerprint', function() {
    const key = keyring.publicKeys.getForId(subkeyFingerP2, true);
    expect(key).to.exist.and.be.an.instanceof(openpgp.key.Key);
    expect(key.getKeyId().toHex()).equals(keyId2);
  });

  it('publicKeys.getForAddress() - unknown address', function() {
    const keys = keyring.publicKeys.getForAddress('nobody@example.com');
    expect(keys).to.be.empty;
  });

  it('publicKeys.getForAddress() - valid address', function() {
    const keys = keyring.publicKeys.getForAddress(user);
    expect(keys).to.exist.and.have.length(1);
  });

  it('publicKeys.getForAddress() - valid address, plain email user id', async function() {
    await keyring.publicKeys.importKey(pubkey3);
    const keys = keyring.publicKeys.getForAddress(user3);
    keyring.removeKeysForId(keyFingerP3);
    expect(keys).to.exist.and.have.length(1);
  });

  it('publicKeys.getForAddress() - address with regex special char |', function() {
    const keys = keyring.publicKeys.getForAddress('whiteout.test|not@t-online.de');
    expect(keys).to.be.empty;
  });

  it('publicKeys.getForAddress() - address with regex special char .', function() {
    const keys = keyring.publicKeys.getForAddress('wh.t.out.test@t-online.de');
    expect(keys).to.be.empty;
  });

  it('privateKeys.getForAddress() - unknown address', function() {
    const key = keyring.privateKeys.getForAddress('nobody@example.com');
    expect(key).to.be.empty;
  });

  it('privateKeys.getForAddress() - valid address', function() {
    const key = keyring.privateKeys.getForAddress(user);
    expect(key).to.exist.and.have.length(1);
  });

  it('store keys in localstorage', async function(){
    await keyring.store();
  });

  it('after loading from localstorage: getKeysForKeyId() - valid id', async function() {
    const keyring = new openpgp.Keyring();
    await keyring.load();
    const keys = keyring.getKeysForId(keyId);
    // we expect public and private key
    expect(keys).to.exist.and.have.length(2);
  });

  it('publicKeys.removeForId() - unknown id', function() {
    const key = keyring.publicKeys.removeForId('01234567890123456');
    expect(key).to.be.null;
  });

  it('publicKeys.removeForId() - valid id', function() {
    const key = keyring.publicKeys.removeForId(keyId);
    expect(key).to.exist.and.be.an.instanceof(openpgp.key.Key);
    expect(key.getKeyId().toHex()).equals(keyId);
    expect(keyring.publicKeys.keys).to.exist.and.have.length(1);
  });

  it('publicKeys.removeForId() - unknown fingerprint', function() {
    const key = keyring.publicKeys.removeForId('71130e8383bef9526e062600d5e9f93acbbc7275');
    expect(key).to.be.null;
    expect(keyring.publicKeys.keys).to.exist.and.have.length(1);
  });

  it('publicKeys.removeForId() - valid fingerprint', function() {
    const key = keyring.publicKeys.removeForId(keyFingerP2);
    expect(key).to.exist.and.be.an.instanceof(openpgp.key.Key);
    expect(key.getKeyId().toHex()).equals(keyId2);
    expect(keyring.publicKeys.keys).to.be.empty;
  });

  it('customize localstorage itemname', async function() {
    const localstore1 = new openpgp.Keyring.localstore('my-custom-prefix-');
    const localstore2 = new openpgp.Keyring.localstore('my-custom-prefix-');
    const localstore3 = new openpgp.Keyring.localstore();
    await localstore3.storePublic([]);
    const key = (await openpgp.key.readArmored(pubkey)).keys[0];
    await localstore1.storePublic([key]);
    expect((await localstore2.loadPublic())[0].getKeyId().equals(key.getKeyId())).to.be.true;
    expect(await localstore3.loadPublic()).to.have.length(0);
  });

  it('emptying keyring and storing removes keys', async function() {
    const key = (await openpgp.key.readArmored(pubkey)).keys[0];

    const localstore = new openpgp.Keyring.localstore('remove-prefix-');

    await localstore.storePublic([]);
    expect(localstore.storage.getItem('remove-prefix-public-keys')).to.be.null;

    await localstore.storePublic([key]);
    expect(localstore.storage.getItem('remove-prefix-public-keys')).to.be.not.null;

    await localstore.storePublic([]);
    expect(localstore.storage.getItem('remove-prefix-public-keys')).to.be.null;
  });

  it('removeKeysForId() - unknown id', async function() {
    await keyring.publicKeys.importKey(pubkey);
    await keyring.publicKeys.importKey(pubkey2);
    await keyring.privateKeys.importKey(privkey);
    expect(keyring.publicKeys.keys).to.have.length(2);
    expect(keyring.privateKeys.keys).to.have.length(1);
    const keys = keyring.removeKeysForId('01234567890123456');
    expect(keys).to.be.null;
    expect(keyring.publicKeys.keys).to.have.length(2);
    expect(keyring.privateKeys.keys).to.have.length(1);
  });

  it('removeKeysForId() - valid id', function() {
    const keys = keyring.removeKeysForId(keyId);
    expect(keys).to.have.length(2);
    expect(keyring.publicKeys.keys).to.have.length(1);
    expect(keyring.privateKeys.keys).to.have.length(0);
  });

  it('removeKeysForId() - unknown fingerprint', async function() {
    await keyring.publicKeys.importKey(pubkey);
    await keyring.publicKeys.importKey(pubkey2);
    await keyring.privateKeys.importKey(privkey);
    expect(keyring.publicKeys.keys).to.have.length(2);
    expect(keyring.privateKeys.keys).to.have.length(1);
    const keys = keyring.removeKeysForId('71130e8383bef9526e062600d5e9f93acbbc7275');
    expect(keys).to.be.null;
    expect(keyring.publicKeys.keys).to.have.length(2);
    expect(keyring.privateKeys.keys).to.have.length(1);
  });

  it('removeKeysForId() - valid fingerprint', function() {
    const keys = keyring.removeKeysForId(keyFingerP);
    expect(keys).to.have.length(2);
    expect(keyring.publicKeys.keys).to.have.length(1);
    expect(keyring.privateKeys.keys).to.have.length(0);
  });

});

