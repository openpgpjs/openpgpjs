const openpgp = typeof window !== 'undefined' && window.openpgp ? window.openpgp : require('../../dist/openpgp');

const { key, cleartext, enums, packet: { List, Signature } } = openpgp;

const chai = require('chai');
chai.use(require('chai-as-promised'));

const expect = chai.expect;

async function generateTestData() {
  const victimPrivKey = await key.generate({
    userIds: ['Victim <victim@example.com>'],
    rsaBits: openpgp.util.getWebCryptoAll() ? 2048 : 1024,
    subkeys: [{
      sign: true
    }]
  });
  victimPrivKey.revocationSignatures = [];

  const attackerPrivKey = await key.generate({
    userIds: ['Attacker <attacker@example.com>'],
    rsaBits: openpgp.util.getWebCryptoAll() ? 2048 : 1024,
    subkeys: [],
    sign: false
  });
  attackerPrivKey.revocationSignatures = [];
  const signed = await openpgp.sign({
    message: await cleartext.fromText('I am batman'),
    privateKeys: victimPrivKey,
    streaming: false,
    armor: true
  });
  return {
    victimPubKey: victimPrivKey.toPublic(),
    attackerPrivKey,
    signed
  };
}

async function testSubkeyTrust() {
  // attacker only has his own private key,
  // the victim's public key and a signed message
  const { victimPubKey, attackerPrivKey, signed } = await generateTestData();

  const pktPubVictim = victimPubKey.toPacketlist();
  const pktPrivAttacker = attackerPrivKey.toPacketlist();
  const dataToSign = {
    key: attackerPrivKey.toPublic().keyPacket,
    bind: pktPubVictim[3] // victim subkey
  };
  const fakeBindingSignature = new Signature();
  fakeBindingSignature.signatureType = enums.signature.subkey_binding;
  fakeBindingSignature.publicKeyAlgorithm = attackerPrivKey.keyPacket.algorithm;
  fakeBindingSignature.hashAlgorithm = enums.hash.sha256;
  fakeBindingSignature.keyFlags = [enums.keyFlags.sign_data];
  await fakeBindingSignature.sign(attackerPrivKey.keyPacket, dataToSign);
  const newList = new List();
  newList.concat([
    pktPrivAttacker[0], // attacker private key
    pktPrivAttacker[1], // attacker user
    pktPrivAttacker[2], // attacker self signature
    pktPubVictim[3], // victim subkey
    fakeBindingSignature // faked key binding
  ]);
  let fakeKey = new key.Key(newList);
  fakeKey = (await key.readArmored(await fakeKey.toPublic().armor())).keys[0];
  const verifyAttackerIsBatman = await openpgp.verify({
    message: (await cleartext.readArmored(signed.data)),
    publicKeys: fakeKey,
    streaming: false
  });
  expect(verifyAttackerIsBatman.signatures[0].keyid.equals(victimPubKey.subKeys[0].getKeyId())).to.be.true;
  expect(verifyAttackerIsBatman.signatures[0].valid).to.be.null;
}

it('Does not trust subkeys without Primary Key Binding Signature', testSubkeyTrust);
