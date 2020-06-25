const openpgp = typeof window !== 'undefined' && window.openpgp ? window.openpgp : require('../..');

const { readArmoredKey, generate, Key, readArmoredCleartextMessage, CleartextMessage, enums, PacketList, SignaturePacket } = openpgp;

const chai = require('chai');
chai.use(require('chai-as-promised'));

const expect = chai.expect;

async function generateTestData() {
  const victimPrivKey = await generate({
    userIds: ['Victim <victim@example.com>'],
    rsaBits: openpgp.util.getWebCryptoAll() ? 2048 : 1024,
    subkeys: [{
      sign: true
    }]
  });
  victimPrivKey.revocationSignatures = [];

  const attackerPrivKey = await generate({
    userIds: ['Attacker <attacker@example.com>'],
    rsaBits: openpgp.util.getWebCryptoAll() ? 2048 : 1024,
    subkeys: [],
    sign: false
  });
  attackerPrivKey.revocationSignatures = [];
  const signed = await openpgp.sign({
    message: await CleartextMessage.fromText('I am batman'),
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
  const fakeBindingSignature = new SignaturePacket();
  fakeBindingSignature.signatureType = enums.signature.subkeyBinding;
  fakeBindingSignature.publicKeyAlgorithm = attackerPrivKey.keyPacket.algorithm;
  fakeBindingSignature.hashAlgorithm = enums.hash.sha256;
  fakeBindingSignature.keyFlags = [enums.keyFlags.signData];
  await fakeBindingSignature.sign(attackerPrivKey.keyPacket, dataToSign);
  const newList = new PacketList();
  newList.concat([
    pktPrivAttacker[0], // attacker private key
    pktPrivAttacker[1], // attacker user
    pktPrivAttacker[2], // attacker self signature
    pktPubVictim[3], // victim subkey
    fakeBindingSignature // faked key binding
  ]);
  let fakeKey = new Key(newList);
  fakeKey = await readArmoredKey(await fakeKey.toPublic().armor());
  const verifyAttackerIsBatman = await openpgp.verify({
    message: (await readArmoredCleartextMessage(signed)),
    publicKeys: fakeKey,
    streaming: false
  });
  expect(verifyAttackerIsBatman.signatures[0].keyid.equals(victimPubKey.subKeys[0].getKeyId())).to.be.true;
  expect(verifyAttackerIsBatman.signatures[0].valid).to.be.null;
}

module.exports = () => it('Does not trust subkeys without Primary Key Binding Signature', testSubkeyTrust);
