const openpgp = typeof window !== 'undefined' && window.openpgp ? window.openpgp : require('../..');

const { readKey, Key, readCleartextMessage, createCleartextMessage, enums, PacketList, SignaturePacket } = openpgp;

const chai = require('chai');
chai.use(require('chai-as-promised'));

const expect = chai.expect;

async function generateTestData() {
  const victimPrivKey = (await openpgp.generateKey({
    userIDs: [{ name: 'Victim', email: 'victim@example.com' }],
    type: 'rsa',
    rsaBits: 2048,
    subkeys: [{
      sign: true
    }]
  })).key;
  victimPrivKey.revocationSignatures = [];

  const attackerPrivKey = (await openpgp.generateKey({
    userIDs: [{ name: 'Attacker', email: 'attacker@example.com' }],
    type: 'rsa',
    rsaBits: 2048,
    subkeys: [],
    sign: false
  })).key;
  attackerPrivKey.revocationSignatures = [];
  const signed = await openpgp.sign({
    message: await createCleartextMessage({ text: 'I am batman' }),
    privateKeys: victimPrivKey,
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
  newList.push(
    pktPrivAttacker[0], // attacker private key
    pktPrivAttacker[1], // attacker user
    pktPrivAttacker[2], // attacker self signature
    pktPubVictim[3], // victim subkey
    fakeBindingSignature // faked key binding
  );
  let fakeKey = new Key(newList);
  fakeKey = await readKey({ armoredKey: await fakeKey.toPublic().armor() });
  const verifyAttackerIsBatman = await openpgp.verify({
    message: await readCleartextMessage({ cleartextMessage: signed }),
    publicKeys: fakeKey
  });
  expect(verifyAttackerIsBatman.signatures[0].keyID.equals(victimPubKey.subKeys[0].getKeyID())).to.be.true;
  expect(verifyAttackerIsBatman.signatures[0].valid).to.be.false;
  expect(verifyAttackerIsBatman.signatures[0].error).to.match(/Could not find valid signing key packet/);
}

module.exports = () => it('Does not trust subkeys without Primary Key Binding Signature', testSubkeyTrust);
