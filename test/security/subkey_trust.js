const { use: chaiUse, expect } = require('chai');
chaiUse(require('chai-as-promised'));

const openpgp = typeof window !== 'undefined' && window.openpgp ? window.openpgp : require('../..');

const { readKey, PublicKey, readCleartextMessage, createCleartextMessage, enums, PacketList, SignaturePacket } = openpgp;

async function generateTestData() {
  const { privateKey: victimPrivKey } = await openpgp.generateKey({
    userIDs: [{ name: 'Victim', email: 'victim@example.com' }],
    type: 'rsa',
    rsaBits: 2048,
    subkeys: [{ sign: true }],
    format: 'object'
  });

  const { privateKey: attackerPrivKey } = await openpgp.generateKey({
    userIDs: [{ name: 'Attacker', email: 'attacker@example.com' }],
    type: 'rsa',
    rsaBits: 2048,
    subkeys: [],
    format: 'object'
  });

  const signed = await openpgp.sign({
    message: await createCleartextMessage({ text: 'I am batman' }),
    signingKeys: victimPrivKey
  });
  return {
    victimPubKey: victimPrivKey.toPublic(),
    attackerPrivKey,
    signed
  };
}

module.exports = () => it('Does not trust subkeys without Primary Key Binding Signature', async function() {
  // attacker only has his own private key,
  // the victim's public key and a signed message
  const { victimPubKey, attackerPrivKey, signed } = await generateTestData();

  const pktPubVictim = victimPubKey.toPacketList();
  const pktPubAttacker = attackerPrivKey.toPublic().toPacketList();
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
    pktPubAttacker[0], // attacker private key
    pktPubAttacker[1], // attacker user
    pktPubAttacker[2], // attacker self signature
    pktPubVictim[3], // victim subkey
    fakeBindingSignature // faked key binding
  );
  let fakeKey = new PublicKey(newList);
  fakeKey = await readKey({ armoredKey: await fakeKey.toPublic().armor() });
  const verifyAttackerIsBatman = await openpgp.verify({
    message: await readCleartextMessage({ cleartextMessage: signed }),
    verificationKeys: fakeKey
  });
  // expect the signature to have the expected keyID, but be invalid due to fake key binding signature in the subkey
  expect(verifyAttackerIsBatman.signatures[0].keyID.equals(victimPubKey.subkeys[0].getKeyID())).to.be.true;
  await expect(verifyAttackerIsBatman.signatures[0].verified).to.be.rejectedWith(/Could not find valid signing key packet/);
});
