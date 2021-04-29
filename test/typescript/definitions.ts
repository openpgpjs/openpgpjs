/**
 * npm run-script test-type-definitions
 * 
 * If types are off, either this will fail to build with TypeScript, or it will fail to run.
 *  - if it fails to build, edit the file to match type definitions
 *  - if it fails to run, edit this file to match the actual library API, then edit the definitions file (openpgp.d.ts) accordingly.
 */

import { expect } from 'chai';
import {
  generateKey, readKey, readKeys, Key,
  readMessage, createMessage, Message, createCleartextMessage,
  encrypt, decrypt, sign, verify, config, enums,
  LiteralDataPacket, PacketList, CompressedDataPacket, PublicKeyPacket, PublicSubkeyPacket, SecretKeyPacket, SecretSubkeyPacket
} from '../..';

(async () => {

  // Generate keys
  const { publicKeyArmored, key } = await generateKey({ userIDs: [{ email: "user@corp.co" }], config: { v5Keys: true } });
  expect(key).to.be.instanceOf(Key);
  const privateKeys = [key];
  const publicKeys = [key.toPublic()];
  expect(key.toPublic().armor(config)).to.equal(publicKeyArmored);

  // Parse keys
  expect(await readKey({ armoredKey: publicKeyArmored })).to.be.instanceOf(Key);
  expect(await readKeys({ armoredKeys: publicKeyArmored })).to.have.lengthOf(1);

  // Encrypt text message (armored)
  const text = 'hello';
  const textMessage = await createMessage({ text: 'hello' });
  const encryptedArmor: string = await encrypt({ publicKeys, message: textMessage });
  expect(encryptedArmor).to.include('-----BEGIN PGP MESSAGE-----');

  // Encrypt binary message (unarmored)
  const binary = new Uint8Array(2);
  binary[0] = 1;
  binary[1] = 2;
  const binaryMessage = await createMessage({ binary });
  const encryptedBinary: Uint8Array = await encrypt({ publicKeys, message: binaryMessage, armor: false });
  expect(encryptedBinary).to.be.instanceOf(Uint8Array);

  // Decrypt text message (armored)
  const encryptedTextMessage = await readMessage({ armoredMessage: encryptedArmor });
  const decryptedText = await decrypt({ privateKeys, message: encryptedTextMessage });
  const decryptedTextData: string = decryptedText.data;
  expect(decryptedTextData).to.equal(text);

  // Decrypt binary message (unarmored)
  const encryptedBinaryMessage = await readMessage({ binaryMessage: encryptedBinary });
  const decryptedBinary = await decrypt({ privateKeys, message: encryptedBinaryMessage, format: 'binary' });
  const decryptedBinaryData: Uint8Array = decryptedBinary.data;
  expect(decryptedBinaryData).to.deep.equal(binary);

  // Encrypt message (inspect packets)
  const encryptedMessage = await readMessage({ binaryMessage: encryptedBinary });
  expect(encryptedMessage).to.be.instanceOf(Message);

  // Sign cleartext message (armored)
  const cleartextMessage = await createCleartextMessage({ text: 'hello' });
  const clearSignedArmor = await sign({ privateKeys, message: cleartextMessage });
  expect(clearSignedArmor).to.include('-----BEGIN PGP SIGNED MESSAGE-----');

  // Sign text message (armored)
  const textSignedArmor: string = await sign({ privateKeys, message: textMessage });
  expect(textSignedArmor).to.include('-----BEGIN PGP MESSAGE-----');

  // Sign text message (unarmored)
  const textSignedBinary: Uint8Array = await sign({ privateKeys, message: binaryMessage, armor: false });
  expect(textSignedBinary).to.be.instanceOf(Uint8Array);

  // Verify signed text message (armored)
  const signedMessage = await readMessage({ armoredMessage: textSignedArmor });
  const verifiedText = await verify({ publicKeys, message: signedMessage });
  const verifiedTextData: string = verifiedText.data;
  expect(verifiedTextData).to.equal(text);

  // Verify signed binary message (unarmored)
  const message = await readMessage({ binaryMessage: textSignedBinary });
  const verifiedBinary = await verify({ publicKeys, message, format: 'binary' });
  const verifiedBinaryData: Uint8Array = verifiedBinary.data;
  expect(verifiedBinaryData).to.deep.equal(binary);

  // Generic packetlist
  const packets = new PacketList();
  expect(packets.push()).to.equal(0);
  expect(packets.push(new LiteralDataPacket())).to.equal(1);
  packets.map(packet => packet.write);
  // @ts-expect-error for unsafe downcasting
  packets.map((packet: LiteralDataPacket) => packet.getText());
  // @ts-expect-error for non-packet element
  try { new PacketList().push(1); } catch (e) {}


  // Packetlist of specific type
  const literalPackets = new PacketList<LiteralDataPacket>();
  literalPackets.push(new LiteralDataPacket());
  literalPackets[0].write();
  literalPackets.map((packet: LiteralDataPacket) => packet);
  packets.push(...literalPackets);
  // @ts-expect-error for incompatible packetlist type
  literalPackets.push(...packets);
  // @ts-expect-error for incompatible packet type
  new PacketList<LiteralDataPacket>().push(new CompressedDataPacket());
  // @ts-expect-error for incompatible packet type
  new PacketList<PublicKeyPacket>().push(new PublicSubkeyPacket());
  // @ts-expect-error for incompatible packet type
  new PacketList<SecretKeyPacket>().push(new SecretSubkeyPacket());

  expect(LiteralDataPacket.tag).to.equal(enums.packet.literalData);

  // // Detached - sign cleartext message (armored)
  // import { Message, sign } from 'openpgp';
  // const message = await createMessage({ text: util.removeTrailingSpaces(text) });
  // const signed = await sign({ privateKeys, message, detached: true });
  // console.log(signed); // String

  // // Detached - sign binary message (unarmored)
  // const message = await createMessage({ text });
  // const signed = await sign({ privateKeys, message, detached: true, armor: false });
  // console.log(signed); // Uint8Array

  // // Encrypt session keys (armored)
  // const encrypted = await encryptSessionKey({ publicKeys, data, algorithm });
  // console.log(encrypted); // String

  // // Encrypt session keys (unarmored)
  // const encrypted = await encryptSessionKey({ publicKeys, data, algorithm, armor: false });
  // console.log(encrypted); // Uint8Array

  // // Streaming - encrypt text message on Node.js (armored)
  // const data = fs.createReadStream(filename, { encoding: 'utf8' });
  // const message = await createMessage({ text: data });
  // const encrypted = await encrypt({ publicKeys, message });
  // encrypted.on('data', chunk => {
  //   console.log(chunk); // String
  // });

  // // Streaming - encrypt binary message on Node.js (unarmored)
  // const data = fs.createReadStream(filename);
  // const message = await createMessage({ binary: data });
  // const encrypted = await encrypt({ publicKeys, message, armor: false });
  // encrypted.pipe(targetStream);

  console.log('TypeScript definitions are correct');
})().catch(e => {
  console.error('TypeScript definitions tests failed by throwing the following error');
  console.error(e);
  process.exit(1);
});
