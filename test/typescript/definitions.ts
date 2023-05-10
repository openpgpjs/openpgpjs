/**
 * npm run-script test-type-definitions
 *
 * If types are off, either this will fail to build with TypeScript, or it will fail to run.
 *  - if it fails to build, edit the file to match type definitions
 *  - if it fails to run, edit this file to match the actual library API, then edit the definitions file (openpgp.d.ts) accordingly.
 */
import { ReadableStream as WebReadableStream } from 'web-streams-polyfill';
import { createReadStream } from 'fs';

import { expect } from 'chai';
import {
  generateKey, readKey, readKeys, readPrivateKey, PrivateKey, Key, PublicKey, revokeKey,
  readMessage, createMessage, Message, createCleartextMessage,
  encrypt, decrypt, sign, verify, config, enums,
  generateSessionKey, encryptSessionKey, decryptSessionKeys,
  LiteralDataPacket, PacketList, CompressedDataPacket, PublicKeyPacket, PublicSubkeyPacket, SecretKeyPacket, SecretSubkeyPacket, CleartextMessage,
  WebStream, NodeStream,
} from '../..';

(async () => {

  // Generate keys
  const keyOptions = { userIDs: [{ email: 'user@corp.co' }], config: { v5Keys: true } };
  const { privateKey: privateKeyArmored, publicKey: publicKeyArmored } = await generateKey(keyOptions);
  const { privateKey: privateKeyBinary } = await generateKey({ ...keyOptions, format: 'binary' });
  const { privateKey, publicKey, revocationCertificate } = await generateKey({ ...keyOptions, format: 'object' });
  expect(privateKey).to.be.instanceOf(PrivateKey);
  expect(publicKey).to.be.instanceOf(PublicKey);
  expect(typeof revocationCertificate).to.equal('string');
  const privateKeys = [privateKey];
  const publicKeys = [privateKey.toPublic()];

  // Parse keys
  expect(await readKeys({ armoredKeys: publicKeyArmored })).to.have.lengthOf(1);
  const parsedKey: Key = await readKey({ armoredKey: publicKeyArmored });
  expect(parsedKey.armor(config)).to.equal(publicKeyArmored);
  expect(parsedKey.isPrivate()).to.be.false;
  const parsedPrivateKey: PrivateKey = await readPrivateKey({ armoredKey: privateKeyArmored });
  expect(parsedPrivateKey.isPrivate()).to.be.true;
  const parsedBinaryPrivateKey: PrivateKey = await readPrivateKey({ binaryKey: privateKeyBinary });
  expect(parsedBinaryPrivateKey.isPrivate()).to.be.true;
  // a generic Key can be directly used as PublicKey, since both classes have the same properties
  // eslint-disable-next-line no-unused-vars
  const unusedPublicKey: PublicKey = parsedKey;

  // Check PrivateKey type inference
  if (parsedKey.isPrivate()) {
    expect(parsedKey.isDecrypted()).to.be.true;
  } else {
    // @ts-expect-error isDecrypted is not defined for public keys
    try { parsedKey.isDecrypted(); } catch (e) {}
  }
  (await privateKey.update(privateKey)).isDecrypted();
  (await privateKey.toPublic().update(privateKey)).isDecrypted();
  // @ts-expect-error isDecrypted is not defined for public keys
  try { (await privateKey.toPublic().update(privateKey.toPublic())).isDecrypted(); } catch (e) {}

  // Revoke keys
  await revokeKey({ key: privateKey });
  // @ts-expect-error for missing revocation certificate
  try { await revokeKey({ key: publicKey }); } catch (e) {}
  const { privateKey: revokedPrivateKey, publicKey: revokedPublicKey } = await revokeKey({ key: privateKey, revocationCertificate, format: 'object' });
  expect(revokedPrivateKey).to.be.instanceOf(PrivateKey);
  expect(revokedPublicKey).to.be.instanceOf(PublicKey);
  const revokedKeyPair = await revokeKey({ key: publicKey, revocationCertificate, format: 'object' });
  // @ts-expect-error for null private key
  try { revokedKeyPair.privateKey.armor(); } catch (e) {}
  expect(revokedKeyPair.privateKey).to.be.null;
  expect(revokedKeyPair.publicKey).to.be.instanceOf(PublicKey);

  // Encrypt text message (armored)
  const text = 'hello';
  const textMessage = await createMessage({ text: 'hello', format: 'text' });
  const encryptedArmor: string = await encrypt({ encryptionKeys: publicKeys, message: textMessage });
  expect(encryptedArmor).to.include('-----BEGIN PGP MESSAGE-----');

  // Encrypt binary message (unarmored)
  const binary = new Uint8Array([1, 2]);
  const binaryMessage = await createMessage({ binary });
  const encryptedBinary: Uint8Array = await encrypt({ encryptionKeys: publicKeys, message: binaryMessage, format: 'binary' });
  expect(encryptedBinary).to.be.instanceOf(Uint8Array);

  // Decrypt text message (armored)
  const encryptedTextMessage = await readMessage({ armoredMessage: encryptedArmor });
  const decryptedText = await decrypt({ decryptionKeys: privateKeys, message: encryptedTextMessage });
  const decryptedTextData: string = decryptedText.data;
  expect(decryptedTextData).to.equal(text);

  // Decrypt binary message (unarmored)
  const encryptedBinaryMessage = await readMessage({ binaryMessage: encryptedBinary });
  const decryptedBinary = await decrypt({ decryptionKeys: privateKeys, message: encryptedBinaryMessage, format: 'binary' });
  const decryptedBinaryData: Uint8Array = decryptedBinary.data;
  expect(decryptedBinaryData).to.deep.equal(binary);

  // Encrypt message (inspect packets)
  const encryptedBinaryObject: Message<Uint8Array> = await encrypt({ encryptionKeys: publicKeys, message: binaryMessage, format: 'object' });
  expect(encryptedBinaryObject).to.be.instanceOf(Message);
  const encryptedTextObject: Message<string> = await encrypt({ encryptionKeys: publicKeys, message: textMessage, format: 'object' });
  expect(encryptedTextObject).to.be.instanceOf(Message);

  // Session key functions
  // Get session keys from encrypted message
  const sessionKeys = await decryptSessionKeys({ message: await readMessage({ binaryMessage: encryptedBinary }), decryptionKeys: privateKeys });
  expect(sessionKeys).to.have.length(1);
  const armoredEncryptedSessionKeys: string = await encryptSessionKey({ ...sessionKeys[0], passwords: 'pass', algorithm: 'aes128', aeadAlgorithm: 'eax' });
  expect(armoredEncryptedSessionKeys).to.include('-----BEGIN PGP MESSAGE-----');
  const encryptedSessionKeys: Message<any> = await encryptSessionKey({ ...sessionKeys[0], passwords: 'pass', algorithm: 'aes128', aeadAlgorithm: 'eax', format: 'object' });
  expect(encryptedSessionKeys).to.be.instanceOf(Message);
  const newSessionKey = await generateSessionKey({ encryptionKeys: privateKey.toPublic() });
  expect(newSessionKey.data).to.exist;
  expect(newSessionKey.algorithm).to.exist;

  // Sign cleartext message (armored)
  const cleartextMessage = await createCleartextMessage({ text: 'hello' });
  const verificationResult = await verify({ message: cleartextMessage, verificationKeys: publicKey });
  const verifiedCleartextData: string = verificationResult.data;
  expect(verifiedCleartextData).to.equal(cleartextMessage.getText());
  // @ts-expect-error Binary output not available for cleartext messages
  try { await verify({ message: cleartextMessage, verificationKeys: publicKey, format: 'binary' }) } catch (e) {}

  const clearSignedArmor = await sign({ signingKeys: privateKeys, message: cleartextMessage });
  expect(clearSignedArmor).to.include('-----BEGIN PGP SIGNED MESSAGE-----');
  const clearSignedObject: CleartextMessage = await sign({ signingKeys: privateKeys, message: cleartextMessage, format: 'object' });
  expect(clearSignedObject).to.be.instanceOf(CleartextMessage);
  // @ts-expect-error PublicKey not assignable to PrivateKey
  try { await sign({ signingKeys: publicKeys, message: cleartextMessage }); } catch (e) {}
  // @ts-expect-error Key not assignable to PrivateKey
  try { await sign({ signingKeys: parsedKey, message: cleartextMessage }); } catch (e) {}

  // Sign text message (armored)
  const textSignedArmor: string = await sign({ signingKeys: privateKeys, message: textMessage });
  expect(textSignedArmor).to.include('-----BEGIN PGP MESSAGE-----');
  // Sign text message (unarmored)
  const textSignedBinary: Uint8Array = await sign({ signingKeys: privateKeys, message: binaryMessage, format: 'binary' });
  expect(textSignedBinary).to.be.instanceOf(Uint8Array);
  // Sign text and binary messages (inspect packages)
  const binarySignedObject: Message<Uint8Array> = await sign({ signingKeys: privateKeys, message: binaryMessage, format: 'object' });
  expect(binarySignedObject).to.be.instanceOf(Message);
  const textSignedObject: Message<string> = await sign({ signingKeys: privateKeys, message: textMessage, format: 'object' });
  expect(textSignedObject).to.be.instanceOf(Message);

  // Sign text message (armored)
  const textSignedWithNotations: string = await sign({ signingKeys: privateKeys, message: textMessage, signatureNotations: [{
    name: 'test@example.org',
    value: new TextEncoder().encode('test'),
    humanReadable: true,
    critical: false
  }] });
  expect(textSignedWithNotations).to.include('-----BEGIN PGP MESSAGE-----');

  // Verify signed text message (armored)
  const signedMessage = await readMessage({ armoredMessage: textSignedArmor });
  const verifiedText = await verify({ verificationKeys: publicKeys, message: signedMessage });
  const verifiedTextData: string = verifiedText.data;
  expect(verifiedTextData).to.equal(text);

  // Verify signed binary message (unarmored)
  const message = await readMessage({ binaryMessage: textSignedBinary });
  const verifiedBinary = await verify({ verificationKeys: publicKeys, message, format: 'binary' });
  const verifiedBinaryData: Uint8Array = verifiedBinary.data;
  expect(verifiedBinaryData).to.deep.equal(binary);
  await verify({ verificationKeys: privateKeys, message, format: 'binary' });

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

  // // Detached - sign text message (armored)
  // import { Message, sign } from 'openpgp';
  // const message = await createMessage({ text: util.removeTrailingSpaces(text) });
  // const signed = await sign({ privateKeys, message, detached: true });
  // console.log(signed); // String

  // // Detached - sign binary message (unarmored)
  // const message = await createMessage({ text });
  // const signed = await sign({ privateKeys, message, detached: true, format: 'binary' });
  // console.log(signed); // Uint8Array

  // @ts-expect-error for passing text stream as binary data
  await createMessage({ binary: new WebReadableStream<string>() });
  // @ts-expect-error for passing binary stream as text data
  await createMessage({ text: new WebReadableStream<Uint8Array>() });
  
  // Streaming - encrypt text message (armored output)
  try {
    const nodeTextStream = createReadStream('non-existent-file', { encoding: 'utf8' });
    const messageFromNodeTextStream = await createMessage({ text: nodeTextStream });
    (await encrypt({ message: messageFromNodeTextStream, passwords: 'password', format: 'armored' })) as NodeStream<string>;
  } catch (err) {}
  const webTextStream = new WebReadableStream<string>();
  const messageFromWebTextStream = await createMessage({ text: webTextStream });
  (await encrypt({ message: messageFromWebTextStream, passwords: 'password', format: 'armored' })) as WebStream<string>;
  messageFromWebTextStream.getText() as WebStream<string>;
  messageFromWebTextStream.getLiteralData() as WebStream<Uint8Array>;

  // Streaming - encrypt binary message (binary output)
  try {
    const nodeBinaryStream = createReadStream('non-existent-file');
    const messageFromNodeBinaryStream = await createMessage({ binary: nodeBinaryStream });
    (await encrypt({ message: messageFromNodeBinaryStream, passwords: 'password', format: 'binary' })) as NodeStream<Uint8Array>;
  } catch (err) {}
  const webBinaryStream = new WebReadableStream<Uint8Array>();
  const messageFromWebBinaryStream = await createMessage({ binary: webBinaryStream });
  (await encrypt({ message: messageFromWebBinaryStream, passwords: 'password', format: 'binary' })) as WebStream<Uint8Array>;
  messageFromWebBinaryStream.getText() as WebStream<string>;
  messageFromWebBinaryStream.getLiteralData() as WebStream<Uint8Array>;

  console.log('TypeScript definitions are correct');
})().catch(e => {
  console.error('TypeScript definitions tests failed by throwing the following error');
  console.error(e);
  process.exit(1);
});
