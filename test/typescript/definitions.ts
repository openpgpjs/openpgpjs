/**
 * npm run-script test-type-definitions
 * 
 * If types are off, either this will fail to build with TypeScript, or it will fail to run.
 *  - if it fails to build, edit the file to match type definitions
 *  - if it fails to run, edit this file to match the actual library API, then edit the definitions file (openpgp.d.ts) accordingly.
 */

import { generateKey, readArmoredKey, readArmoredKeys, Key, readMessage, readArmoredMessage, Message, CleartextMessage, encrypt, decrypt, sign, verify } from '../..';
import { expect } from 'chai';

(async () => {

  // Generate keys
  const { publicKeyArmored, key } = await generateKey({ userIds: [{ email: "user@corp.co" }] });
  expect(key).to.be.instanceOf(Key);
  const privateKeys = [key];
  const publicKeys = [key.toPublic()];

  // Parse keys
  expect(await readArmoredKey(publicKeyArmored)).to.be.instanceOf(Key);
  expect(await readArmoredKeys(publicKeyArmored)).to.have.lengthOf(1);

  // Encrypt text message (armored)
  const text = 'hello';
  const textMessage = Message.fromText('hello');
  const encryptedArmor: string = await encrypt({ publicKeys, message: textMessage });
  expect(encryptedArmor).to.include('-----BEGIN PGP MESSAGE-----');

  // Encrypt binary message (unarmored)
  const binary = new Uint8Array(2);
  binary[0] = 1;
  binary[1] = 2;
  const binaryMessage = Message.fromBinary(binary);
  const encryptedBinary: Uint8Array = await encrypt({ publicKeys, message: binaryMessage, armor: false });
  expect(encryptedBinary).to.be.instanceOf(Uint8Array);

  // Decrypt text message (armored)
  const encryptedTextMessage = await readArmoredMessage(encryptedArmor);
  const decryptedText = await decrypt({ privateKeys, message: encryptedTextMessage });
  const decryptedTextData: string = decryptedText.data;
  expect(decryptedTextData).to.equal(text);

  // Decrypt binary message (unarmored)
  const encryptedBinaryMessage = await readMessage(encryptedBinary);
  const decryptedBinary = await decrypt({ privateKeys, message: encryptedBinaryMessage, format: 'binary' });
  const decryptedBinaryData: Uint8Array = decryptedBinary.data;
  expect(decryptedBinaryData).to.deep.equal(binary);

  // Encrypt message (inspect packets)
  const encryptedMessage = await readMessage(encryptedBinary);
  expect(encryptedMessage).to.be.instanceOf(Message);

  // Sign cleartext message (armored)
  const cleartextMessage = CleartextMessage.fromText('hello');
  const clearSignedArmor = await sign({ privateKeys, message: cleartextMessage });
  expect(clearSignedArmor).to.include('-----BEGIN PGP SIGNED MESSAGE-----');

  // Sign text message (armored)
  const textSignedArmor: string = await sign({ privateKeys, message: textMessage });
  expect(textSignedArmor).to.include('-----BEGIN PGP MESSAGE-----');

  // Sign text message (unarmored)
  const textSignedBinary: Uint8Array = await sign({ privateKeys, message: binaryMessage, armor: false });
  expect(textSignedBinary).to.be.instanceOf(Uint8Array);

  // Verify signed text message (armored)
  const signedMessage = await readArmoredMessage(textSignedArmor);
  const verifiedText = await verify({ publicKeys, message: signedMessage });
  const verifiedTextData: string = verifiedText.data;
  expect(verifiedTextData).to.equal(text);

  // Verify signed binary message (unarmored)
  const message = await readMessage(textSignedBinary);
  const verifiedBinary = await verify({ publicKeys, message, format: 'binary' });
  const verifiedBinaryData: Uint8Array = verifiedBinary.data;
  expect(verifiedBinaryData).to.deep.equal(binary);

  // // Detached - sign cleartext message (armored)
  // import { Message, sign } from 'openpgp';
  // const message = Message.fromText(util.removeTrailingSpaces(text));
  // const signed = await sign({ privateKeys, message, detached: true });
  // console.log(signed); // String

  // // Detached - sign binary message (unarmored)
  // const message = Message.fromText(text);
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
  // const message = Message.fromText(data);
  // const encrypted = await encrypt({ publicKeys, message });
  // encrypted.on('data', chunk => {
  //   console.log(chunk); // String
  // });

  // // Streaming - encrypt binary message on Node.js (unarmored)
  // const data = fs.createReadStream(filename);
  // const message = Message.fromBinary(data);
  // const encrypted = await encrypt({ publicKeys, message, armor: false });
  // encrypted.pipe(targetStream);

  console.log('TypeScript definitions are correct');
})().catch(e => {
  console.error('TypeScript definitions tests failed by throwing the following error');
  console.error(e);
  process.exit(1);
});
