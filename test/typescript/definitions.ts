/**
 * npm run-script test-type-definitions
 * 
 * If types are off, either this will fail to build with TypeScript, or it will fail to run.
 *  - if it fails to build, edit the file to match type definitions
 *  - if it failt to run, edit the definitions (and consequently this file) to match actual library API
 */

import { generateKey, readArmoredKey, readArmoredKeys, Key, readMessage, Message, CleartextMessage, encrypt, sign } from '../../dist/node/openpgp';
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
  const messageFromText = Message.fromText('hello');
  const encryptedArmored = await encrypt({ publicKeys, message: messageFromText });
  expect(encryptedArmored).to.include('-----BEGIN PGP MESSAGE-----');

  // Encrypt text message (unarmored)
  const uint = new Uint8Array(2);
  uint[0] = 1;
  uint[1] = 2;
  const messageFromBinary = Message.fromBinary(uint);
  const encryptedBinary = await encrypt({ publicKeys, message: messageFromBinary, armor: false });
  expect(encryptedBinary).to.be.instanceOf(Uint8Array);

  // Encrypt message (inspect packets)
  const messageParsed = await readMessage(encryptedBinary);
  expect(messageParsed).to.be.instanceOf(Message);

  // Sign cleartext message (armored)
  const cleartextMessage = CleartextMessage.fromText('hello');
  const clearSigned = await sign({ privateKeys, message: cleartextMessage });
  expect(clearSigned).to.include('-----BEGIN PGP SIGNED MESSAGE-----');

  // Sign text message (unarmored)
  const textMessage = Message.fromText('hello');
  const textSigned = await sign({ privateKeys, message: textMessage, armor: false });
  expect(textSigned).to.be.instanceOf(Uint8Array);

  // // Detached - sign cleartext message (armored)
  // import { Message, sign } from 'openpgp';
  // const message = Message.fromText(util.removeTrailingSpaces(text));
  // const signed = await sign({ privateKeys, message, detached: true });
  // console.log(signed); // String

  // // Detached - sign binary message (unarmored)
  // const message = Message.fromText(text);
  // const signed = await sign({ privateKeys, message, detached: true, armor: false });
  // console.log(signed); // Uint8Array

  // // Verify signed text message (armored)
  // const message = await readArmoredMessage(armor);
  // const verified = await verify({ publicKeys, message });
  // console.log(verified.data); // String
  // console.log(verified.signatures); // Array

  // // Verify signed binary message (unarmored)
  // const message = await readMessage(binary);
  // const verified = await verify({ publicKeys, message, format: 'binary' });
  // console.log(verified.data); // Uint8Array
  // console.log(verified.signatures); // Array

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

  console.log('typescript definitions are correct');
})().catch(e => {
  console.error('TypeScript definitions tests failed by throwing the following error');
  console.error(e);
  process.exit(1);
});
