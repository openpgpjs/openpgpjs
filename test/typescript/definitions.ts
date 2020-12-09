/**
 * Testing typescript definitions.
 *
 * If types are off, either this will fail to build with TypeScript, or it will fail to run.
 *  - if it fails to build, edit the file to match type definitions
 *  - if it failt to run, edit the definitions (and consequently this file) to match actual library API
 *
 * the triple /// below brings in the type definitions manually
 */

/// - <reference path="../../openpgp.d.ts" />

import { generateKey, readArmoredKey, readArmoredKeys, Key, Message, encrypt } from '../../dist/node/openpgp';
import { expect } from 'chai';

(async () => {

  // generate
  const { publicKeyArmored, key } = await generateKey({ userIds: [{ email: "user@corp.co" }] });
  expect(key).to.be.instanceOf(Key);

  // parse
  expect(await readArmoredKey(publicKeyArmored)).to.be.instanceOf(Key);
  expect(await readArmoredKeys(publicKeyArmored)).to.have.lengthOf(1);

  // Encrypt text message(armored)
  const message = Message.fromText('hello');
  const encrypted = await encrypt({ publicKeys: [key.toPublic()], message });
  expect(encrypted).to.include('-----BEGIN PGP MESSAGE-----');

  // // Encrypt text message(unarmored)  
  // const message = Message.fromBinary(data);
  // const encrypted = await encrypt({ publicKeys, message, armor: false });
  // console.log(encrypted); // Uint8Array

  // // Encrypt message(inspect packets)
  // import stream from 'web-stream-tools';
  // const encrypted = await encrypt({ publicKeys, message, armor: false });
  // const message = await readMessage(encrypted.data);
  // message.packets.concat(await stream.readToEnd(message.packets.stream, _ => _)); // Optional, if you want to inspect trailing signature packets

  // // Sign cleartext message(armored)
  // const message = CleartextMessage.fromText(text);
  // const signed = await sign({ privateKeys, message });
  // console.log(signed); // String

  // // Sign text message(unarmored)
  // const message = Message.fromText(text);
  // const signed = await sign({ privateKeys, message, armor: false });
  // console.log(signed); // Uint8Array

  // // Detached - sign cleartext message(armored)
  // import { Message, sign } from 'openpgp';
  // const message = Message.fromText(util.removeTrailingSpaces(text));
  // const signed = await sign({ privateKeys, message, detached: true });
  // console.log(signed); // String

  // // Detached - sign binary message(unarmored)
  // const message = Message.fromText(text);
  // const signed = await sign({ privateKeys, message, detached: true, armor: false });
  // console.log(signed); // Uint8Array

  // // Verify signed text message(armored)  
  // const message = await readArmoredMessage(armor);
  // const verified = await verify({ publicKeys, message });
  // console.log(verified.data); // String
  // console.log(verified.signatures); // Array

  // // Verify signed binary message(unarmored)
  // const message = await readMessage(binary);
  // const verified = await verify({ publicKeys, message, format: 'binary' });
  // console.log(verified.data); // Uint8Array
  // console.log(verified.signatures); // Array

  // // Encrypt session keys(armored)
  // const encrypted = await encryptSessionKey({ publicKeys, data, algorithm });
  // console.log(encrypted); // String

  // // Encrypt session keys(unarmored)
  // const encrypted = await encryptSessionKey({ publicKeys, data, algorithm, armor: false });
  // console.log(encrypted); // Uint8Array

  // // Streaming - encrypt text message on Node.js(armored)
  // const data = fs.createReadStream(filename, { encoding: 'utf8' });
  // const message = Message.fromText(data);
  // const encrypted = await encrypt({ publicKeys, message });
  // encrypted.on('data', chunk => {
  //   console.log(chunk); // String
  // });

  // //Streaming - encrypt binary message on Node.js(unarmored)
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
