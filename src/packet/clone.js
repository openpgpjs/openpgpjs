// OpenPGP.js - An OpenPGP implementation in javascript
// Copyright (C) 2015 Tankred Hase
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

/**
 * @fileoverview This module implements packet list cloning required to
 * pass certain object types between the web worker and main thread using
 * the structured cloning algorithm.
 * @module packet/clone
 */

import stream from 'web-stream-tools';
import { Key } from '../key';
import { Message } from '../message';
import { CleartextMessage } from '../cleartext';
import { Signature } from '../signature';
import List from './packetlist';
import type_keyid from '../type/keyid';
import util from '../util';


//////////////////////////////
//                          //
//   List --> Clone   //
//                          //
//////////////////////////////


/**
 * Create a packetlist from the correspoding object types.
 * @param  {Object} options   the object passed to and from the web worker
 * @returns {Object}           a mutated version of the options optject
 */
export function clonePackets(options) {
  if (options.publicKeys) {
    options.publicKeys = options.publicKeys.map(key => key.toPacketlist());
  }
  if (options.privateKeys) {
    options.privateKeys = options.privateKeys.map(key => key.toPacketlist());
  }
  if (options.publicKey) {
    options.publicKey = options.publicKey.toPacketlist();
  }
  if (options.privateKey) {
    options.privateKey = options.privateKey.toPacketlist();
  }
  if (options.key) {
    options.key = options.key.toPacketlist();
  }
  if (options.message) {
    //could be either a Message or CleartextMessage object
    if (options.message instanceof Message) {
      options.message = { packets: options.message.packets, fromStream: options.message.fromStream };
    } else if (options.message instanceof CleartextMessage) {
      options.message = { text: options.message.text, signature: options.message.signature.packets };
    }
  }
  if (options.signature && (options.signature instanceof Signature)) {
    options.signature = options.signature.packets;
  }
  if (options.signatures) {
    options.signatures.forEach(verificationObjectToClone);
  }
  return options;
}

function verificationObjectToClone(verObject) {
  const verified = verObject.verified;
  verObject.verified = stream.fromAsync(() => verified);
  if (verObject.signature instanceof Promise) {
    const signature = verObject.signature;
    verObject.signature = stream.fromAsync(async () => {
      const packets = (await signature).packets;
      try {
        await verified;
      } catch (e) {}
      if (packets && packets[0]) {
        delete packets[0].signature;
        delete packets[0].hashed;
      }
      return packets;
    });
  } else {
    verObject.signature = verObject.signature.packets;
  }
  if (verObject.error) {
    verObject.error = verObject.error.message;
  }
  return verObject;
}

//////////////////////////////
//                          //
//   Clone --> List   //
//                          //
//////////////////////////////


/**
 * Creates an object with the correct prototype from a corresponding packetlist.
 * @param  {Object} options   the object passed to and from the web worker
 * @param  {String} method    the public api function name to be delegated to the worker
 * @returns {Object}           a mutated version of the options optject
 */
export function parseClonedPackets(options) {
  if (options.publicKeys) {
    options.publicKeys = options.publicKeys.map(packetlistCloneToKey);
  }
  if (options.privateKeys) {
    options.privateKeys = options.privateKeys.map(packetlistCloneToKey);
  }
  if (options.publicKey) {
    options.publicKey = packetlistCloneToKey(options.publicKey);
  }
  if (options.privateKey) {
    options.privateKey = packetlistCloneToKey(options.privateKey);
  }
  if (options.key) {
    options.key = packetlistCloneToKey(options.key);
  }
  if (options.message && options.message.signature) {
    options.message = packetlistCloneToCleartextMessage(options.message);
  } else if (options.message) {
    options.message = packetlistCloneToMessage(options.message);
  }
  if (options.signatures) {
    options.signatures = options.signatures.map(packetlistCloneToSignatures);
  }
  if (options.signature) {
    options.signature = packetlistCloneToSignature(options.signature);
  }
  return options;
}

function packetlistCloneToKey(clone) {
  const packetlist = List.fromStructuredClone(clone);
  return new Key(packetlist);
}

function packetlistCloneToMessage(clone) {
  const packetlist = List.fromStructuredClone(clone.packets);
  const message = new Message(packetlist);
  message.fromStream = clone.fromStream;
  return message;
}

function packetlistCloneToCleartextMessage(clone) {
  const packetlist = List.fromStructuredClone(clone.signature);
  return new CleartextMessage(clone.text, new Signature(packetlist));
}

//verification objects
function packetlistCloneToSignatures(clone) {
  clone.keyid = type_keyid.fromClone(clone.keyid);
  if (util.isStream(clone.signature)) {
    clone.signature = stream.readToEnd(clone.signature, ([signature]) => new Signature(List.fromStructuredClone(signature)));
    clone.signature.catch(() => {});
  } else {
    clone.signature = new Signature(List.fromStructuredClone(clone.signature));
  }
  clone.verified = stream.readToEnd(clone.verified, ([verified]) => verified);
  clone.verified.catch(() => {});
  if (clone.error) {
    clone.error = new Error(clone.error);
  }
  return clone;
}

function packetlistCloneToSignature(clone) {
  if (util.isString(clone) || util.isStream(clone)) {
    //signature is armored
    return clone;
  }
  const packetlist = List.fromStructuredClone(clone);
  return new Signature(packetlist);
}
