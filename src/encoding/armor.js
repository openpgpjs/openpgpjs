// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
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
 * @requires web-stream-tools
 * @requires encoding/base64
 * @requires enums
 * @requires config
 * @requires util
 * @module encoding/armor
 */

import stream from 'web-stream-tools';
import base64 from './base64.js';
import enums from '../enums.js';
import config from '../config';
import util from '../util';

/**
 * Finds out which Ascii Armoring type is used. Throws error if unknown type.
 * @private
 * @param {String} text [String] ascii armored text
 * @returns {Integer} 0 = MESSAGE PART n of m
 *         1 = MESSAGE PART n
 *         2 = SIGNED MESSAGE
 *         3 = PGP MESSAGE
 *         4 = PUBLIC KEY BLOCK
 *         5 = PRIVATE KEY BLOCK
 *         6 = SIGNATURE
 */
function getType(text) {
  const reHeader = /^-----BEGIN PGP (MESSAGE, PART \d+\/\d+|MESSAGE, PART \d+|SIGNED MESSAGE|MESSAGE|PUBLIC KEY BLOCK|PRIVATE KEY BLOCK|SIGNATURE)-----$/m;

  const header = text.match(reHeader);

  if (!header) {
    throw new Error('Unknown ASCII armor type');
  }

  // BEGIN PGP MESSAGE, PART X/Y
  // Used for multi-part messages, where the armor is split amongst Y
  // parts, and this is the Xth part out of Y.
  if (/MESSAGE, PART \d+\/\d+/.test(header[1])) {
    return enums.armor.multipart_section;
  } else
  // BEGIN PGP MESSAGE, PART X
  // Used for multi-part messages, where this is the Xth part of an
  // unspecified number of parts. Requires the MESSAGE-ID Armor
  // Header to be used.
  if (/MESSAGE, PART \d+/.test(header[1])) {
    return enums.armor.multipart_last;
  } else
  // BEGIN PGP SIGNED MESSAGE
  if (/SIGNED MESSAGE/.test(header[1])) {
    return enums.armor.signed;
  } else
  // BEGIN PGP MESSAGE
  // Used for signed, encrypted, or compressed files.
  if (/MESSAGE/.test(header[1])) {
    return enums.armor.message;
  } else
  // BEGIN PGP PUBLIC KEY BLOCK
  // Used for armoring public keys.
  if (/PUBLIC KEY BLOCK/.test(header[1])) {
    return enums.armor.public_key;
  } else
  // BEGIN PGP PRIVATE KEY BLOCK
  // Used for armoring private keys.
  if (/PRIVATE KEY BLOCK/.test(header[1])) {
    return enums.armor.private_key;
  } else
  // BEGIN PGP SIGNATURE
  // Used for detached signatures, OpenPGP/MIME signatures, and
  // cleartext signatures. Note that PGP 2.x uses BEGIN PGP MESSAGE
  // for detached signatures.
  if (/SIGNATURE/.test(header[1])) {
    return enums.armor.signature;
  }
}

/**
 * Add additional information to the armor version of an OpenPGP binary
 * packet block.
 * @author  Alex
 * @version 2011-12-16
 * @param {String} customComment (optional) additional comment to add to the armored string
 * @returns {String} The header information
 */
function addheader(customComment) {
  let result = "";
  if (config.show_version) {
    result += "Version: " + config.versionstring + '\r\n';
  }
  if (config.show_comment) {
    result += "Comment: " + config.commentstring + '\r\n';
  }
  if (customComment) {
    result += "Comment: " + customComment + '\r\n';
  }
  result += '\r\n';
  return result;
}


/**
 * Calculates a checksum over the given data and returns it base64 encoded
 * @param {String | ReadableStream<String>} data Data to create a CRC-24 checksum for
 * @returns {String | ReadableStream<String>} Base64 encoded checksum
 */
function getCheckSum(data) {
  const crc = createcrc24(data);
  return base64.encode(crc);
}

// https://create.stephan-brumme.com/crc32/#slicing-by-8-overview

const crc_table = [
  new Array(0xFF),
  new Array(0xFF),
  new Array(0xFF),
  new Array(0xFF)
];

for (let i = 0; i <= 0xFF; i++) {
  let crc = i << 16;
  for (let j = 0; j < 8; j++) {
    crc = (crc << 1) ^ ((crc & 0x800000) !== 0 ? 0x864CFB : 0);
  }
  crc_table[0][i] =
    ((crc & 0xFF0000) >> 16) |
    (crc & 0x00FF00) |
    ((crc & 0x0000FF) << 16);
}
for (let i = 0; i <= 0xFF; i++) {
  crc_table[1][i] = (crc_table[0][i] >> 8) ^ crc_table[0][crc_table[0][i] & 0xFF];
}
for (let i = 0; i <= 0xFF; i++) {
  crc_table[2][i] = (crc_table[1][i] >> 8) ^ crc_table[0][crc_table[1][i] & 0xFF];
}
for (let i = 0; i <= 0xFF; i++) {
  crc_table[3][i] = (crc_table[2][i] >> 8) ^ crc_table[0][crc_table[2][i] & 0xFF];
}

// https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/DataView#Endianness
const isLittleEndian = (function() {
  const buffer = new ArrayBuffer(2);
  new DataView(buffer).setInt16(0, 0xFF, true /* littleEndian */);
  // Int16Array uses the platform's endianness.
  return new Int16Array(buffer)[0] === 0xFF;
}());

/**
 * Internal function to calculate a CRC-24 checksum over a given string (data)
 * @param {String | ReadableStream<String>} data Data to create a CRC-24 checksum for
 * @returns {Uint8Array | ReadableStream<Uint8Array>} The CRC-24 checksum
 */
function createcrc24(input) {
  let crc = 0xCE04B7;
  return stream.transform(input, value => {
    const len32 = isLittleEndian ? Math.floor(value.length / 4) : 0;
    const arr32 = new Uint32Array(value.buffer, value.byteOffset, len32);
    for (let i = 0; i < len32; i++) {
      crc ^= arr32[i];
      crc =
        crc_table[0][(crc >> 24) & 0xFF] ^
        crc_table[1][(crc >> 16) & 0xFF] ^
        crc_table[2][(crc >> 8) & 0xFF] ^
        crc_table[3][(crc >> 0) & 0xFF];
    }
    for (let i = len32 * 4; i < value.length; i++) {
      crc = (crc >> 8) ^ crc_table[0][(crc & 0xFF) ^ value[i]];
    }
  }, () => new Uint8Array([crc, crc >> 8, crc >> 16]));
}

/**
 * Verify armored headers. RFC4880, section 6.3: "OpenPGP should consider improperly formatted
 * Armor Headers to be corruption of the ASCII Armor."
 * @private
 * @param  {Array<String>} headers Armor headers
 */
function verifyHeaders(headers) {
  for (let i = 0; i < headers.length; i++) {
    if (!/^([^\s:]|[^\s:][^:]*[^\s:]): .+$/.test(headers[i])) {
      throw new Error('Improperly formatted armor header: ' + headers[i]);
    }
    if (!/^(Version|Comment|MessageID|Hash|Charset): .+$/.test(headers[i])) {
      util.print_debug_error(new Error('Unknown header: ' + headers[i]));
    }
  }
}

/**
 * Splits a message into two parts, the body and the checksum. This is an internal function
 * @param {String} text OpenPGP armored message part
 * @returns {Object} An object with attribute "body" containing the body
 * and an attribute "checksum" containing the checksum.
 */
function splitChecksum(text) {
  let body = text;
  let checksum = "";

  const lastEquals = text.lastIndexOf("=");

  if (lastEquals >= 0 && lastEquals !== text.length - 1) { // '=' as the last char means no checksum
    body = text.slice(0, lastEquals);
    checksum = text.slice(lastEquals + 1).substr(0, 4);
  }

  return { body: body, checksum: checksum };
}

/**
 * DeArmor an OpenPGP armored message; verify the checksum and return
 * the encoded bytes
 * @param {String} text OpenPGP armored message
 * @returns {Promise<Object>} An object with attribute "text" containing the message text,
 * an attribute "data" containing a stream of bytes and "type" for the ASCII armor type
 * @async
 * @static
 */
function dearmor(input) {
  return new Promise(async (resolve, reject) => {
    try {
      const reSplit = /^-----[^-]+-----$/m;
      const reEmptyLine = /^[ \f\r\t\u00a0\u2000-\u200a\u202f\u205f\u3000]*$/;

      let type;
      const headers = [];
      let lastHeaders = headers;
      let headersDone;
      let text = [];
      let textDone;
      let checksum;
      let data = base64.decode(stream.transformPair(input, async (readable, writable) => {
        const reader = stream.getReader(readable);
        try {
          while (true) {
            let line = await reader.readLine();
            if (line === undefined) {
              throw new Error('Misformed armored text');
            }
            // remove trailing whitespace at end of lines
            line = util.removeTrailingSpaces(line.replace(/[\r\n]/g, ''));
            if (!type) {
              if (reSplit.test(line)) {
                type = getType(line);
              }
            } else if (!headersDone) {
              if (reSplit.test(line)) {
                reject(new Error('Mandatory blank line missing between armor headers and armor data'));
              }
              if (!reEmptyLine.test(line)) {
                lastHeaders.push(line);
              } else {
                verifyHeaders(lastHeaders);
                headersDone = true;
                if (textDone || type !== 2) {
                  resolve({ text, data, headers, type });
                  break;
                }
              }
            } else if (!textDone && type === 2) {
              if (!reSplit.test(line)) {
                // Reverse dash-escaping for msg
                text.push(line.replace(/^- /, ''));
              } else {
                text = text.join('\r\n');
                textDone = true;
                verifyHeaders(lastHeaders);
                lastHeaders = [];
                headersDone = false;
              }
            }
          }
        } catch (e) {
          reject(e);
          return;
        }
        const writer = stream.getWriter(writable);
        try {
          while (true) {
            await writer.ready;
            const { done, value } = await reader.read();
            if (done) {
              throw new Error('Misformed armored text');
            }
            const line = value + '';
            if (line.indexOf('=') === -1 && line.indexOf('-') === -1) {
              await writer.write(line);
            } else {
              let remainder = await reader.readToEnd();
              if (!remainder.length) remainder = '';
              remainder = line + remainder;
              remainder = util.removeTrailingSpaces(remainder.replace(/\r/g, ''));
              const parts = remainder.split(reSplit);
              if (parts.length === 1) {
                throw new Error('Misformed armored text');
              }
              const split = splitChecksum(parts[0].slice(0, -1));
              checksum = split.checksum;
              await writer.write(split.body);
              break;
            }
          }
          await writer.ready;
          await writer.close();
        } catch (e) {
          await writer.abort(e);
        }
      }));
      data = stream.transformPair(data, async (readable, writable) => {
        const checksumVerified = stream.readToEnd(getCheckSum(stream.passiveClone(readable)));
        checksumVerified.catch(() => {});
        await stream.pipe(readable, writable, {
          preventClose: true
        });
        const writer = stream.getWriter(writable);
        try {
          const checksumVerifiedString = (await checksumVerified).replace('\r\n', '');
          if (checksum !== checksumVerifiedString && (checksum || config.checksum_required)) {
            throw new Error("Ascii armor integrity check on message failed: '" + checksum + "' should be '" +
                    checksumVerifiedString + "'");
          }
          await writer.ready;
          await writer.close();
        } catch (e) {
          await writer.abort(e);
        }
      });
    } catch (e) {
      reject(e);
    }
  });
}


/**
 * Armor an OpenPGP binary packet block
 * @param {Integer} messagetype type of the message
 * @param body
 * @param {Integer} partindex
 * @param {Integer} parttotal
 * @param {String} customComment (optional) additional comment to add to the armored string
 * @returns {String | ReadableStream<String>} Armored text
 * @static
 */
function armor(messagetype, body, partindex, parttotal, customComment) {
  let text;
  let hash;
  if (messagetype === enums.armor.signed) {
    text = body.text;
    hash = body.hash;
    body = body.data;
  }
  const bodyClone = stream.passiveClone(body);
  const result = [];
  switch (messagetype) {
    case enums.armor.multipart_section:
      result.push("-----BEGIN PGP MESSAGE, PART " + partindex + "/" + parttotal + "-----\r\n");
      result.push(addheader(customComment));
      result.push(base64.encode(body));
      result.push("=", getCheckSum(bodyClone));
      result.push("-----END PGP MESSAGE, PART " + partindex + "/" + parttotal + "-----\r\n");
      break;
    case enums.armor.multipart_last:
      result.push("-----BEGIN PGP MESSAGE, PART " + partindex + "-----\r\n");
      result.push(addheader(customComment));
      result.push(base64.encode(body));
      result.push("=", getCheckSum(bodyClone));
      result.push("-----END PGP MESSAGE, PART " + partindex + "-----\r\n");
      break;
    case enums.armor.signed:
      result.push("\r\n-----BEGIN PGP SIGNED MESSAGE-----\r\n");
      result.push("Hash: " + hash + "\r\n\r\n");
      result.push(text.replace(/^-/mg, "- -"));
      result.push("\r\n-----BEGIN PGP SIGNATURE-----\r\n");
      result.push(addheader(customComment));
      result.push(base64.encode(body));
      result.push("=", getCheckSum(bodyClone));
      result.push("-----END PGP SIGNATURE-----\r\n");
      break;
    case enums.armor.message:
      result.push("-----BEGIN PGP MESSAGE-----\r\n");
      result.push(addheader(customComment));
      result.push(base64.encode(body));
      result.push("=", getCheckSum(bodyClone));
      result.push("-----END PGP MESSAGE-----\r\n");
      break;
    case enums.armor.public_key:
      result.push("-----BEGIN PGP PUBLIC KEY BLOCK-----\r\n");
      result.push(addheader(customComment));
      result.push(base64.encode(body));
      result.push("=", getCheckSum(bodyClone));
      result.push("-----END PGP PUBLIC KEY BLOCK-----\r\n");
      break;
    case enums.armor.private_key:
      result.push("-----BEGIN PGP PRIVATE KEY BLOCK-----\r\n");
      result.push(addheader(customComment));
      result.push(base64.encode(body));
      result.push("=", getCheckSum(bodyClone));
      result.push("-----END PGP PRIVATE KEY BLOCK-----\r\n");
      break;
    case enums.armor.signature:
      result.push("-----BEGIN PGP SIGNATURE-----\r\n");
      result.push(addheader(customComment));
      result.push(base64.encode(body));
      result.push("=", getCheckSum(bodyClone));
      result.push("-----END PGP SIGNATURE-----\r\n");
      break;
  }

  return util.concat(result);
}

export default {
  encode: armor,
  decode: dearmor
};
