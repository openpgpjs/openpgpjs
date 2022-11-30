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

import * as stream from '@openpgp/web-stream-tools';
import * as base64 from './base64';
import enums from '../enums';
import util from '../util';
import defaultConfig from '../config';

/**
 * Finds out which Ascii Armoring type is used. Throws error if unknown type.
 * @param {String} text - ascii armored text
 * @returns {Integer} 0 = MESSAGE PART n of m.
 *         1 = MESSAGE PART n
 *         2 = SIGNED MESSAGE
 *         3 = PGP MESSAGE
 *         4 = PUBLIC KEY BLOCK
 *         5 = PRIVATE KEY BLOCK
 *         6 = SIGNATURE
 * @private
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
    return enums.armor.multipartSection;
  } else
  // BEGIN PGP MESSAGE, PART X
  // Used for multi-part messages, where this is the Xth part of an
  // unspecified number of parts. Requires the MESSAGE-ID Armor
  // Header to be used.
  if (/MESSAGE, PART \d+/.test(header[1])) {
    return enums.armor.multipartLast;
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
    return enums.armor.publicKey;
  } else
  // BEGIN PGP PRIVATE KEY BLOCK
  // Used for armoring private keys.
  if (/PRIVATE KEY BLOCK/.test(header[1])) {
    return enums.armor.privateKey;
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
 * @param {String} [customComment] - Additional comment to add to the armored string
 * @returns {String} The header information.
 * @private
 */
function addheader(customComment, config) {
  let result = '';
  if (config.showVersion) {
    result += 'Version: ' + config.versionString + '\n';
  }
  if (config.showComment) {
    result += 'Comment: ' + config.commentString + '\n';
  }
  if (customComment) {
    result += 'Comment: ' + customComment + '\n';
  }
  result += '\n';
  return result;
}


/**
 * Calculates a checksum over the given data and returns it base64 encoded
 * @param {String | ReadableStream<String>} data - Data to create a CRC-24 checksum for
 * @returns {String | ReadableStream<String>} Base64 encoded checksum.
 * @private
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
 * @param {String | ReadableStream<String>} input - Data to create a CRC-24 checksum for
 * @returns {Uint8Array | ReadableStream<Uint8Array>} The CRC-24 checksum.
 * @private
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
 * Verify armored headers. crypto-refresh-06, section 6.2:
 * "An OpenPGP implementation may consider improperly formatted Armor
 * Headers to be corruption of the ASCII Armor, but SHOULD make an
 * effort to recover."
 * @private
 * @param {Array<String>} headers - Armor headers
 */
function verifyHeaders(headers) {
  for (let i = 0; i < headers.length; i++) {
    if (!/^([^\s:]|[^\s:][^:]*[^\s:]): .+$/.test(headers[i])) {
      util.printDebugError(new Error('Improperly formatted armor header: ' + headers[i]));
    }
    if (!/^(Version|Comment|MessageID|Hash|Charset): .+$/.test(headers[i])) {
      util.printDebugError(new Error('Unknown header: ' + headers[i]));
    }
  }
}

/**
 * Splits a message into two parts, the body and the checksum. This is an internal function
 * @param {String} text - OpenPGP armored message part
 * @returns {Object} An object with attribute "body" containing the body.
 * and an attribute "checksum" containing the checksum.
 * @private
 */
function splitChecksum(text) {
  let body = text;
  let checksum = '';

  const lastEquals = text.lastIndexOf('=');

  if (lastEquals >= 0 && lastEquals !== text.length - 1) { // '=' as the last char means no checksum
    body = text.slice(0, lastEquals);
    checksum = text.slice(lastEquals + 1).substr(0, 4);
  }

  return { body: body, checksum: checksum };
}

/**
 * Dearmor an OpenPGP armored message; verify the checksum and return
 * the encoded bytes
 * @param {String} input - OpenPGP armored message
 * @returns {Promise<Object>} An object with attribute "text" containing the message text,
 * an attribute "data" containing a stream of bytes and "type" for the ASCII armor type
 * @async
 * @static
 */
export function unarmor(input, config = defaultConfig) {
  // eslint-disable-next-line no-async-promise-executor
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
          const checksumVerifiedString = (await checksumVerified).replace('\n', '');
          if (checksum !== checksumVerifiedString && (checksum || config.checksumRequired)) {
            throw new Error('Ascii armor integrity check failed');
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
  }).then(async result => {
    if (stream.isArrayStream(result.data)) {
      result.data = await stream.readToEnd(result.data);
    }
    return result;
  });
}


/**
 * Armor an OpenPGP binary packet block
 * @param {module:enums.armor} messageType - Type of the message
 * @param {Uint8Array | ReadableStream<Uint8Array>} body - The message body to armor
 * @param {Integer} [partIndex]
 * @param {Integer} [partTotal]
 * @param {String} [customComment] - Additional comment to add to the armored string
 * @returns {String | ReadableStream<String>} Armored text.
 * @static
 */
export function armor(messageType, body, partIndex, partTotal, customComment, config = defaultConfig) {
  let text;
  let hash;
  if (messageType === enums.armor.signed) {
    text = body.text;
    hash = body.hash;
    body = body.data;
  }
  const result = [];
  switch (messageType) {
    case enums.armor.multipartSection:
      result.push('-----BEGIN PGP MESSAGE, PART ' + partIndex + '/' + partTotal + '-----\n');
      result.push(addheader(customComment, config));
      result.push(base64.encode(body));
      result.push('-----END PGP MESSAGE, PART ' + partIndex + '/' + partTotal + '-----\n');
      break;
    case enums.armor.multipartLast:
      result.push('-----BEGIN PGP MESSAGE, PART ' + partIndex + '-----\n');
      result.push(addheader(customComment, config));
      result.push(base64.encode(body));
      result.push('-----END PGP MESSAGE, PART ' + partIndex + '-----\n');
      break;
    case enums.armor.signed:
      result.push('-----BEGIN PGP SIGNED MESSAGE-----\n');
      result.push('Hash: ' + hash + '\n\n');
      result.push(text.replace(/^-/mg, '- -'));
      result.push('\n-----BEGIN PGP SIGNATURE-----\n');
      result.push(addheader(customComment, config));
      result.push(base64.encode(body));
      result.push('-----END PGP SIGNATURE-----\n');
      break;
    case enums.armor.message:
      result.push('-----BEGIN PGP MESSAGE-----\n');
      result.push(addheader(customComment, config));
      result.push(base64.encode(body));
      result.push('-----END PGP MESSAGE-----\n');
      break;
    case enums.armor.publicKey:
      result.push('-----BEGIN PGP PUBLIC KEY BLOCK-----\n');
      result.push(addheader(customComment, config));
      result.push(base64.encode(body));
      result.push('-----END PGP PUBLIC KEY BLOCK-----\n');
      break;
    case enums.armor.privateKey:
      result.push('-----BEGIN PGP PRIVATE KEY BLOCK-----\n');
      result.push(addheader(customComment, config));
      result.push(base64.encode(body));
      result.push('-----END PGP PRIVATE KEY BLOCK-----\n');
      break;
    case enums.armor.signature:
      result.push('-----BEGIN PGP SIGNATURE-----\n');
      result.push(addheader(customComment, config));
      result.push(base64.encode(body));
      result.push('-----END PGP SIGNATURE-----\n');
      break;
  }

  return util.concat(result);
}
