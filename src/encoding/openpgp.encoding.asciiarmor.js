// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
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
 * DeArmor an OpenPGP armored message; verify the checksum and return 
 * the encoded bytes
 * @param {String} text OpenPGP armored message
 * @returns {(Boolean|Object)} Either false in case of an error 
 * or an object with attribute "text" containing the message text
 * and an attribute "openpgp" containing the bytes.
 */
function openpgp_encoding_deArmor(text) {
	text = text.replace(/\r/g, '')
	// remove whitespace of blank line to allow later split at \n\n
	text = text.replace(/\n\s+\n/, '\n\n');

	var type = openpgp_encoding_get_type(text);

	if (type != 2) {
		var splittedtext = text.split('-----');

		var data = { 
			openpgp: openpgp_encoding_base64_decode(
				splittedtext[2]
					.split('\n\n')[1]
					.split("\n=")[0]
					.replace(/\n- /g,"\n")),
			type: type
		};

		if (verifyCheckSum(data.openpgp, 
			splittedtext[2]
				.split('\n\n')[1]
				.split("\n=")[1]
				.split('\n')[0]))

			return data;
		else {
			util.print_error("Ascii armor integrity check on message failed: '"
				+ splittedtext[2]
					.split('\n\n')[1]
					.split("\n=")[1]
					.split('\n')[0] 
				+ "' should be '"
				+ getCheckSum(data)) + "'";
			return false;
		}
	} else {
		var splittedtext = text.split('-----');

		var result = {
			text: splittedtext[2]
				.replace(/\n- /g,"\n")
				.split("\n\n")[1],
			openpgp: openpgp_encoding_base64_decode(splittedtext[4]
				.split("\n\n")[1]
				.split("\n=")[0]),
			type: type
		};

		if (verifyCheckSum(result.openpgp, splittedtext[4]
			.split("\n\n")[1]
			.split("\n=")[1]))

				return result;
		else {
			util.print_error("Ascii armor integrity check on message failed");
			return false;
		}
	}
}

/**
 * Finds out which Ascii Armoring type is used. This is an internal function
 * @param {String} text [String] ascii armored text
 * @returns {Integer} 0 = MESSAGE PART n of m
 *         1 = MESSAGE PART n
 *         2 = SIGNED MESSAGE
 *         3 = PGP MESSAGE
 *         4 = PUBLIC KEY BLOCK
 *         5 = PRIVATE KEY BLOCK
 *         null = unknown
 */
function openpgp_encoding_get_type(text) {
	var splittedtext = text.split('-----');
	// BEGIN PGP MESSAGE, PART X/Y
	// Used for multi-part messages, where the armor is split amongst Y
	// parts, and this is the Xth part out of Y.
	if (splittedtext[1].match(/BEGIN PGP MESSAGE, PART \d+\/\d+/)) {
		return 0;
	} else
		// BEGIN PGP MESSAGE, PART X
		// Used for multi-part messages, where this is the Xth part of an
		// unspecified number of parts. Requires the MESSAGE-ID Armor
		// Header to be used.
	if (splittedtext[1].match(/BEGIN PGP MESSAGE, PART \d+/)) {
		return 1;

	} else
		// BEGIN PGP SIGNATURE
		// Used for detached signatures, OpenPGP/MIME signatures, and
		// cleartext signatures. Note that PGP 2.x uses BEGIN PGP MESSAGE
		// for detached signatures.
	if (splittedtext[1].match(/BEGIN PGP SIGNED MESSAGE/)) {
		return 2;

	} else
  	    // BEGIN PGP MESSAGE
	    // Used for signed, encrypted, or compressed files.
	if (splittedtext[1].match(/BEGIN PGP MESSAGE/)) {
		return 3;

	} else
		// BEGIN PGP PUBLIC KEY BLOCK
		// Used for armoring public keys.
	if (splittedtext[1].match(/BEGIN PGP PUBLIC KEY BLOCK/)) {
		return 4;

	} else
		// BEGIN PGP PRIVATE KEY BLOCK
		// Used for armoring private keys.
	if (splittedtext[1].match(/BEGIN PGP PRIVATE KEY BLOCK/)) {
		return 5;
	}
}

/**
 * Add additional information to the armor version of an OpenPGP binary
 * packet block.
 * @author  Alex
 * @version 2011-12-16
 * @returns {String} The header information
 */
function openpgp_encoding_armor_addheader() {
    var result = "";
	if (openpgp.config.config.show_version) {
        result += "Version: "+openpgp.config.versionstring+'\r\n';
    }
	if (openpgp.config.config.show_comment) {
        result += "Comment: "+openpgp.config.commentstring+'\r\n';
    }
    result += '\r\n';
    return result;
}

/**
 * Armor an OpenPGP binary packet block
 * @param {Integer} messagetype type of the message
 * @param data
 * @param {Integer} partindex
 * @param {Integer} parttotal
 * @returns {String} Armored text
 */
function openpgp_encoding_armor(messagetype, data, partindex, parttotal) {
	var result = "";
	switch(messagetype) {
	case 0:
		result += "-----BEGIN PGP MESSAGE, PART "+partindex+"/"+parttotal+"-----\r\n";
		result += openpgp_encoding_armor_addheader();
		result += openpgp_encoding_base64_encode(data);
		result += "\r\n="+getCheckSum(data)+"\r\n";
		result += "-----END PGP MESSAGE, PART "+partindex+"/"+parttotal+"-----\r\n";
		break;
	case 1:
		result += "-----BEGIN PGP MESSAGE, PART "+partindex+"-----\r\n";
		result += openpgp_encoding_armor_addheader();
		result += openpgp_encoding_base64_encode(data);
		result += "\r\n="+getCheckSum(data)+"\r\n";
		result += "-----END PGP MESSAGE, PART "+partindex+"-----\r\n";
		break;
	case 2:
		result += "\r\n-----BEGIN PGP SIGNED MESSAGE-----\r\nHash: "+data.hash+"\r\n\r\n";
		result += data.text.replace(/\n-/g,"\n- -");
		result += "\r\n-----BEGIN PGP SIGNATURE-----\r\n";
		result += openpgp_encoding_armor_addheader();
		result += openpgp_encoding_base64_encode(data.openpgp);
		result += "\r\n="+getCheckSum(data.openpgp)+"\r\n";
		result += "-----END PGP SIGNATURE-----\r\n";
		break;
	case 3:
		result += "-----BEGIN PGP MESSAGE-----\r\n";
		result += openpgp_encoding_armor_addheader();
		result += openpgp_encoding_base64_encode(data);
		result += "\r\n="+getCheckSum(data)+"\r\n";
		result += "-----END PGP MESSAGE-----\r\n";
		break;
	case 4:
		result += "-----BEGIN PGP PUBLIC KEY BLOCK-----\r\n";
		result += openpgp_encoding_armor_addheader();
		result += openpgp_encoding_base64_encode(data);
		result += "\r\n="+getCheckSum(data)+"\r\n";
		result += "-----END PGP PUBLIC KEY BLOCK-----\r\n\r\n";
		break;
	case 5:
		result += "-----BEGIN PGP PRIVATE KEY BLOCK-----\r\n";
		result += openpgp_encoding_armor_addheader();
		result += openpgp_encoding_base64_encode(data);
		result += "\r\n="+getCheckSum(data)+"\r\n";
		result += "-----END PGP PRIVATE KEY BLOCK-----\r\n";
		break;
	}

	return result;
}

/**
 * Calculates a checksum over the given data and returns it base64 encoded
 * @param {String} data Data to create a CRC-24 checksum for
 * @return {String} Base64 encoded checksum
 */
function getCheckSum(data) {
	var c = createcrc24(data);
	var str = "" + String.fromCharCode(c >> 16)+
				   String.fromCharCode((c >> 8) & 0xFF)+
				   String.fromCharCode(c & 0xFF);
	return openpgp_encoding_base64_encode(str);
}

/**
 * Calculates the checksum over the given data and compares it with the 
 * given base64 encoded checksum
 * @param {String} data Data to create a CRC-24 checksum for
 * @param {String} checksum Base64 encoded checksum
 * @return {Boolean} True if the given checksum is correct; otherwise false
 */
function verifyCheckSum(data, checksum) {
	var c = getCheckSum(data);
	var d = checksum;
	return c[0] == d[0] && c[1] == d[1] && c[2] == d[2];
}
/**
 * Internal function to calculate a CRC-24 checksum over a given string (data)
 * @param {String} data Data to create a CRC-24 checksum for
 * @return {Integer} The CRC-24 checksum as number
 */
var crc_table = [
0x00000000, 0x00864cfb, 0x018ad50d, 0x010c99f6, 0x0393e6e1, 0x0315aa1a, 0x021933ec, 0x029f7f17, 0x07a18139, 0x0727cdc2, 0x062b5434, 0x06ad18cf, 0x043267d8, 0x04b42b23, 0x05b8b2d5, 0x053efe2e, 0x0fc54e89, 0x0f430272, 0x0e4f9b84, 0x0ec9d77f, 0x0c56a868, 0x0cd0e493, 0x0ddc7d65, 0x0d5a319e, 0x0864cfb0, 0x08e2834b, 0x09ee1abd, 0x09685646, 0x0bf72951, 0x0b7165aa, 0x0a7dfc5c, 0x0afbb0a7, 0x1f0cd1e9, 0x1f8a9d12, 0x1e8604e4, 0x1e00481f, 0x1c9f3708, 0x1c197bf3, 0x1d15e205, 0x1d93aefe, 0x18ad50d0, 0x182b1c2b, 0x192785dd, 0x19a1c926, 0x1b3eb631, 0x1bb8faca, 0x1ab4633c, 0x1a322fc7, 0x10c99f60, 0x104fd39b, 0x11434a6d, 0x11c50696, 0x135a7981, 0x13dc357a, 0x12d0ac8c, 0x1256e077, 0x17681e59, 0x17ee52a2, 0x16e2cb54, 0x166487af, 0x14fbf8b8, 0x147db443, 0x15712db5, 0x15f7614e, 0x3e19a3d2, 0x3e9fef29, 0x3f9376df, 0x3f153a24, 0x3d8a4533, 0x3d0c09c8, 0x3c00903e, 0x3c86dcc5, 0x39b822eb, 0x393e6e10, 0x3832f7e6, 0x38b4bb1d, 0x3a2bc40a, 0x3aad88f1, 0x3ba11107, 0x3b275dfc, 0x31dced5b, 0x315aa1a0,
0x30563856, 0x30d074ad, 0x324f0bba, 0x32c94741, 0x33c5deb7, 0x3343924c, 0x367d6c62, 0x36fb2099, 0x37f7b96f, 0x3771f594, 0x35ee8a83, 0x3568c678, 0x34645f8e, 0x34e21375, 0x2115723b, 0x21933ec0, 0x209fa736, 0x2019ebcd, 0x228694da, 0x2200d821, 0x230c41d7, 0x238a0d2c, 0x26b4f302, 0x2632bff9, 0x273e260f, 0x27b86af4, 0x252715e3, 0x25a15918, 0x24adc0ee, 0x242b8c15, 0x2ed03cb2, 0x2e567049, 0x2f5ae9bf, 0x2fdca544, 0x2d43da53, 0x2dc596a8, 0x2cc90f5e, 0x2c4f43a5, 0x2971bd8b, 0x29f7f170, 0x28fb6886, 0x287d247d, 0x2ae25b6a, 0x2a641791, 0x2b688e67, 0x2beec29c, 0x7c3347a4, 0x7cb50b5f, 0x7db992a9, 0x7d3fde52, 0x7fa0a145, 0x7f26edbe, 0x7e2a7448, 0x7eac38b3, 0x7b92c69d, 0x7b148a66, 0x7a181390, 0x7a9e5f6b, 0x7801207c, 0x78876c87, 0x798bf571, 0x790db98a, 0x73f6092d, 0x737045d6, 0x727cdc20, 0x72fa90db, 0x7065efcc, 0x70e3a337, 0x71ef3ac1, 0x7169763a, 0x74578814, 0x74d1c4ef, 0x75dd5d19, 0x755b11e2, 0x77c46ef5, 0x7742220e, 0x764ebbf8, 0x76c8f703, 0x633f964d, 0x63b9dab6, 0x62b54340, 0x62330fbb,
0x60ac70ac, 0x602a3c57, 0x6126a5a1, 0x61a0e95a, 0x649e1774, 0x64185b8f, 0x6514c279, 0x65928e82, 0x670df195, 0x678bbd6e, 0x66872498, 0x66016863, 0x6cfad8c4, 0x6c7c943f, 0x6d700dc9, 0x6df64132, 0x6f693e25, 0x6fef72de, 0x6ee3eb28, 0x6e65a7d3, 0x6b5b59fd, 0x6bdd1506, 0x6ad18cf0, 0x6a57c00b, 0x68c8bf1c, 0x684ef3e7, 0x69426a11, 0x69c426ea, 0x422ae476, 0x42aca88d, 0x43a0317b, 0x43267d80, 0x41b90297, 0x413f4e6c, 0x4033d79a, 0x40b59b61, 0x458b654f, 0x450d29b4, 0x4401b042, 0x4487fcb9, 0x461883ae, 0x469ecf55, 0x479256a3, 0x47141a58, 0x4defaaff, 0x4d69e604, 0x4c657ff2, 0x4ce33309, 0x4e7c4c1e, 0x4efa00e5, 0x4ff69913, 0x4f70d5e8, 0x4a4e2bc6, 0x4ac8673d, 0x4bc4fecb, 0x4b42b230, 0x49ddcd27, 0x495b81dc, 0x4857182a, 0x48d154d1, 0x5d26359f, 0x5da07964, 0x5cace092, 0x5c2aac69, 0x5eb5d37e, 0x5e339f85, 0x5f3f0673, 0x5fb94a88, 0x5a87b4a6, 0x5a01f85d, 0x5b0d61ab, 0x5b8b2d50, 0x59145247, 0x59921ebc, 0x589e874a, 0x5818cbb1, 0x52e37b16, 0x526537ed, 0x5369ae1b, 0x53efe2e0, 0x51709df7, 0x51f6d10c,
0x50fa48fa, 0x507c0401, 0x5542fa2f, 0x55c4b6d4, 0x54c82f22, 0x544e63d9, 0x56d11cce, 0x56575035, 0x575bc9c3, 0x57dd8538];

function createcrc24(input) {
  var crc = 0xB704CE;
  var index = 0;

  while((input.length - index) > 16)  {
   crc = (crc << 8) ^ crc_table[((crc >> 16) ^ input.charCodeAt(index)) & 0xff];
   crc = (crc << 8) ^ crc_table[((crc >> 16) ^ input.charCodeAt(index+1)) & 0xff];
   crc = (crc << 8) ^ crc_table[((crc >> 16) ^ input.charCodeAt(index+2)) & 0xff];
   crc = (crc << 8) ^ crc_table[((crc >> 16) ^ input.charCodeAt(index+3)) & 0xff];
   crc = (crc << 8) ^ crc_table[((crc >> 16) ^ input.charCodeAt(index+4)) & 0xff];
   crc = (crc << 8) ^ crc_table[((crc >> 16) ^ input.charCodeAt(index+5)) & 0xff];
   crc = (crc << 8) ^ crc_table[((crc >> 16) ^ input.charCodeAt(index+6)) & 0xff];
   crc = (crc << 8) ^ crc_table[((crc >> 16) ^ input.charCodeAt(index+7)) & 0xff];
   crc = (crc << 8) ^ crc_table[((crc >> 16) ^ input.charCodeAt(index+8)) & 0xff];
   crc = (crc << 8) ^ crc_table[((crc >> 16) ^ input.charCodeAt(index+9)) & 0xff];
   crc = (crc << 8) ^ crc_table[((crc >> 16) ^ input.charCodeAt(index+10)) & 0xff];
   crc = (crc << 8) ^ crc_table[((crc >> 16) ^ input.charCodeAt(index+11)) & 0xff];
   crc = (crc << 8) ^ crc_table[((crc >> 16) ^ input.charCodeAt(index+12)) & 0xff];
   crc = (crc << 8) ^ crc_table[((crc >> 16) ^ input.charCodeAt(index+13)) & 0xff];
   crc = (crc << 8) ^ crc_table[((crc >> 16) ^ input.charCodeAt(index+14)) & 0xff];
   crc = (crc << 8) ^ crc_table[((crc >> 16) ^ input.charCodeAt(index+15)) & 0xff];
   index += 16;
  }

  for(var j = index; j < input.length; j++) {
   crc = (crc << 8) ^ crc_table[((crc >> 16) ^ input.charCodeAt(index++)) & 0xff]
  }
  return crc & 0xffffff;
}

