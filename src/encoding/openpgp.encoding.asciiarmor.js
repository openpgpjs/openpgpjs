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
 * DeArmor an OpenPGP armored message; verify the checksum and return the encoded bytes
 * @text [String] OpenPGP armored message
 * @return either the bytes of the decoded message or an object with attribute "text" containing the message text
 * and an attribute "openpgp" containing the bytes.
 */
function openpgp_encoding_deArmor(text) {
	var type = getPGPMessageType(text);
	if (type != 2) {
	var splittedtext = text.split('-----');
	data = { openpgp: openpgp_encoding_base64_decode(splittedtext[2].split('\n\n')[1].split("\n=")[0].replace(/\n- /g,"\n")),
			type: type};
	if (verifyCheckSum(data.openpgp, splittedtext[2].split('\n\n')[1].split("\n=")[1].split('\n')[0]))
		return data;
	else
		util.print_error("Ascii armor integrity check on message failed: '"+splittedtext[2].split('\n\n')[1].split("\n=")[1].split('\n')[0]+"' should be '"+getCheckSum(data))+"'";
	} else {
		var splittedtext = text.split('-----');
		var result = { text: splittedtext[2].replace(/\n- /g,"\n").split("\n\n")[1],
		               openpgp: openpgp_encoding_base64_decode(splittedtext[4].split("\n\n")[1].split("\n=")[0]),
		               type: type};
		if (verifyCheckSum(result.openpgp, splittedtext[4].split("\n\n")[1].split("\n=")[1]))
				return result;
		else
			util.print_error("Ascii armor integrity check on message failed");
	}
}

/**
 * Finds out which Ascii Armoring type is used. This is an internal function
 * @param text [String] ascii armored text
 * @return 0 = MESSAGE PART n of m
 *         1 = MESSAGE PART n
 *         2 = SIGNED MESSAGE
 *         3 = PGP MESSAGE
 *         4 = PUBLIC KEY BLOCK
 *         5 = PRIVATE KEY BLOCK
 *         null = unknown
 */
function getPGPMessageType(text) {
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
 * Add additional information to the armor version of an OpenPGP binary packet block
 * @param messagetype type of the message
 * @param data
 * @return
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
 * @param messagetype type of the message
 * @param data
 * @param partindex
 * @param parttotal
 * @return
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
		result += '\r\n';
		result += openpgp_encoding_base64_encode(data);
		result += "\r\n="+getCheckSum(data)+"\r\n";
		result += "-----END PGP PRIVATE KEY BLOCK-----\r\n";
		break;
	}

	return result;
}

/**
 * Calculates a checksum over the given data and returns it base64 encoded
 * @param data [String] data to create a CRC-24 checksum for
 * @return [String] base64 encoded checksum
 */
function getCheckSum(data) {
	var c = createcrc24(data);
	var str = "" + String.fromCharCode(c >> 16)+
				   String.fromCharCode((c >> 8) & 0xFF)+
				   String.fromCharCode(c & 0xFF);
	return openpgp_encoding_base64_encode(str);
}

/**
 * Calculates the checksum over the given data and compares it with the given base64 encoded checksum
 * @param data [String] data to create a CRC-24 checksum for
 * @param checksum [String] base64 encoded checksum
 * @return true if the given checksum is correct; otherwise false
 */
function verifyCheckSum(data, checksum) {
	var c = getCheckSum(data);
	var d = checksum;
	return c[0] == d[0] && c[1] == d[1] && c[2] == d[2];
}
/**
 * Internal function to calculate a CRC-24 checksum over a given string (data)
 * @param data [String] data to create a CRC-24 checksum for
 * @return [Integer] the CRC-24 checksum as number
 */
function createcrc24 (data) {
	var crc = 0xB704CE;
	var i;
	var mypos = 0;
	var len = data.length;
	while (len--) {
		crc ^= (data[mypos++].charCodeAt()) << 16;
		for (i = 0; i < 8; i++) {
			crc <<= 1;
			if (crc & 0x1000000)
            	crc ^= 0x1864CFB;
        }
    }
    return crc & 0xFFFFFF;
}
