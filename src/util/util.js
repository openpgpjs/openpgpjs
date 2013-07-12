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

var Util = function() {

    this.emailRegEx = /[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?/;
	
	this.hexdump = function(str) {
	    var r=[];
	    var e=str.length;
	    var c=0;
	    var h;
	    var i = 0;
	    while(c<e){
	        h=str.charCodeAt(c++).toString(16);
	        while(h.length<2) h="0"+h;
	        r.push(" "+h);
	        i++;
	        if (i % 32 == 0)
	        	r.push("\n           ");
	    }
	    return r.join('');
	};
	
	/**
	 * Create hexstring from a binary
	 * @param {String} str String to convert
	 * @return {String} String containing the hexadecimal values
	 */
	this.hexstrdump = function(str) {
		if (str == null)
			return "";
	    var r=[];
	    var e=str.length;
	    var c=0;
	    var h;
	    while(c<e){
	        h=str[c++].charCodeAt().toString(16);
	        while(h.length<2) h="0"+h;
	        r.push(""+h);
	    }
	    return r.join('');
	};
	
	/**
	 * Create binary string from a hex encoded string
	 * @param {String} str Hex string to convert
	 * @return {String} String containing the binary values
	 */
	this.hex2bin = function(hex) {
	    var str = '';
	    for (var i = 0; i < hex.length; i += 2)
	        str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
	    return str;
	};
	
	/**
	 * Creating a hex string from an binary array of integers (0..255)
	 * @param {String} str Array of bytes to convert
	 * @return {String} Hexadecimal representation of the array
	 */
	this.hexidump = function(str) {
	    var r=[];
	    var e=str.length;
	    var c=0;
	    var h;
	    while(c<e){
	        h=str[c++].toString(16);
	        while(h.length<2) h="0"+h;
	        r.push(""+h);
	    }
	    return r.join('');
	};


	/**
	 * Convert a native javascript string to a string of utf8 bytes
	 * @param {String} str The string to convert
	 * @return {String} A valid squence of utf8 bytes
	 */
	this.encode_utf8 = function(str) {
		return unescape(encodeURIComponent(str));
	};

	/**
	 * Convert a string of utf8 bytes to a native javascript string
	 * @param {String} utf8 A valid squence of utf8 bytes
	 * @return {String} A native javascript string
	 */
	this.decode_utf8 = function(utf8) {
		try {
      return decodeURIComponent(escape(utf8));
    } catch (e) {
      return utf8;
    }
	};

	var str2bin = function(str, result) {
		for (var i = 0; i < str.length; i++) {
			result[i] = str.charCodeAt(i);
		}

		return result;
	};
	
	var bin2str = function(bin) {
		var result = [];

		for (var i = 0; i < bin.length; i++) {
			result.push(String.fromCharCode(bin[i]));
		}

		return result.join('');
	};

	/**
	 * Convert a string to an array of integers(0.255)
	 * @param {String} str String to convert
	 * @return {Integer[]} An array of (binary) integers
	 */
	this.str2bin = function(str) { 
		return str2bin(str, new Array(str.length));
	};
	
	
	/**
	 * Convert an array of integers(0.255) to a string 
	 * @param {Integer[]} bin An array of (binary) integers to convert
	 * @return {String} The string representation of the array
	 */
	this.bin2str = bin2str;
	
	/**
	 * Convert a string to a Uint8Array
	 * @param {String} str String to convert
	 * @return {Uint8Array} The array of (binary) integers
	 */
	this.str2Uint8Array = function(str) { 
		return str2bin(str, new Uint8Array(new ArrayBuffer(str.length))); 
	};
	
	/**
	 * Convert a Uint8Array to a string. This currently functions 
	 * the same as bin2str. 
	 * @param {Uint8Array} bin An array of (binary) integers to convert
	 * @return {String} String representation of the array
	 */
	this.Uint8Array2str = bin2str;
	
	/**
	 * Calculates a 16bit sum of a string by adding each character 
	 * codes modulus 65535
	 * @param {String} text String to create a sum of
	 * @return {Integer} An integer containing the sum of all character 
	 * codes % 65535
	 */
	this.calc_checksum = function(text) {
		var checksum = {  s: 0, add: function (sadd) { this.s = (this.s + sadd) % 65536; }};
		for (var i = 0; i < text.length; i++) {
			checksum.add(text.charCodeAt(i));
		}
		return checksum.s;
	};
	
	/**
	 * Helper function to print a debug message. Debug 
	 * messages are only printed if
	 * openpgp.config.debug is set to true. The calling
	 * Javascript context MUST define
	 * a "showMessages(text)" function. Line feeds ('\n')
	 * are automatically converted to HTML line feeds '<br/>'
	 * @param {String} str String of the debug message
	 * @return {String} An HTML tt entity containing a paragraph with a 
	 * style attribute where the debug message is HTMLencoded in. 
	 */
	this.print_debug = function(str) {
		if (openpgp.config.debug) {
			str = openpgp_encoding_html_encode(str);
			showMessages("<tt><p style=\"background-color: #ffffff; width: 652px; word-break: break-word; padding: 5px; border-bottom: 1px solid black;\">"+str.replace(/\n/g,"<br>")+"</p></tt>");
		}
	};
	
	/**
	 * Helper function to print a debug message. Debug 
	 * messages are only printed if
	 * openpgp.config.debug is set to true. The calling
	 * Javascript context MUST define
	 * a "showMessages(text)" function. Line feeds ('\n')
	 * are automatically converted to HTML line feeds '<br/>'
	 * Different than print_debug because will call hexstrdump iff necessary.
	 * @param {String} str String of the debug message
	 * @return {String} An HTML tt entity containing a paragraph with a 
	 * style attribute where the debug message is HTMLencoded in. 
	 */
	this.print_debug_hexstr_dump = function(str,strToHex) {
		if (openpgp.config.debug) {
			str = str + this.hexstrdump(strToHex);
			str = openpgp_encoding_html_encode(str);
			showMessages("<tt><p style=\"background-color: #ffffff; width: 652px; word-break: break-word; padding: 5px; border-bottom: 1px solid black;\">"+str.replace(/\n/g,"<br>")+"</p></tt>");
		}
	};
	
	/**
	 * Helper function to print an error message. 
	 * The calling Javascript context MUST define
	 * a "showMessages(text)" function. Line feeds ('\n')
	 * are automatically converted to HTML line feeds '<br/>'
	 * @param {String} str String of the error message
	 * @return {String} A HTML paragraph entity with a style attribute 
	 * containing the HTML encoded error message
	 */
	this.print_error = function(str) {
		str = openpgp_encoding_html_encode(str);
		showMessages("<p style=\"font-size: 80%; background-color: #FF8888; margin:0; width: 652px; word-break: break-word; padding: 5px; border-bottom: 1px solid black;\"><span style=\"color: #888;\"><b>ERROR:</b></span>	"+str.replace(/\n/g,"<br>")+"</p>");
	};
	
	/**
	 * Helper function to print an info message. 
	 * The calling Javascript context MUST define
	 * a "showMessages(text)" function. Line feeds ('\n')
	 * are automatically converted to HTML line feeds '<br/>'.
	 * @param {String} str String of the info message
	 * @return {String} A HTML paragraph entity with a style attribute 
	 * containing the HTML encoded info message
	 */
	this.print_info = function(str) {
		str = openpgp_encoding_html_encode(str);
		showMessages("<p style=\"font-size: 80%; background-color: #88FF88; margin:0; width: 652px; word-break: break-word; padding: 5px; border-bottom: 1px solid black;\"><span style=\"color: #888;\"><b>INFO:</b></span>	"+str.replace(/\n/g,"<br>")+"</p>");
	};
	
	this.print_warning = function(str) {
		str = openpgp_encoding_html_encode(str);
		showMessages("<p style=\"font-size: 80%; background-color: #FFAA88; margin:0; width: 652px; word-break: break-word; padding: 5px; border-bottom: 1px solid black;\"><span style=\"color: #888;\"><b>WARNING:</b></span>	"+str.replace(/\n/g,"<br>")+"</p>");
	};
	
	this.getLeftNBits = function (string, bitcount) {
		var rest = bitcount % 8;
		if (rest == 0)
			return string.substring(0, bitcount / 8);
		var bytes = (bitcount - rest) / 8 +1;
		var result = string.substring(0, bytes);
		return this.shiftRight(result, 8-rest); // +String.fromCharCode(string.charCodeAt(bytes -1) << (8-rest) & 0xFF);
	};

	/**
	 * Shifting a string to n bits right
	 * @param {String} value The string to shift
	 * @param {Integer} bitcount Amount of bits to shift (MUST be smaller 
	 * than 9)
	 * @return {String} Resulting string. 
	 */
	this.shiftRight = function(value, bitcount) {
		var temp = util.str2bin(value);
        if (bitcount % 8 != 0) {
        	for (var i = temp.length-1; i >= 0; i--) {
        		temp[i] >>= bitcount % 8;
        		if (i > 0)
        			temp[i] |= (temp[i - 1] << (8 - (bitcount % 8))) & 0xFF;
        	}
        } else {
        	return value;
        }
        return util.bin2str(temp);
	};
	
	/**
	 * Return the algorithm type as string
	 * @return {String} String representing the message type
	 */
	this.get_hashAlgorithmString = function(algo) {
		switch(algo) {
		case 1:
			return "MD5";
		case 2:
			return "SHA1";
		case 3:
			return "RIPEMD160";
		case 8:
			return "SHA256";
		case 9:
			return "SHA384";
		case 10:
			return "SHA512";
		case 11:
			return "SHA224";
		}
		return "unknown";
	};
};

/**
 * an instance that should be used. 
 */
var util = new Util();
