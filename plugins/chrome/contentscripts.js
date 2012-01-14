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


if (window.location.href.indexOf("https://mail.google.com/mail/?view=cm") == 0) {
	// we are running in the compose window
} else {
	// we are running in the normal interface
	chrome.extension.sendRequest({account: document.getElementsByTagName("script")[4].text.split(",")[10].replace(/"/g,"").trim()}, function(response) {});

}

var current_message_type = -1;
var current_message = null;

/**
 * searches the given text for a pgp message. If a message is available the openpgp message dialog is shown
 * @param text text to be searched
 */
function find_openpgp(text) {
	text = text.replace(/\r\n/g,"\n");
	if (document.location.hash != current_message) {
		if (/-----BEGIN PGP MESSAGE-----/.test(text) && /-----END PGP MESSAGE-----/.test(text)) {
			current_message= document.location.hash;
			current_message_type = 0;
			current_pgp_block = text.substring(text.indexOf("-----BEGIN PGP MESSAGE-----"), text.indexOf("-----END PGP MESSAGE-----")+25);
			current_pgp_block = current_pgp_block.replace(/\n/g,"").replace(/<br>/g,"\n").replace(/<wbr>/g,"");
			if (pgp_verifyCheckSum(current_pgp_block))
				show_pgp_alert();

		} else if (/-----BEGIN PGP SIGNED MESSAGE-----/.test(text) && /-----END PGP SIGNATURE-----/.test(text)) {
			current_message= document.location.hash;
			current_message_type = 1;
			current_pgp_block = text.substring(text.indexOf("-----BEGIN PGP SIGNED MESSAGE-----"), text.indexOf("-----END PGP SIGNATURE-----")+26);
			current_pgp_block = current_pgp_block.replace(/\n/g,"").replace(/<br>/g,"\n").replace(/<wbr>/g,"");
			if (pgp_verifyCheckSum(current_pgp_block.substring(current_pgp_block.indexOf("-----BEGIN PGP SIGNATURE-----"))))
				show_pgp_alert();
		} else {
			hide_pgp_alert();
		}
	}
}

var doc = null;

/**
 * call routine to open the openpgp.html page for handling a message
 * @return null
 */
function start_pgp_dialog() {
	//Gmail does not provide a generic way. to get message data out of the HTML interface so we parse the DOM
	Gmail.getMail(function(msg) {
		msg.action = 1;
	    chrome.extension.sendRequest(msg, function(response) {
	    	// hide_pgp_alert(); // hide pgp alert after opening the openpgp window
	    });
	});
}

/**
 * showing the pgp alert
 * @return
 */
function show_pgp_alert() {
		var div = document.createElement("div");
		var buttonyes = document.createElement("button");
		var buttonno = document.createElement("button");
		buttonyes.setAttribute("type", "submit");
		buttonyes.addEventListener("mousedown", function () {
			var msg = start_pgp_dialog();
		});
		buttonno.setAttribute("type", "submit");
		buttonno.addEventListener("mousedown", function() { hide_pgp_alert(); }, true);
		buttonyes.appendChild(document.createTextNode("Yes"));
		buttonno.appendChild(document.createTextNode("No"));
		div.setAttribute("id", "gpg4browsers_alert");
		div.setAttribute("style","position: fixed; top: 0px; width: 100%; background-color: #eeeeff; border-bottom: 1px solid #aaa;");
		if (current_message_type == 0)
			div.appendChild(document.createTextNode("This mail is encrypted. Do you want to open it with OpenPGP.js?"));
		else if (current_message_type == 1)
			div.appendChild(document.createTextNode("This mail is signed. Do you want to open it with OpenPGP.js?"));
		div.appendChild(buttonyes);
		div.appendChild(buttonno);
		document.body.appendChild(div);
};

/**
 * hiding the pgp alert
 * @return
 */
function hide_pgp_alert() {
	if (document.getElementById("gpg4browsers_alert") != null) {
		document.getElementById("gpg4browsers_alert").parentNode.removeChild(document.getElementById("gpg4browsers_alert"));
	}
}

/**
 * background process timer to constantly check the displayed page for pgp messages
 */
window.setInterval(function() {
     find_openpgp(document.body.innerHTML);
     if (document.getElementById("canvas_frame") != null)
    	 find_openpgp(document.getElementById("canvas_frame").contentDocument.body.innerHTML);
}, 1000);


/**
 * verifies the checksum of an base64 encrypted pgp block
 * @param text containing the base64 block and the base64 encoded checksum
 * @return true if the checksum was correct, false otherwise
 */
function pgp_verifyCheckSum(text) {
	var splittedtext = text.split('-----');
	var data = r2s(splittedtext[2].split('\n\n')[1].split("\n=")[0]);
	var checksum = splittedtext[2].split('\n\n')[1].split("\n=")[1].replace(/\n/g,"");
	var c = getCheckSum(data);
	var d = checksum;
	return c[0] == d[0] && c[1] == d[1] && c[2] == d[2];
}

/**
 * calculates the checksum over a given block of data
 * @param data block to be used
 * @return a string containing the base64 encoded checksum
 */
function getCheckSum(data) {
	var c = createcrc24(data);
	var str = "" + String.fromCharCode(c >> 16)+
				   String.fromCharCode((c >> 8) & 0xFF)+
				   String.fromCharCode(c & 0xFF);
	return s2r(str);
}


/**
 * calculation routine for a CRC-24 checksum
 * @param data
 * @return
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

// base64 implementation

var b64s = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

/**
 * Converting Base64 data to a string
 * @param t base64 encoded data string
 * @return data string
 */
function r2s(t) {
	var c, n;
	var r = '', s = 0, a = 0;
	var tl = t.length;

	for (n = 0; n < tl; n++) {
		c = b64s.indexOf(t.charAt(n));
		if (c >= 0) {
			if (s)
				r += String.fromCharCode(a | (c >> (6 - s)) & 255);
			s = (s + 2) & 7;
			a = (c << s) & 255;
		}
	}
	return r;
}

/**
 * Converting a data string to a base64 encoded string
 * @param t data string
 * @return base64 encoded data string
 */
function s2r(t) {
	var a, c, n;
	var r = '', l = 0, s = 0;
	var tl = t.length;

	for (n = 0; n < tl; n++) {
		c = t.charCodeAt(n);
		if (s == 0) {
			r += b64s.charAt((c >> 2) & 63);
			a = (c & 3) << 4;
		} else if (s == 1) {
			r += b64s.charAt((a | (c >> 4) & 15));
			a = (c & 15) << 2;
		} else if (s == 2) {
			r += b64s.charAt(a | ((c >> 6) & 3));
			l += 1;
			if ((l % 60) == 0)
				r += "\n";
			r += b64s.charAt(c & 63);
		}
		l += 1;
		if ((l % 60) == 0)
			r += "\n";

		s += 1;
		if (s == 3)
			s = 0;
	}
	if (s > 0) {
		r += b64s.charAt(a);
		l += 1;
		if ((l % 60) == 0)
			r += "\n";
		r += '=';
		l += 1;
	}
	if (s == 1) {
		if ((l % 60) == 0)
			r += "\n";
		r += '=';
	}

	return r;
}
