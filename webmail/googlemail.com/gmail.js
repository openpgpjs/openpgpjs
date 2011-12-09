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

// The google mail interface
// these functions retrieve an email out of html
var Gmail  = {

	getMail : function(callback) {
	var unquote_printable = function(text) {
		var result = "";
		while (text.indexOf("=") != -1) {
			var i = text.indexOf("=");
			result += text.substring(0, i);
			result += String.fromCharCode(parseInt(text.substring(i+1, i+3),16));
			text = text.substring(i+3);
		}
		result += text;
		return result;
	};
	var xhr = new XMLHttpRequest();
	xhr.open("GET", "https://mail.google.com/mail/h/?v=om&th="+document.location.hash.split("/")[1],true);
	xhr.onreadystatechange = function() {
		if (xhr.readyState == 4) {
			var mail = new Object();
			var msg = xhr.responseText.replace(/\r\n/g,"\n").replace(/\n/g,"\r\n");
			var header = msg.substring(0, msg.indexOf("\r\n\r\n")).replace(/\r\n /g," ").split("\r\n");
			mail.body = msg.substring(msg.indexOf("\r\n\r\n")+4);
			for (var i = 0; i < header.length; i++) {
				var split = header[i].split(": ")
				if (split[0] == "Content-Transfer-Encoding" && split[1] == "quoted-printable")
					mail.body = unquote_printable(mail.body);
			}
			mail.account = document.getElementsByTagName("title")[0].textContent.split(" - ")[2];	
			
			for (var i = 0; i < header.length; i++) {
				var split = header[i].split(": ");
				if (split.length < 2) continue;
				if (split[0] == "To")
					mail.to = split[1].split(", ");
				else if (split[0] == "CC")
				    mail.cc = split[1].split(", ");
				else if (split[0] == "Subject")
					mail.subject = split[1];
				else if (split[0] == "From")
					mail.from = split[1];
				else if (split[0] == "Date")
				mail.date = new Date(split[1]);
			}
			callback(mail);
			
		}
	};
	xhr.send();
}
};

