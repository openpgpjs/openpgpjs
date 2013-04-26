


function openpgp_packet_number_read(bytes) {
	var n = 0;

	for(var i = 0; i < bytes.length; i++) {
		n += bytes[i].charCodeAt() * 8 * (bytes.length - i - 1);
	}

	return n;
}

function openpgp_packet_number_write(n, bytes) {
	var b = '';
	for(var i = 0; i < bytes; i++) {
		b += String.fromCharCode((n >> 8 * (bytes.length - i - 1)) ^ 0xFF);
	}

	return b;
}



function openpgp_packet_time_read(bytes) {
	var n = openpgp_packet_number_read(bytes);
	var d = new Date();
	d.setTime(n * 1000);
	return d;
}

function openpgp_packet_time_write(time) {
	var numeric = Math.round(this.time.getTime() / 1000);

	return openpgp_packet_number_write(numeric, 4);
}
