
unittests.register("Packet testing", function() {

	var tests = [function() {



		var literal = new openpgp_packet_literaldata();
		literal.set_data('Hello world', openpgp_packet_literaldata.formats.utf8);
		
		var enc = new openpgp_packet_encrypteddata();
		enc.data.push(literal);

		var key = '12345678901234567890123456789012',
			algo = openpgp.symmetric.aes256;

		enc.encrypt(algo, key);

		var message = new openpgp_packetlist();
		message.push(enc);


		var msg2 = new openpgp_packetlist();
		msg2.read(message.write());

		msg2[0].decrypt(algo, key);

		return msg2[0].data[0].data == literal.data;
	}];

	var results = [];

	for(var i in tests) {
		results.push(tests[i]());
	}
	
	
	return results;
});
