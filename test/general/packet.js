
unittests.register("Packet testing", function() {

	var tests = [function() {

		var literal = new openpgp_packet_literal();
		literal.set_data('Hello world', openpgp_packet_literal.format.utf8);
		
		var enc = new openpgp_packet_symmetrically_encrypted();
		enc.packets.push(literal);

		var key = '12345678901234567890123456789012',
			algo = openpgp.symmetric.aes256;

		enc.encrypt(algo, key);

		var message = new openpgp_packetlist();
		message.push(enc);


		var msg2 = new openpgp_packetlist();
		msg2.read(message.write());

		msg2[0].decrypt(algo, key);

		return new test_result('Symmetrically encrypted packet', 
			msg2[0].packets[0].data == literal.data);

	}, function() {
		var key = '12345678901234567890123456789012',
			algo = openpgp.symmetric.aes256;

		var literal = new openpgp_packet_literal(),
			enc = new openpgp_packet_sym_encrypted_integrity_protected(),
			msg = new openpgp_packetlist();

		literal.set_data('Hello world!', openpgp_packet_literal.format.utf8);
		enc.packets.push(literal);
		enc.encrypt(algo, key);
		msg.push(enc);
		


		var msg2 = new openpgp_packetlist();
		msg2.read(msg.write());

		msg2[0].decrypt(algo, key);

		return new test_result('Sym. encrypted integrity protected packet', 
			msg2[0].packets[0].data == literal.data);
	
	}, function() {
			
		var msg = 
			'-----BEGIN PGP MESSAGE-----\n' +
			'Version: GnuPG v2.0.19 (GNU/Linux)\n' +
			'\n' +
			'jA0ECQMCpo7I8WqsebTJ0koBmm6/oqdHXJU9aPe+Po+nk/k4/PZrLmlXwz2lhqBg\n' +
			'GAlY9rxVStLBrg0Hn+5gkhyHI9B85rM1BEYXQ8pP5CSFuTwbJ3O2s67dzQ==\n' +
			'=VZ0/\n' +
			'-----END PGP MESSAGE-----';



		var msgbytes = openpgp_encoding_deArmor(msg).openpgp;

		var parsed = new openpgp_packetlist();
		parsed.read(msgbytes);

		parsed[0].decrypt('test');

		var key = parsed[0].key;
		parsed[1].decrypt(parsed[0].algorithm, key);
		var compressed = parsed[1].packets[0];

		var result = compressed.packets[0].data;

		return new test_result('Sym encrypted session key with a compressed packet',
			result == 'Hello world!\n');

	}, function() {
	
		var rsa = new RSA(),
			key = rsa.generate(512, "10001")


		var key = [
			[key.d, key.p, key.q, key.u],
			[key.n, key.ee]];

		key = key.map(function(k) {
			return k.map(function(bn) {
				var mpi = new openpgp_type_mpi();
				mpi.fromBigInteger(bn);
				return mpi;
				});
		});

		var mpi = new openpgp_type_mpi();
		mpi.fromBigInteger(key[0][1].data);
		mpi.read(mpi.write());

		var enc = new openpgp_packet_public_key_encrypted_session_key(),
			msg = new openpgp_packetlist(),
			msg2 = new openpgp_packetlist();

		enc.symmetric_key = '12345678901234567890123456789012';
		enc.public_key_algorithm = openpgp.publickey.rsa_encrypt;
		enc.symmetric_algorithm = openpgp.symmetric.aes256;
		enc.public_key_id.bytes = '12345678';
		enc.encrypt(key[1]);

		msg.push(enc);

		msg2.read(msg.write());

		msg2[0].decrypt(key[1], key[0]);

		return new test_result('Public key encrypted symmetric key packet', 
			msg2[0].symmetric_key == enc.symmetric_key &&
			msg2[0].symmetric_algorithm == enc.symmetric_algorithm);
	}, function() {
		var armored_key = 
			'-----BEGIN PGP PRIVATE KEY BLOCK-----\n' +
			'Version: GnuPG v2.0.19 (GNU/Linux)\n' +
			'\n' +
			'lQHYBFF33iMBBAC9YfOYahJlWrVj2J1TjQiZLunWljI4G9e6ARTyD99nfOkV3swh\n' +
			'0WaOse4Utj7BfTqdYcoezhCaQpuExUupKWZqmduBcwSmEBfNu1XyKcxlDQuuk0Vk\n' +
			'viGC3kFRce/cJaKVFSRU8V5zPgt6KQNv/wNz7ydEisaSoNbk51vQt5oGfwARAQAB\n' +
			'AAP5AVL8xWMuKgLj9g7/wftMH+jO7vhAxje2W3Y+8r8TnOSn0536lQvzl/eQyeLC\n' +
			'VK2k3+7+trgO7I4KuXCXZqgAbEi3niDYXDaCJ+8gdR9qvPM2gi9NM71TGXZvGE0w\n' +
			'X8gIZfqLTQWKm9TIS/3tdrth4nwhiye0ASychOboIiN6VIECAMbCQ4/noxGV6yTK\n' +
			'VezsGSz+iCMxz2lV270/Ac2C5WPk+OlxXloxUXeEkGIr6Xkmhhpceed2KL41UC8Y\n' +
			'w5ttGIECAPPsahniKGyqp9CHy6W0B83yhhcIbmLlaVG2ftKyUEDxIggzOlXuVrue\n' +
			'z9XRd6wFqwDd1QMFW0uUyHPDCIFPnv8CAJaDFSZutuWdWMt15NZXjfgRgfJuDrtv\n' +
			'E7yFY/p0el8lCihOT8WoHbTn1PbCYMzNBc0IhHaZKAtA2pjkE+wzz9ClP7QbR2Vv\n' +
			'cmdlIDxnZW9yZ2VAZXhhbXBsZS5jb20+iLkEEwECACMFAlF33iMCGwMHCwkIBwMC\n' +
			'AQYVCAIJCgsEFgIDAQIeAQIXgAAKCRBcqs36fwJCXRbvA/9LPiK6WFKcFoNBnLEJ\n' +
			'mS/CNkL8yTpkslpCP6+TwJMc8uXqwYl9/PW2+CwmzZjs6JsvTzMcR/ZbfZJuSW6Y\n' +
			'EsLNejsSpgcY9aiewGtE+53e5oKYnlmVMTWOPywciIgMvXlzdGhxcwqJ8u0hT+ug\n' +
			'9CjcAfuX9yw85LwXtdGwNh7J8Q==\n' +
			'=lKiS\n' +
			'-----END PGP PRIVATE KEY BLOCK-----';

		key = new openpgp_packetlist();
		key.read(openpgp_encoding_deArmor(armored_key).openpgp);
		key = key[0];

		var enc = new openpgp_packet_public_key_encrypted_session_key(),
			secret = '12345678901234567890123456789012';

		enc.symmetric_key = secret;
		enc.public_key_algorithm = openpgp.publickey.rsa_encrypt;
		enc.symmetric_algorithm = openpgp.symmetric.aes256;
		enc.public_key_id.bytes = '12345678';

		enc.encrypt(key.public_key.mpi);

		enc.decrypt(key.public_key.mpi, key.mpi);

		return new test_result('Public key packet (reading, unencrpted)',
			enc.symmetric_key == secret);
	}, function() {





		key = new openpgp_packetlist();
		key.read(openpgp_encoding_deArmor(armored_key).openpgp);
		key = key[0];

		var msg = new openpgp_packetlist();
		msg.read(openpgp_encoding_deArmor(gpg).openpgp);

		msg[0].decrypt(key.public_key.mpi, key.mpi);
		msg[1].decrypt(msg[0].symmetric_algorithm, msg[0].symmetric_key);



		return new test_result('Public key packet (reading, GPG encrypted)',
			true);
	}];

	tests.reverse();

	var results = [];

	for(var i in tests) {
		results.push(tests[i]());
	}
	
	
	return results;
});
