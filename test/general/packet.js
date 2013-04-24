
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


		var key = [[key.d.toMPI(), key.p.toMPI(), key.q.toMPI(), key.u.toMPI()],
			[key.n.toMPI(), key.ee.toMPI()]];

		key = key.map(function(k) {
			return k.map(function(v) {
				var mpi = new openpgp_type_mpi();
				mpi.read(v, 0, v.length);
				return mpi;
				});
		});
		var enc = new openpgp_packet_public_key_encrypted_session_key(),
			msg = new openpgp_packetlist(),
			msg2 = new openpgp_packetlist();

		enc.symmetric_key = '12345678901234567890123456789012',
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
	}];

	var results = [];

	for(var i in tests) {
		results.push(tests[i]());
	}
	
	
	return results;
})
