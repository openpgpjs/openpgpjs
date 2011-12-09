
unittests.register("SHA* test with test vectors from NIST FIPS 180-2", function() {
	var result = new Array();
	
	result[0] = new test_result("SHA1 - a9993e364706816aba3e25717850c26c9cd0d89d = str_sha1(\"abc\") ",
			"a9993e364706816aba3e25717850c26c9cd0d89d" == util.hexstrdump(str_sha1("abc")));
	result[1] = new test_result("SHA1 - 84983e441c3bd26ebaae4aa1f95129e5e54670f1 = str_sha1(\"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq\") ",
			"84983e441c3bd26ebaae4aa1f95129e5e54670f1" == util.hexstrdump(str_sha1("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")));
	result[2] = new test_result("SHA224 - 23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7 = str_sha224(\"abc\") ",
			"23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7" == util.hexstrdump(str_sha224("abc")));
	result[3] = new test_result("SHA224 - 75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525 = str_sha224(\"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq\") ",
			"75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525" == util.hexstrdump(str_sha224("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")));
	result[4] = new test_result("SHA256 - ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad = str_sha256(\"abc\") ",
			"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" == util.hexstrdump(str_sha256("abc")));
	result[5] = new test_result("SHA256 - 248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1 = str_sha256(\"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq\") ",
			"248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1" == util.hexstrdump(str_sha256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")));
	result[6] = new test_result("SHA384 - cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7 = str_sha384(\"abc\") ",
			"cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7" == util.hexstrdump(str_sha384("abc")));
	result[7] = new test_result("SHA384 - 3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b = str384(\"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq\") ",
			"3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b" == util.hexstrdump(str_sha384("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")));					
	result[8] = new test_result("SHA512 - ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f = str_sha512(\"abc\") ",
			"ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f" == util.hexstrdump(str_sha512("abc")));
	result[9] = new test_result("SHA512 - 204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445 = str_sha512(\"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq\") ",
			"204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445" == util.hexstrdump(str_sha512("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")));					
	return result;
});
