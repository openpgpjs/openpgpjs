
unittests.register("MD5 test with test vectors from RFC 1321", function() {
	var result = new Array();
	result[0] = new test_result("MD5 (\"\") = d41d8cd98f00b204e9800998ecf8427e",
			util.hexstrdump(MD5("")) == "d41d8cd98f00b204e9800998ecf8427e");
	result[1] = new test_result("MD5 (\"a\") = 0cc175b9c0f1b6a831c399e269772661",
			util.hexstrdump(MD5 ("abc")) == "900150983cd24fb0d6963f7d28e17f72");
	result[2] = new test_result("MD5 (\"message digest\") = f96b697d7cb7938d525a2f31aaf161d0",
			util.hexstrdump(MD5 ("message digest")) == "f96b697d7cb7938d525a2f31aaf161d0");
	result[3] = new test_result("MD5 (\"abcdefghijklmnopqrstuvwxyz\") = c3fcd3d76192e4007dfb496cca67e13b",
			util.hexstrdump(MD5 ("abcdefghijklmnopqrstuvwxyz")) == "c3fcd3d76192e4007dfb496cca67e13b");
	result[4] = new test_result("MD5 (\"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789\") = d174ab98d277d9f5a5611c2c9f419d9f",
			util.hexstrdump(MD5 ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")) == "d174ab98d277d9f5a5611c2c9f419d9f");
	result[5] = new test_result("MD5 (\"12345678901234567890123456789012345678901234567890123456789012345678901234567890\") = 57edf4a22be3c955ac49da2e2107b67a",
			util.hexstrdump(MD5 ("12345678901234567890123456789012345678901234567890123456789012345678901234567890")) == "57edf4a22be3c955ac49da2e2107b67a");
	return result;
});
