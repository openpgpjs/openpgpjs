var unit = require('../../unit.js');

unit.register("RIPE-MD 160 bits test with test vectors from http://homes.esat.kuleuven.be/~bosselae/ripemd160.html", function() {

	var openpgp = require('../../../'),
		util = openpgp.util,
		RMDstring = openpgp.crypto.hash.ripemd;

	var result = new Array();
	result[0] = new unit.result("RMDstring (\"\") = 9c1185a5c5e9fc54612808977ee8f548b2258d31",
			util.hexstrdump(RMDstring("")) == "9c1185a5c5e9fc54612808977ee8f548b2258d31");
	result[1] = new unit.result("RMDstring (\"a\") = 0bdc9d2d256b3ee9daae347be6f4dc835a467ffe",
			util.hexstrdump(RMDstring("a")) == "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe");
	result[2] = new unit.result("RMDstring (\"abc\") = 8eb208f7e05d987a9b044a8e98c6b087f15a0bfc",
			util.hexstrdump(RMDstring("abc")) == "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc");
	result[3] = new unit.result("RMDstring (\"message digest\") = 5d0689ef49d2fae572b881b123a85ffa21595f36",
			util.hexstrdump(RMDstring("message digest")) == "5d0689ef49d2fae572b881b123a85ffa21595f36");
	return result;
});
