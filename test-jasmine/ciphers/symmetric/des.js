describe("TripleDES (EDE) cipher test with test vectors from http://csrc.nist.gov/publications/nistpubs/800-20/800-20.pdf", function() {
    var i;
    var key = util.bin2str([1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]);
	var testvectors = [[[0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00],[0x95,0xF8,0xA5,0xE5,0xDD,0x31,0xD9,0x00]],
	                   [[0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00],[0xDD,0x7F,0x12,0x1C,0xA5,0x01,0x56,0x19]],
	                   [[0x20,0x00,0x00,0x00,0x00,0x00,0x00,0x00],[0x2E,0x86,0x53,0x10,0x4F,0x38,0x34,0xEA]],
	                   [[0x10,0x00,0x00,0x00,0x00,0x00,0x00,0x00],[0x4B,0xD3,0x88,0xFF,0x6C,0xD8,0x1D,0x4F]],
	                   [[0x08,0x00,0x00,0x00,0x00,0x00,0x00,0x00],[0x20,0xB9,0xE7,0x67,0xB2,0xFB,0x14,0x56]],
	                   [[0x04,0x00,0x00,0x00,0x00,0x00,0x00,0x00],[0x55,0x57,0x93,0x80,0xD7,0x71,0x38,0xEF]],
	                   [[0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00],[0x6C,0xC5,0xDE,0xFA,0xAF,0x04,0x51,0x2F]],
	                   [[0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00],[0x0D,0x9F,0x27,0x9B,0xA5,0xD8,0x72,0x60]],
	                   [[0x00,0x80,0x00,0x00,0x00,0x00,0x00,0x00],[0xD9,0x03,0x1B,0x02,0x71,0xBD,0x5A,0x0A]],
	                   [[0x00,0x40,0x00,0x00,0x00,0x00,0x00,0x00],[0x42,0x42,0x50,0xB3,0x7C,0x3D,0xD9,0x51]],
	                   [[0x00,0x20,0x00,0x00,0x00,0x00,0x00,0x00],[0xB8,0x06,0x1B,0x7E,0xCD,0x9A,0x21,0xE5]],
	                   [[0x00,0x10,0x00,0x00,0x00,0x00,0x00,0x00],[0xF1,0x5D,0x0F,0x28,0x6B,0x65,0xBD,0x28]],
	                   [[0x00,0x08,0x00,0x00,0x00,0x00,0x00,0x00],[0xAD,0xD0,0xCC,0x8D,0x6E,0x5D,0xEB,0xA1]],
	                   [[0x00,0x04,0x00,0x00,0x00,0x00,0x00,0x00],[0xE6,0xD5,0xF8,0x27,0x52,0xAD,0x63,0xD1]],
	                   [[0x00,0x02,0x00,0x00,0x00,0x00,0x00,0x00],[0xEC,0xBF,0xE3,0xBD,0x3F,0x59,0x1A,0x5E]],
	                   [[0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00],[0xF3,0x56,0x83,0x43,0x79,0xD1,0x65,0xCD]],
	                   [[0x00,0x00,0x80,0x00,0x00,0x00,0x00,0x00],[0x2B,0x9F,0x98,0x2F,0x20,0x03,0x7F,0xA9]],
	                   [[0x00,0x00,0x40,0x00,0x00,0x00,0x00,0x00],[0x88,0x9D,0xE0,0x68,0xA1,0x6F,0x0B,0xE6]],
	                   [[0x00,0x00,0x20,0x00,0x00,0x00,0x00,0x00],[0xE1,0x9E,0x27,0x5D,0x84,0x6A,0x12,0x98]],
	                   [[0x00,0x00,0x10,0x00,0x00,0x00,0x00,0x00],[0x32,0x9A,0x8E,0xD5,0x23,0xD7,0x1A,0xEC]],
	                   [[0x00,0x00,0x08,0x00,0x00,0x00,0x00,0x00],[0xE7,0xFC,0xE2,0x25,0x57,0xD2,0x3C,0x97]],
	                   [[0x00,0x00,0x04,0x00,0x00,0x00,0x00,0x00],[0x12,0xA9,0xF5,0x81,0x7F,0xF2,0xD6,0x5D]]];

	for (i = 0; i < testvectors.length; i++) {

	    var block = testvectors[i][0];
	    var expected = testvectors[i][1];

	    it("block: " + util.hexidump(block) + " key: " + util.hexstrdump(key), function () {

	        var expectedString = util.bin2str(expected);
	        var res = util.bin2str(desede(block, key));
	        expect(res).toBe(expectedString);
		});
	}

});


