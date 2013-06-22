describe("SHA* test with test vectors from NIST FIPS 180-2", function () {

    it("SHA1 - a9993e364706816aba3e25717850c26c9cd0d89d = str_sha1(\"abc\") ", function () {
        expect("a9993e364706816aba3e25717850c26c9cd0d89d").toBe(util.hexstrdump(str_sha1("abc")));
    });
    it("SHA1 - 84983e441c3bd26ebaae4aa1f95129e5e54670f1 = str_sha1(\"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq\") ", function () {
        expect("84983e441c3bd26ebaae4aa1f95129e5e54670f1").toBe(util.hexstrdump(str_sha1("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")));
    });
    it("SHA224 - 23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7 = str_sha224(\"abc\") ", function () {
        expect("23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7").toBe(util.hexstrdump(str_sha224("abc")));
    });
    it("SHA224 - 75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525 = str_sha224(\"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq\") ", function () {
        expect("75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525").toBe(util.hexstrdump(str_sha224("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")));
    });
    it("SHA256 - ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad = str_sha256(\"abc\") ", function () {
        expect("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad").toBe(util.hexstrdump(str_sha256("abc")));
    });
    it("SHA256 - 248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1 = str_sha256(\"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq\") ", function () {
        expect("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1").toBe(util.hexstrdump(str_sha256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")));
    });
    it("SHA384 - cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7 = str_sha384(\"abc\") ", function () {
        expect("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7").toBe(util.hexstrdump(str_sha384("abc")));
    });
    it("SHA384 - 3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b = str384(\"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq\") ", function () {
        expect("3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b").toBe(util.hexstrdump(str_sha384("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")));
    });
    it("SHA512 - ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f = str_sha512(\"abc\") ", function () {
        expect("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f").toBe(util.hexstrdump(str_sha512("abc")));
    });
    it("SHA512 - 204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445 = str_sha512(\"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq\") ", function () {
        expect("204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445").toBe(util.hexstrdump(str_sha512("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")));
    });
});
