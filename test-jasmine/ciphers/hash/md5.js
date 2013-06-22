describe("MD5 test with test vectors from RFC 1321", function () {
    it("MD5 (\"\") = d41d8cd98f00b204e9800998ecf8427e", function () {
        expect(util.hexstrdump(MD5(""))).toBe("d41d8cd98f00b204e9800998ecf8427e");
    });
    it("MD5 (\"a\") = 0cc175b9c0f1b6a831c399e269772661", function() {
        expect(util.hexstrdump(MD5("abc"))).toBe("900150983cd24fb0d6963f7d28e17f72");
    });
    it("MD5 (\"message digest\") = f96b697d7cb7938d525a2f31aaf161d0", function() {
        expect(util.hexstrdump(MD5("message digest"))).toBe("f96b697d7cb7938d525a2f31aaf161d0");
    });
    it("MD5 (\"abcdefghijklmnopqrstuvwxyz\") = c3fcd3d76192e4007dfb496cca67e13b", function() {
        expect(util.hexstrdump(MD5("abcdefghijklmnopqrstuvwxyz"))).toBe("c3fcd3d76192e4007dfb496cca67e13b");
    });
    it("MD5 (\"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789\") = d174ab98d277d9f5a5611c2c9f419d9f", function () {
        expect(util.hexstrdump(MD5("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"))).toBe("d174ab98d277d9f5a5611c2c9f419d9f");
    });
    it("MD5 (\"12345678901234567890123456789012345678901234567890123456789012345678901234567890\") = 57edf4a22be3c955ac49da2e2107b67a", function () {
        expect(util.hexstrdump(MD5("12345678901234567890123456789012345678901234567890123456789012345678901234567890"))).toBe("57edf4a22be3c955ac49da2e2107b67a");
    });
});
