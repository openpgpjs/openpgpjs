describe("RIPE-MD 160 bits test with test vectors from http://homes.esat.kuleuven.be/~bosselae/ripemd160.html", function() {

    it("RMDstring (\"\") = 9c1185a5c5e9fc54612808977ee8f548b2258d31", function() {
        expect(util.hexstrdump(RMDstring(""))).toBe("9c1185a5c5e9fc54612808977ee8f548b2258d31");
    });
    it("RMDstring (\"a\") = 0bdc9d2d256b3ee9daae347be6f4dc835a467ffe", function() {
        expect(util.hexstrdump(RMDstring("a"))).toBe("0bdc9d2d256b3ee9daae347be6f4dc835a467ffe");
    });
    it("RMDstring (\"abc\") = 8eb208f7e05d987a9b044a8e98c6b087f15a0bfc", function() {
        expect(util.hexstrdump(RMDstring("abc"))).toBe("8eb208f7e05d987a9b044a8e98c6b087f15a0bfc");
    });
    it("RMDstring (\"message digest\") = 5d0689ef49d2fae572b881b123a85ffa21595f36", function() {
        expect(util.hexstrdump(RMDstring("message digest"))).toBe("5d0689ef49d2fae572b881b123a85ffa21595f36");
    });
});
