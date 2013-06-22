describe("generate_key_pair", function () {

    openpgp.init();

    it("generates a 1024-bit RSA key pair", function () {
        var pair,
            privateKey,
            privateKeyArmored,
            publicKeyArmored,
            length = 1024,
            keyType = 1, // 1 = RSA
            userid = "Bob Bobson <bob@bob.bob>",
            passphrase = "qwerty uiop";

        pair = openpgp.generate_key_pair(keyType, length, userid, passphrase);

        expect(pair).toBeDefined();
        expect(pair).not.toBeNull();

        privateKey = pair.privateKey;
        expect(privateKey).toBeDefined();
        expect(privateKey).not.toBeNull();

        privateKeyArmored = pair.privateKeyArmored;
        expect(privateKeyArmored).toBeDefined();
        expect(privateKeyArmored).not.toBeNull();
        expect(privateKeyArmored.length).toBeGreaterThan(1);

        publicKeyArmored = pair.publicKeyArmored;
        expect(publicKeyArmored).toBeDefined();
        expect(publicKeyArmored).not.toBeNull();
        expect(publicKeyArmored.length).toBeGreaterThan(1);
    });


    // disabled -- takes a long time
    xit("generates a 2048-bit RSA key pair", function () {
        var pair,
            privateKey,
            privateKeyArmored,
            publicKeyArmored,
            length = 2048,
            keyType = 1, // 1 = RSA
            userid = "Bob Bobson <bob@bob.bob>",
            passphrase = "qwerty uiop";

        pair = openpgp.generate_key_pair(keyType, length, userid, passphrase);

        expect(pair).toBeDefined();
        expect(pair).not.toBeNull();

        privateKey = pair.privateKey;
        expect(privateKey).toBeDefined();
        expect(privateKey).not.toBeNull();

        privateKeyArmored = pair.privateKeyArmored;
        expect(privateKeyArmored).toBeDefined();
        expect(privateKeyArmored).not.toBeNull();
        expect(privateKeyArmored.length).toBeGreaterThan(1);

        publicKeyArmored = pair.publicKeyArmored;
        expect(publicKeyArmored).toBeDefined();
        expect(publicKeyArmored).not.toBeNull();
        expect(publicKeyArmored.length).toBeGreaterThan(1);
    });


    // disabled -- takes a long time
    xit("generates a 4096-bit RSA key pair", function () {
        var pair,
            privateKey,
            privateKeyArmored,
            publicKeyArmored,
            length = 4096,
            keyType = 1, // 1 = RSA
            userid = "Bob Bobson <bob@bob.bob>",
            passphrase = "qwerty uiop";

        pair = openpgp.generate_key_pair(keyType, length, userid, passphrase);

        expect(pair).toBeDefined();
        expect(pair).not.toBeNull();

        privateKey = pair.privateKey;
        expect(privateKey).toBeDefined();
        expect(privateKey).not.toBeNull();

        privateKeyArmored = pair.privateKeyArmored;
        expect(privateKeyArmored).toBeDefined();
        expect(privateKeyArmored).not.toBeNull();
        expect(privateKeyArmored.length).toBeGreaterThan(1);

        publicKeyArmored = pair.publicKeyArmored;
        expect(publicKeyArmored).toBeDefined();
        expect(publicKeyArmored).not.toBeNull();
        expect(publicKeyArmored.length).toBeGreaterThan(1);
    });

});