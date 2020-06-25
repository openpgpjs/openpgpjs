importScripts('../../dist/openpgp.js');

const publicKeyArmored = `-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: OpenPGP.js v4.7.2
Comment: https://openpgpjs.org

xjMEXh8OhhYJKwYBBAHaRw8BAQdAgfwsqplEv19tUU/CoJOsGiWhssumaO5p
aFHmyl5hHpbNIURhbmllbCA8ZC5odWlnZW5zQHByb3Rvbm1haWwuY29tPsJ4
BBAWCgAgBQJeHw6GBgsJBwgDAgQVCAoCBBYCAQACGQECGwMCHgEACgkQ33Rm
ygBzJWpArgEA7EG2cf40B92+ohh5+r6G/YBzwgy0JxhdYeI6VeTLjwABAIMO
45Nn00opO7gI7nqu0VHkWWDREKH3zHcVkitrpXcNzjgEXh8OhhIKKwYBBAGX
VQEFAQEHQK8Z7Zeg4qap2g8+axIMWaHmn+dbsBjMjssfRlkZRx1oAwEIB8Jh
BBgWCAAJBQJeHw6GAhsMAAoJEN90ZsoAcyVqjigA/0q+C3cX2cVRFOWq1xKt
aKsRWgxXiPCDD1SP6nqS9dIiAP9bl5iix1Wo1eTSV1f+nqGmTkFaZbnvcfZy
Q9eY5AnnBg==
=jTkZ
-----END PGP PUBLIC KEY BLOCK-----
`;

const privateKeyArmored = `-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: OpenPGP.js v4.7.2
Comment: https://openpgpjs.org

xYYEXh8OhhYJKwYBBAHaRw8BAQdAgfwsqplEv19tUU/CoJOsGiWhssumaO5p
aFHmyl5hHpb+CQMIQGjCBRmnRL1g1x10ygKW8a29+2V7pGbRFShEi+92Y6Xa
js3SmduC5K9T2Jnn3Mn1esoCA0gliMpakkWZm3B65J2axI8qo8RTGRnRP1Yp
w80hRGFuaWVsIDxkLmh1aWdlbnNAcHJvdG9ubWFpbC5jb20+wngEEBYKACAF
Al4fDoYGCwkHCAMCBBUICgIEFgIBAAIZAQIbAwIeAQAKCRDfdGbKAHMlakCu
AQDsQbZx/jQH3b6iGHn6vob9gHPCDLQnGF1h4jpV5MuPAAEAgw7jk2fTSik7
uAjueq7RUeRZYNEQoffMdxWSK2uldw3HiwReHw6GEgorBgEEAZdVAQUBAQdA
rxntl6DipqnaDz5rEgxZoeaf51uwGMyOyx9GWRlHHWgDAQgH/gkDCNKsGYh3
rcY5YKc2PzxhFexONEmwJ6Cq3KJ+nW9RbRDYb78aitaacLmWfuxNYu12OhKr
DLwUsgyr8vXKg6yZcmNnpi0P1VYElfb4ECZABq/CYQQYFggACQUCXh8OhgIb
DAAKCRDfdGbKAHMlao4oAP9Kvgt3F9nFURTlqtcSrWirEVoMV4jwgw9Uj+p6
kvXSIgD/W5eYosdVqNXk0ldX/p6hpk5BWmW573H2ckPXmOQJ5wY=
=lOCw
-----END PGP PRIVATE KEY BLOCK-----
`;

onmessage = async function({ data: { action, message }, ports: [port] }) {
  try {
    let result;
    switch (action) {
      case 'encrypt': {
        const publicKey = await openpgp.readArmoredKey(publicKeyArmored);
        const privateKey = await openpgp.readArmoredKey(privateKeyArmored);
        await privateKey.decrypt('test');
        const data = await openpgp.encrypt({
          message: openpgp.Message.fromText(message),
          publicKeys: publicKey,
          privateKeys: privateKey
        });
        result = data;
        break;
      }
      case 'decrypt': {
        const publicKey = await openpgp.readArmoredKey(publicKeyArmored);
        const privateKey = await openpgp.readArmoredKey(privateKeyArmored);
        await privateKey.decrypt('test');
        const { data, signatures } = await openpgp.decrypt({
          message: await openpgp.readArmoredMessage(message),
          publicKeys: publicKey,
          privateKeys: privateKey
        });
        if (!signatures[0].valid) {
          throw new Error("Couldn't veriy signature");
        }
        result = data;
        break;
      }
    }
    port.postMessage({ result });
  } catch (e) {
    console.error(e);
    port.postMessage({ error: e.message });
  }
};
