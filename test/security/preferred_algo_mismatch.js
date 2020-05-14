const openpgp = typeof window !== 'undefined' && window.openpgp ? window.openpgp : require('../..');

const { key, cleartext, enums, PacketList, SignaturePacket } = openpgp;

const chai = require('chai');
chai.use(require('chai-as-promised'));

const expect = chai.expect;

const messageArmor = `-----BEGIN PGP MESSAGE-----
Version: OpenPGP.js VERSION
Comment: https://openpgpjs.org

wYwD3eCUoDfD5yoBA/98Ceee8cVOuwZMscnFXzkldJV6Km/Uozcwsx0+Epqb
31qF6QosSgEBNGet5PXxV3VU5BnjSeMnK3500NFGgLZUYKLqdHmtwj4hIz7S
VpX1fVpp5n8729Fuv9MhRcFrrIrRj5h6Mj8G7xIgCQm+uJTla3X8wRXss8/p
y57epbYHO9JGAZsQl6kFLOsgtlV/NPwAtjsH/AzsQs3Y6WcudHh0XB3E+ncK
BLn6oaBjcnlwdGVk0wJnjV2YZRiZ7V3lUIDdYIMNpL+5qA==
=IoHy
-----END PGP MESSAGE-----`;

const privateKeyArmor = `-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: OpenPGP.js VERSION
Comment: https://openpgpjs.org

xcEYBFvbA08BBACl8U5VEY7TNq1PAzwU0f3soqNfFpKtNFt+LY3q5sasouJ7
zE4/TPYrAaAoM5/yOjfvbfJP5myBUCtkdtIRIY2iP2uOPhfaly8U+zH25Qnq
bmgLfvu4ytPAPrKZF8f98cIeJmHD81SPRgDMuB2U9wwgN6stgVBBCUS+lu/L
/4pyuwARAQABAAP+Jz6BIvcrCuJ0bCo8rEPZRHxWHKfO+m1Wcem+FV6Mf8lp
vJNdsfS2hwc0ZC2JVxTTo6kh1CmPYamfCXxcQ7bmsqWkkq/6d17zKE6BqE/n
spW7qTnZ14VPC0iPrBetAWRlCk+m0cEkRnBxqPOVBNd6VPcZyM7GUOGf/kiw
AsHf+nECANkN1tsqLJ3+pH2MRouF7yHevQ9OGg+rwetBO2a8avvcsAuoFjVw
hERpkHv/PQjKAE7KcBzqLLad0QbrQW+sUcMCAMO3to0tSBJrNA9YkrViT76I
siiahSB/FC9JlO+T46xncRleZeBHc0zoVAP+W/PjRo2CR4ydtwjjalrxcKX9
E6kCALfDyhkRNzZLxg2XOGDWyeXqe80VWnMBqTZK73nZlACRcUoXuvjRc15Q
K2c3/nZ7LMyQidj8XsTq4sz1zfWz4Cejj80cVGVzdCBVc2VyIDx0ZXN0QGV4
YW1wbGUuY29tPsK1BBABCAApBQJb2wNPAgsJCRDd4JSgN8PnKgQVCAoCAxYC
AQIZAQIbDwIeBwMiAQIAABGjA/4y6HjthMU03AC3bIUyYPv6EJc9czS5wysa
5rKuNhzka0Klb0INcX1YZ8usPIIl1rtr8f8xxCdSiqhJpn+uqIPVROHi0XLG
ej3gSJM5i1lIt1jxyJlvVI/7W0vzuE85KDzGXQFNFyO/T9D7T1SDHnS8KbBh
EnxUPL95HuMKoVkf4w==
=oopr
-----END PGP PRIVATE KEY BLOCK-----`;

module.exports = () => it('Does not accept message encrypted with algo not mentioned in preferred algorithms', async function() {
  const message = await openpgp.message.readArmored(messageArmor);
  const privKey = await openpgp.key.readArmored(privateKeyArmor);
  await expect(openpgp.decrypt({ message, privateKeys: [privKey] })).to.be.rejectedWith('A non-preferred symmetric algorithm was used.');
});
