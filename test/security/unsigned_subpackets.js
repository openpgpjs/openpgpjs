const openpgp = typeof window !== 'undefined' && window.openpgp ? window.openpgp : require('../..');

const { readArmoredKey, Key, message, enums, PacketList, SignaturePacket } = openpgp;

const chai = require('chai');
chai.use(require('chai-as-promised'));

const expect = chai.expect;

/*
* This key is long expired and cannot be used for encryption.
*/
const INVALID_KEY = `
-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: OpenPGP.js VERSION
Comment: https://openpgpjs.org

xcMGBDhtQ4ABB/9uAfnjiE8HLfFrk4AzYIoxISvIbqDlItn3Mk2RK4iGTaAL
h+hN8BrqOopgdHj5c3pTo6VDvJLieHwymdZ3d296L55zt2ichhVIgRxh20Tv
j0dYLKGIEWDMBKvQNoDi83eGrIeHGNjRDOipr/PD251LzwaeiNVyw8ce2Fpd
1ORbC2MJU57C2appZqeMJsWPCnsHNkhxPyRGdp+vifgizi/lt2DcQ6C6EiJx
HV0jFDPJnb69LxKLUelRH+l/b2ZHTONu2pZwUXcFpjA5yTrSzO/kaUtGu/Cz
3euQ3scEtvMXgO2R9H7halxYwyXL/PPLmgaUt1RNXGC7BZjkUW4n8qd/ABEB
AAH+CQMITYNkFGQHMiJgt2s69CHTfwUUZg1Yfcq8alY7GpqeH4CayWCMPI+v
l7kIJdl2b9N/xGnpaUMmaXJts6AtlIBLwzxg0syIfgRv4/wfrVeruJ9TfCFC
NbKP3lk3FZCGF0I4T1FSNvyPJ//ee1cX7U/gM7A2g5xyBFnH5d8LTUDlQjXb
a+BwYN2TZaFrvlWwMIU+NQa+EOiyAwXsgyQbVn2d7JsUUs/lyEG2xkWNTeqe
FWKJJvyDwixsxd7oobBSM6Krt2TreuelPBFQxKyaYyv81gASga9wxyfbIuTG
7wAKW9i4pFMgrrIABcnNKOyeAgMDcAYXAW3eNbYDCIDL9/AuOUotPR+0pEun
WssAZGBM78ZlJZ1Qnbg9nT0rn4pHrFQHnBxlWyPEqj1mZ0Svc0vXHVH+8JgN
pwOGxo7DiF5lL/bphdFVMF2e+UPoc1efO4cpW+ZH/BOug14dJROfkrPhrUTp
nYu6VF9N723YVT9PDTg79E4kIzjMDvhV1odHSaxfl4VtgueYv+Bt3n2nXdME
XZVBXbp7jO7pTS5HsOBcModos8ZYS5RcaHPJ6H8807hFyva4GThZ744ryV8b
XnROoC+d/xR4ShA4f/f9QszMXZ+Xlh4IU3Ccz5PF5UiZ/nC5ho5KzJphBB53
c78gjRIXeUK1Rgj2AquF3KDOjCm60oazKzXv8316ZODNJr+HVvGSKeq85z9Z
z/BfXUtn+PrmzHxegusZfFCpB6YAJCILsHgJ2gT8v26QF+1CJ3ngHVnSkghR
z64zJexeqA8ChTZnhPbHVhh5qx2hlNTofBV29LJGa/EpMykO5pZiuaSEkmZx
RpU+iKNYKa3U516O8f9yj+UZ5/t2SJRpT+9fro3RB4lUnt/RdkY8q2R+3owo
xr4sYaInfvrs3eCsmh5UtygUVARKrK84zR1UZXN0aSBUZXN0IDx0ZXN0QGV4
YW1wbGUuY29tPsLAewQQAQgALwUCOG1DgAUJAAAACgYLCQcIAwIJEMwSTBo3
j0N5BBUICgIDFgIBAhkBAhsDAh4BAAD2TQf+KQbrX2zO9SL5ffCK5qu2VigM
0E3uF763II9vRYfXHdZtXY/8K/uBLbu2rdZHwwb/jAHEe60Qf5VjcbIMtCfA
khPB5JuCvW+JEsYhXplNxYka27svfWI75/cYVc/0OharKEaaPOv2F8C1k2jL
Sk7Az01IAJkdwmBkG6fUwupevuvpO+kUQjsHg35q8Lm7G8roCYiK7K7/JQi3
K+e0ovVFvunFSORaG8jR37uT7X7KA0LHD3S7XYO0o2OJi0QKB1wN3H3FEll0
bFznfdIzKKIDzGwC/zhpUMGMwsqVLb8sw/H9cr82yPoM6pXVUqnstKDlLce8
Dc2vwS83Aja9iWrIEg==
=dvRO
-----END PGP PRIVATE KEY BLOCK-----`;

async function getInvalidKey() {
  return await readArmoredKey(INVALID_KEY);
}
async function makeKeyValid() {
  /**
  * Checks if a key can be used for encryption.
  */
  async function encryptFails(k) {
    try {
      await openpgp.encrypt({
        message: message.fromText('Hello', 'hello.txt'),
        publicKeys: k
      });
      return false;
    } catch (e) {
      return true;
    }
  }
  const invalidkey = await getInvalidKey();
  // deconstruct invalid key
  const [pubkey, puser, pusersig] = invalidkey.toPacketlist().map(i => i);
  // create a fake signature
  const fake = new SignaturePacket();
  Object.assign(fake, pusersig);
  // extend expiration times
  fake.keyExpirationTime = 0x7FFFFFFF;
  fake.signatureExpirationTime = 0x7FFFFFFF;
  // add key capability
  fake.keyFlags[0] |= enums.keyFlags.encryptCommunication;
  // create modified subpacket data
  pusersig.read_sub_packets(fake.write_hashed_sub_packets(), false);
  // reconstruct the modified key
  const newlist = new PacketList();
  newlist.concat([pubkey, puser, pusersig]);
  let modifiedkey = new Key(newlist);
  // re-read the message to eliminate any
  // behaviour due to cached values.
  modifiedkey = await readArmoredKey(await modifiedkey.armor());

  expect(await encryptFails(invalidkey)).to.be.true;
  expect(await encryptFails(modifiedkey)).to.be.true;
}

module.exports = () => it('Does not accept unsigned subpackets', makeKeyValid);
