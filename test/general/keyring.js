var openpgp = require('openpgp');

'use strict';

var expect = chai.expect;

describe("Keyring testing", function() {
  var keyring = new (new require('keyring'))();

  keyring.init();
  keyring.importKey([
        '-----BEGIN PGP PUBLIC KEY BLOCK-----',
        'Version: GnuPG v1.4.11 (GNU/Linux)',
        '',
        'mQGiBFERvI4RBAD0M/HGglCtVNXPF72ehT8riAXrl0rSec4RJC61Bh+UAOhxn5+U',
        'fDgos5p1SpIzYmn+M87JoSSVLAjfakFk0gHgR9I3bu7SIwq3Bikk1Vw3gO+yDSO6',
        'TKpLUFGYDiBSSE1MGdxBadWLE1hlRf5B2x62gnGmjSpSVbly33PFkoDmrwCg9rAp',
        'RmncnF9GhWjOLFkEoQw9Yx8EAOsxvq8Ig5Z1gk+ZKfDZeftpHRe3FdrRtbnhxvYY',
        '7z+w9uz1EpoZUwDR5G4X3hTwJQ7lXmIOskg/+eRMLEAqEY7b/7tW6RaUJ2d6Ehsi',
        'dOS89fIxElwjAOnVOM5S24f0FDQTTto7QBOoxcNTfkEJCHXSlpoOUmGAP85fXh3l',
        'yPTGBACJfKc76Un3UWC1sWIRDxYiyh3ZpZyNEskoV6ESW8jEI1RnMnv5TrfGJH5K',
        'E8jWX7TTnoFyPJtBTjlucAtkQaS4Bb7dg1LLja17zAqKNGOJK2b9fb2Z+lnTjPiY',
        'i7DPH1XHnfaEexjlh/U7mYa5RrwIphRxNi8gCuxv874ZMmhEn7QWVGVzdDMgPHRl',
        'c3QzQHRlc3QuY29tPohiBBMRAgAiBQJREbyOAhsDBgsJCAcDAgYVCAIJCgsEFgID',
        'AQIeAQIXgAAKCRC0u8O0Moa2JYxyAJ9Oi2UlcUT0VJNgwjyl/VF9Xcjf9gCeJPvy',
        'g/fp4EAU8MJIaN2yMI8pLFS5AaIEURG8nhEEAKVgeNDuYDPufLuJ0GrJV/CbXEjj',
        'aEPA0iTUqV0nTCPdAfQ/nmE3gh5UlNMr/zSHJ+c4FQhYdLrzRGDOSzV+mfPHH3t+',
        'YVx+wat0BYwABpHAtsIuLIVo2RQqYZYH85tatwBkm71HHT3jmlEAvr6NFH38+v3s',
        '3w4Wl0/sdHyaeiSXAKCxJ4X1eOdN7L1rrbJozQ/gDCFuVQP/dcV6Ksss8Aw443jG',
        'AYBLHWh6o4GhAY6/h1kijF0xD+uc+tNmTQnQi1tEOoTeIZMXnSRwtk8XEuJkkbAP',
        '+uyvMgyV3wrk9zkaTAin7nrjAERxezFOdBEOtnB1CovJxtMn+RRxaMEGpC4GnETy',
        'N5+6FkLuLcNXiCQP75ajzOAN1aID/juNjUNpBbNpfqBV7j1K+Kn0n9HYTyQl9ghy',
        '026+/4c8ag2HV+bg3BD7c2VTVu9xBODHsfu0q8Ql/QB9W8tmYugU6DeXMHaeWPUH',
        'ph98guM9kF2yHIiRBvAd5i7wOjwn+I/Ir6nBR2yxJ3p31CDUnUlbjTPYg7mtQvHW',
        'EY2Cp4SWiJEEGBECAAkFAlERvJ4CGwIAUgkQtLvDtDKGtiVHIAQZEQIABgUCURG8',
        'ngAKCRAMiMeR296Y2SjyAJ9V3wRJJ2Szazqal4khWGfLu5R6/wCfQQIRD24yVdz8',
        '2a+2eCrwyALT2GAihACfS0nWM3a0gtITqngpJsRws+Ep+eIAn15qD2itutxNb8NI',
        'bR2gBB5QmVJ3',
        '=pGA6',
        '-----END PGP PUBLIC KEY BLOCK-----'
        ].join("\n"));

  var msg2 = openpgp.message.readArmored([
        '-----BEGIN PGP MESSAGE-----',
        'Version: GnuPG v1.4.11 (GNU/Linux)',
        '',
        'kA0DAAIRDIjHkdvemNkBrB1iB2Zvby50eHRREbz3VEVTVCBEQVRBIDEyMzQ1NohG',
        'BAARAgAGBQJREbz3AAoJEAyIx5Hb3pjZ2TcAn32LpDEuHe9QrSRlyvSuREKNOFwz',
        'AJ9zh4zsK4GIPuEu81YPNmHsju7DYg==',
        '=WaSx',
        '-----END PGP MESSAGE-----'
        ].join("\n"));

  it('Testing keyring getKeysForKeyId method', function (done) {
    var signingKeyIds = msg2.getSigningKeyIds();
    var key = keyring.getKeysForKeyId(signingKeyIds[0].toHex());
    expect(key).to.exist;
    expect(key).to.have.length(1);

    var verified = msg2.verify(key);
    expect(verified).to.exist;
    expect(verified).to.have.length(1);
    expect(verified[0].valid).to.be.true;
    done();
  });
});

 
