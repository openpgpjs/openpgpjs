const openpgp = typeof window !== 'undefined' && window.openpgp ? window.openpgp : require('../..');
const crypto = require('../../src/crypto');
const util = require('../../src/util');

const chai = require('chai');
chai.use(require('chai-as-promised'));

const expect = chai.expect;

module.exports = () => describe('API functional testing', function() {
  const RSAPublicKeyMaterial = util.concatUint8Array([
    new Uint8Array([0x08,0x00,0xac,0x15,0xb3,0xd6,0xd2,0x0f,0xf0,0x7a,0xdd,0x21,0xb7,
      0xbf,0x61,0xfa,0xca,0x93,0x86,0xc8,0x55,0x5a,0x4b,0xa6,0xa4,0x1a,
      0x60,0xa2,0x3a,0x37,0x06,0x08,0xd8,0x15,0x8e,0x85,0x45,0xaa,0xb7,
      0x1d,0x7b,0x0b,0x73,0x94,0x55,0x0c,0x5c,0xec,0xc0,0x22,0x4b,0xa1,
      0x64,0x20,0x7d,0x4d,0xa8,0x96,0x1a,0x64,0x38,0x93,0xcd,0xec,0x73,
      0x5d,0xf9,0x89,0x88,0x24,0x3d,0x48,0xff,0x3b,0x87,0x62,0xd0,0x84,
      0xea,0xff,0x39,0xb5,0x27,0x70,0xea,0x4a,0xb2,0x2e,0x9d,0xf1,0x7c,
      0x23,0xec,0xf4,0x5e,0xea,0x61,0x3d,0xe5,0xd8,0x0d,0xf9,0x59,0x6d,
      0x28,0x00,0xeb,0xcb,0xc9,0x55,0x00,0x72,0x30,0x1f,0x65,0x9d,0xd6,
      0x17,0x58,0x5f,0xa6,0x4a,0xa0,0xdd,0xe1,0x76,0xf2,0xef,0x21,0x9f,
      0x84,0xfc,0xaa,0x5b,0x52,0x6e,0xc1,0xa2,0xb9,0xbd,0xb9,0xf4,0x9e,
      0x49,0x92,0xf2,0xaf,0x57,0x86,0xf2,0xef,0x70,0xbf,0x51,0x40,0xfd,
      0xbf,0x56,0x51,0xe8,0x2c,0xa2,0x4f,0xf8,0xa4,0xd7,0x36,0x18,0x85,
      0xce,0x09,0x0d,0xbc,0x8d,0x65,0x5e,0x8a,0x1d,0x98,0xb0,0x4d,0x9d,
      0xc1,0xcf,0x82,0xe1,0xb7,0x43,0x5d,0x5a,0x72,0xcd,0x55,0xd2,0xff,
      0xb1,0xb4,0x78,0xbf,0xa1,0x7d,0xac,0xd9,0x1b,0xc4,0xfa,0x39,0x34,
      0x92,0x09,0xf9,0x08,0x2a,0x6b,0x9d,0x14,0x56,0x12,0x4c,0xe9,0xa6,
      0x29,0xc1,0xf3,0xa9,0x0b,0xfc,0x31,0x75,0x58,0x74,0x2a,0x88,0xaf,
      0xee,0xc9,0xa4,0xcd,0x15,0xdc,0x1b,0x8d,0x64,0xc1,0x36,0x17,0xc4,
      0x8d,0x5e,0x99,0x7a,0x5b,0x9f,0x39,0xd0,0x00,0x6e,0xf9]),
    new Uint8Array([0x00,0x11,0x01,0x00,0x01])
  ]);
  const RSAPrivateKeyMaterial = util.concatUint8Array([
    new Uint8Array([0x07,0xfe,0x23,0xff,0xce,0x45,0x6c,0x60,0x65,0x40,0x6e,0xae,0x35,
      0x10,0x56,0x60,0xee,0xab,0xfa,0x10,0x42,0xba,0xc7,0x04,0xaf,0x63,
      0xcd,0x3f,0x62,0xca,0x4b,0xfa,0xe1,0xa9,0x70,0xcd,0x34,0x8b,0xc8,
      0x0e,0xe4,0xc4,0xba,0x83,0x17,0x5f,0xa4,0xb8,0xea,0x60,0xc2,0x4d,
      0x9a,0xf2,0xa9,0x03,0xeb,0xf6,0xaa,0xc2,0xb8,0x8b,0x43,0x12,0xe9,
      0xf7,0x88,0xd2,0x5a,0xa6,0xaa,0x23,0x71,0x31,0x74,0xdb,0x19,0x20,
      0x15,0x41,0x1b,0x43,0x68,0x62,0xd8,0xc0,0x93,0x91,0xe8,0xfc,0xb1,
      0xa9,0x9a,0x52,0x6c,0xe0,0xbf,0x43,0x01,0xa8,0x37,0x14,0x28,0xbf,
      0x0b,0x15,0x56,0x3e,0xa5,0x79,0xa0,0xc4,0x42,0x88,0xee,0xeb,0x1b,
      0xf4,0x7a,0x4a,0x58,0x31,0x58,0x81,0xd2,0x3e,0xde,0x07,0x64,0x92,
      0xf0,0x60,0xd3,0x9a,0x29,0xca,0xc6,0x67,0x75,0x07,0xca,0x92,0x39,
      0x56,0xf6,0x11,0x84,0xba,0x6d,0x4b,0xe6,0x6f,0x66,0xc2,0x17,0xeb,
      0x46,0x69,0x1c,0xbb,0xdf,0xc0,0x38,0x00,0xd6,0x01,0xe6,0x70,0x9d,
      0x4b,0x9b,0x70,0xed,0x5c,0xb8,0xcf,0xe8,0x68,0x71,0xbe,0x24,0x6d,
      0xb1,0xa3,0x13,0xcc,0xf1,0xbc,0x67,0xdc,0xe0,0x69,0x09,0x82,0x3c,
      0x3b,0x0f,0x14,0x98,0x48,0x30,0xb2,0x70,0xc6,0x9e,0xfa,0x46,0x8f,
      0xf1,0xc0,0x65,0x8e,0xc6,0xae,0xdc,0x47,0x91,0x13,0x1e,0xd6,0x4a,
      0xf2,0xad,0xda,0xc2,0xc7,0x39,0x78,0x99,0xde,0x57,0x14,0x45,0x7f,
      0x32,0x38,0xa3,0x44,0x0f,0xe7,0x39,0x4c,0x6f,0x0f,0x32,0x7e,0xf1,
      0x5c,0x84,0x97,0xdd,0xa0,0x0c,0x87,0x66,0x7d,0x75,0x79]),
    new Uint8Array([0x04,0x00,0xc2,0xbc,0x71,0xf7,0x41,0x4a,0x09,0x66,0x70,0x02,0x68,
      0x8b,0xeb,0xe2,0x34,0xd1,0x12,0x83,0x93,0x75,0xe9,0x71,0x32,0xe2,
      0xed,0x18,0x6f,0x8e,0x3a,0xff,0x22,0x70,0x28,0x01,0xbf,0x4a,0x39,
      0x41,0xbb,0x3c,0x4a,0xbc,0xb8,0x13,0xfc,0x14,0xf6,0x71,0xa1,0x44,
      0x1c,0x02,0xa1,0x73,0x81,0xcc,0xa0,0x35,0x02,0x3e,0x97,0xb5,0xc4,
      0x94,0x33,0xf1,0xd1,0xdf,0x14,0x3f,0xfb,0x8f,0xb9,0x75,0x70,0xdc,
      0x74,0x3f,0x07,0x35,0x8f,0x53,0xaa,0xb2,0xd6,0x88,0x51,0x71,0x4e,
      0x01,0x24,0xec,0x7d,0xca,0xf6,0xa2,0xb3,0xbb,0xad,0x2e,0x60,0xfb,
      0x1c,0xee,0x49,0xd0,0x4e,0x5c,0xe3,0x1f,0x88,0x48,0xe4,0x68,0x14,
      0x3d,0x71,0xba,0xd7,0x4d,0x35,0x10,0x86,0x37,0x62,0xe0,0xa5,0x0b]),
    new Uint8Array([0x04,0x00,0xe2,0x38,0xf9,0xc8,0x3c,0xd1,0xcf,0x62,0x93,0xc3,0x77,
      0x76,0x97,0x44,0xe8,0xc8,0xca,0x93,0x9a,0xef,0xf0,0x63,0x76,0x25,
      0x3b,0x1c,0x46,0xff,0x90,0x13,0x91,0x15,0x97,0x7e,0x88,0x95,0xd4,
      0x7f,0x2f,0x52,0x6e,0x0d,0x55,0x55,0x2e,0xf1,0x58,0x5c,0x7e,0x56,
      0xd4,0x48,0xaa,0xdb,0x8c,0x44,0x4d,0x84,0x69,0x33,0x87,0x07,0xb2,
      0x7e,0xf5,0xa0,0x60,0xfb,0x73,0x59,0x46,0x29,0xcb,0x1e,0x3f,0x7c,
      0x2f,0xa6,0x53,0xe3,0x8c,0xef,0xd5,0xeb,0xbb,0xc8,0x9a,0x8e,0x66,
      0x4a,0x47,0x2f,0xe1,0xba,0x5e,0x32,0xd4,0x52,0x04,0x88,0x9d,0x63,
      0x3e,0xba,0x71,0x2d,0xf7,0x61,0xd5,0xfc,0x26,0xbf,0xd8,0x60,0x92,
      0x7b,0x94,0xf8,0x6f,0x3d,0x97,0x0b,0x0c,0x52,0x8c,0xb3,0xb6,0x8b]),
    new Uint8Array([0x04,0x00,0xb7,0xc5,0x4d,0x6e,0x2f,0xdd,0xef,0xec,0x07,0x70,0xa2,
      0x7c,0x1c,0x9d,0x8e,0x66,0x60,0x7c,0x61,0x1e,0x45,0xe9,0xdc,0x82,
      0x2f,0xc5,0x7e,0x1a,0xc6,0xd0,0x92,0xc5,0x22,0x9b,0x9a,0xfb,0x73,
      0x95,0x99,0xf2,0x7c,0xdb,0x2a,0x93,0x7b,0x5a,0x29,0x73,0x24,0x16,
      0x41,0x49,0xb5,0xf2,0x5f,0xbe,0xe7,0x64,0x4d,0xda,0x52,0x9e,0xc1,
      0x41,0x40,0x5e,0x03,0x92,0x8d,0x39,0x95,0x1f,0x68,0x9f,0x00,0x2e,
      0x0c,0x6f,0xcf,0xd9,0x6d,0x68,0xf7,0x00,0x4f,0x0e,0xc8,0x0b,0xfa,
      0x51,0xe0,0x22,0xf0,0xff,0xa7,0x42,0xd4,0xde,0x0b,0x47,0x8f,0x2b,
      0xf5,0x4d,0x04,0x32,0x91,0x89,0x4b,0x0e,0x05,0x8d,0x70,0xf9,0xbb,
      0xe7,0xd6,0x76,0xea,0x0e,0x1a,0x90,0x30,0xf5,0x98,0x01,0xc5,0x73])
  ]);

  const DSAPublicKeyMaterial = util.concatUint8Array([
    new Uint8Array([0x08,0x00,0xa8,0x85,0x5c,0x28,0x05,0x94,0x03,0xbe,0x07,0x6c,0x13,0x3e,0x65,
      0xfb,0xb5,0xe1,0x99,0x7c,0xfa,0x84,0xe3,0xac,0x47,0xa5,0xc4,0x46,0xd8,0x5f,
      0x44,0xe9,0xc1,0x6b,0x69,0xf7,0x10,0x76,0x49,0xa7,0x25,0x85,0xf4,0x1b,0xed,
      0xc6,0x60,0xc4,0x5b,0xaa,0xd4,0x87,0xd6,0x8f,0x92,0x56,0x7d,0x55,0x3f,0x45,
      0xae,0x12,0x73,0xda,0x29,0x8c,0xba,0x32,0xcc,0xd7,0xa4,0xd0,0x24,0xb0,0x7c,
      0xd8,0x0c,0x3a,0x91,0x6f,0x98,0x40,0x9c,0x9a,0xa8,0xcc,0x28,0x27,0x95,0x0b,
      0xe1,0x5b,0xb9,0x3b,0x1c,0x1c,0xd2,0xec,0xab,0x07,0x25,0x8d,0x7a,0x2a,0x2b,
      0x16,0x14,0xe8,0xda,0x71,0xd2,0xab,0xba,0x85,0x14,0x0d,0xc5,0xe0,0x88,0xeb,
      0xa5,0xe2,0xd5,0x48,0x3d,0x74,0x0c,0x41,0xeb,0xfd,0xb6,0x4e,0xf9,0x2c,0x82,
      0x17,0xdd,0x64,0x1e,0x19,0x39,0xa3,0x7f,0xf9,0x00,0xcd,0x9b,0xda,0x2e,0xbd,
      0x71,0x12,0xdf,0x0d,0x7c,0x0a,0x6b,0x2d,0x21,0x3b,0x9c,0x66,0x93,0x4a,0x1e,
      0x90,0x79,0xd3,0x5a,0x5b,0xe5,0xb9,0x94,0x1b,0xe6,0x47,0x99,0x06,0x98,0xd8,
      0x2a,0xe5,0xe2,0xa6,0x95,0x6a,0x07,0xc8,0xac,0x7c,0xe9,0xfc,0xa2,0x6a,0x16,
      0x2c,0x94,0x98,0xbd,0x91,0x0a,0x7c,0x7c,0x2c,0xb9,0x7e,0xa2,0x51,0x8b,0x45,
      0x1d,0x46,0x34,0xa8,0x52,0x2b,0xdd,0xd9,0xa8,0xbc,0x46,0x78,0x66,0xe1,0x72,
      0x11,0xf1,0xcb,0x1a,0xb6,0x4e,0x05,0x54,0xf7,0xe9,0xbe,0x4c,0x25,0x59,0x08,
      0x9f,0xf8,0xea,0x25,0x97,0x33,0xd6,0xc9,0x0f,0x59,0x0e,0xfd,0x9f,0xdc,0xe2,
      0xc0,0xcf,0x2f]),
    new Uint8Array([0x01,0x00,0xe1,0x72,0x2c,0xd0,0xbb,0x1a,0x4f,0xb6,0xb6,0x95,0x77,0x71,0x2e,
      0x01,0x48,0x3e,0x35,0x54,0x64,0x2b,0xed,0x40,0x5f,0x65,0x0c,0x57,0x28,0x5f,
      0xfd,0xfd,0xff,0xd7]),
    new Uint8Array([0x07,0xff,0x5d,0x9f,0xc4,0xb5,0x63,0x25,0x9d,0x72,0x88,0xe5,0x53,0x46,0x98,
      0xe3,0xe9,0x62,0xcb,0x0c,0xa1,0xb7,0x75,0x9f,0x18,0x41,0x94,0x32,0x28,0x29,
      0x6d,0x69,0xe0,0x3f,0x7d,0x7b,0x2b,0x06,0x5a,0x33,0x5c,0xd4,0x36,0x31,0x09,
      0x54,0x85,0x9d,0xb8,0x20,0xfe,0xda,0xfc,0xcd,0x1f,0xb1,0x2c,0x15,0x08,0x9d,
      0x32,0x53,0x2f,0xc1,0x42,0x22,0x69,0xff,0x67,0x2e,0x39,0x97,0x50,0x66,0x39,
      0xda,0xcf,0xfd,0x64,0x6f,0x91,0x05,0x64,0x37,0xc5,0x07,0x24,0xaa,0x40,0xa0,
      0x75,0x82,0x1d,0x97,0x96,0x12,0xf1,0xbd,0x9e,0x09,0x26,0x3c,0x97,0x5d,0x57,
      0xb8,0x5c,0x7d,0x89,0x03,0x82,0xcd,0x40,0xe5,0x03,0xe6,0x4a,0xfb,0xbc,0xd2,
      0xef,0x7a,0x89,0x02,0x08,0xc8,0x52,0xfa,0x97,0x74,0x66,0x32,0xae,0xa6,0x52,
      0x4b,0xef,0x5f,0xce,0x91,0x23,0x3f,0xab,0x9d,0x62,0x21,0xef,0x48,0x6d,0x07,
      0x5a,0xba,0xdf,0x00,0x91,0x54,0xea,0x5c,0xfa,0x4b,0x16,0x28,0x1a,0xce,0x48,
      0xb7,0x5c,0x50,0xa5,0x59,0xa4,0xb4,0xaf,0x1f,0xeb,0x8d,0x58,0x3f,0x0a,0xa5,
      0x97,0x2b,0x51,0x56,0xe8,0x88,0xf6,0x07,0xbc,0xdf,0xfa,0x2b,0x7b,0x88,0xe0,
      0x46,0xc8,0x7a,0x3e,0xd8,0x80,0xdb,0x4d,0x87,0x61,0x4f,0x64,0xcd,0xeb,0xe8,
      0x0d,0x86,0x16,0xcc,0xdd,0x6c,0x76,0x66,0xc1,0x73,0xb7,0x08,0x98,0x89,0x2f,
      0x67,0x69,0xd1,0xfc,0x97,0x4d,0xa2,0xce,0xad,0xbb,0x6f,0xab,0xa5,0xd6,0x18,
      0xb3,0x1a,0x96,0x02,0xbc,0x31,0x42,0xa2,0xad,0x77,0xe8,0xe2,0x4c,0x99,0xf9,
      0xdd,0xbe,0xcd]),
    new Uint8Array([0x07,0xff,0x5d,0xfe,0x9c,0x98,0xef,0x3a,0xa6,0x49,0xf0,0x10,0x67,0x79,0x2a,
      0x9d,0x79,0x43,0x06,0xa4,0xa8,0x6b,0x1a,0x6d,0x1f,0x77,0x6e,0x00,0x31,0xb9,
      0xed,0xc9,0x66,0xff,0xf1,0x21,0x32,0xfa,0x62,0x43,0xcd,0x97,0xd3,0x3d,0xaf,
      0xb4,0x29,0x29,0x26,0x4e,0x1c,0xa0,0xad,0x1c,0x07,0x28,0x3f,0xe5,0x43,0x10,
      0xba,0xb4,0x08,0xe0,0xdc,0xa2,0xc3,0x5b,0x1f,0xbd,0x94,0xc7,0x43,0xe5,0xf2,
      0x17,0x30,0x54,0x7f,0x14,0xbe,0xf4,0xbd,0x91,0x3b,0xe4,0x36,0xa4,0x50,0x5b,
      0x37,0x89,0x5e,0xcc,0xc7,0x74,0x54,0x32,0x20,0x09,0x63,0x98,0xb7,0xd9,0xaf,
      0x7f,0xb0,0x6c,0x27,0x43,0xfe,0x52,0xe6,0x1a,0x88,0x59,0x25,0xfc,0xeb,0x43,
      0x50,0xc7,0x65,0x43,0xc1,0x86,0x73,0x58,0x53,0x3a,0xcf,0x7a,0xa3,0x1d,0x56,
      0xc8,0x4a,0x80,0x70,0xb7,0xbf,0xf2,0xa3,0xec,0xe8,0x77,0x05,0x33,0x09,0x9d,
      0xaa,0xca,0xa0,0xe1,0x64,0x64,0x6f,0x76,0x99,0x41,0x75,0x78,0x90,0xf6,0xe7,
      0x23,0xe6,0xec,0x50,0xe5,0x99,0xa8,0x3e,0x1a,0x4b,0xc9,0x88,0x58,0x66,0xae,
      0x1a,0x53,0x5e,0xe4,0xb7,0x86,0xcf,0xa6,0xe5,0xad,0xb4,0x80,0xa0,0xf1,0x0d,
      0x96,0xb8,0x41,0xd0,0x07,0x9a,0x21,0x8d,0x50,0x7f,0x4f,0x73,0x13,0xa2,0xe2,
      0x02,0x07,0xc3,0xa3,0x0f,0x09,0x18,0x7f,0xf7,0x6b,0x90,0x70,0xc0,0xf9,0x0c,
      0x67,0x8d,0x9d,0x14,0xb6,0x9d,0x32,0x82,0xd0,0xb5,0xc6,0x57,0xf0,0x91,0xd9,
      0xc3,0x26,0xae,0x9f,0xa9,0x67,0x49,0x96,0x5c,0x07,0x3e,0x47,0x5c,0xed,0x60,
      0x07,0xac,0x6a])
  ]);
  const DSAPrivateKeyMaterial = util.concatUint8Array([
    new Uint8Array([0x01,0x00,0x9b,0x58,0xa8,0xf4,0x04,0xb1,0xd5,0x14,0x09,0xe1,0xe1,0xa1,0x8a,
      0x0b,0xa3,0xc3,0xa3,0x66,0xaa,0x27,0x99,0x50,0x1c,0x4d,0xba,0x24,0xee,0xdf,
      0xdf,0xb8,0x8e,0x8e])
  ]);

  const elGamalPublicKeyMaterial = util.concatUint8Array([
    new Uint8Array([0x08,0x00,0xea,0xcc,0xbe,0xe2,0xe4,0x5a,0x51,0x18,0x93,0xa1,0x12,0x2f,0x00,
      0x99,0x42,0xd8,0x5c,0x1c,0x2f,0xb6,0x3c,0xd9,0x94,0x61,0xb4,0x55,0x8d,0x4e,
      0x73,0xe6,0x69,0xbc,0x1d,0x33,0xe3,0x2d,0x91,0x23,0x69,0x95,0x98,0xd7,0x18,
      0x5a,0xaf,0xa7,0x93,0xc6,0x05,0x93,0x3a,0xc7,0xea,0xd0,0xb1,0xa9,0xc7,0xab,
      0x41,0x89,0xc8,0x38,0x99,0xdc,0x1a,0x57,0x35,0x1a,0x27,0x62,0x40,0x71,0x9f,
      0x36,0x1c,0x6d,0x18,0x1c,0x93,0xf7,0xba,0x35,0x06,0xed,0x30,0xb8,0xd9,0x8a,
      0x7c,0x03,0xaf,0xba,0x40,0x1f,0x62,0xf1,0x6d,0x87,0x2c,0xa6,0x2e,0x46,0xb0,
      0xaa,0xbc,0xbc,0x93,0xfa,0x9b,0x47,0x3f,0x70,0x1f,0x2a,0xc2,0x66,0x9c,0x7c,
      0x69,0xe0,0x2b,0x05,0xee,0xb7,0xa7,0x7f,0xf3,0x21,0x48,0x85,0xc2,0x95,0x5f,
      0x6f,0x1e,0xb3,0x9b,0x97,0xf8,0x14,0xc3,0xff,0x4d,0x97,0x25,0x29,0x94,0x41,
      0x4b,0x90,0xd8,0xba,0x71,0x45,0x4b,0x1e,0x2f,0xca,0x82,0x5f,0x56,0x77,0xe9,
      0xd3,0x88,0x5d,0x8b,0xec,0x92,0x8b,0x8a,0x23,0x88,0x05,0xf8,0x2c,0xa8,0xf1,
      0x70,0x76,0xe7,0xbf,0x75,0xa8,0x31,0x14,0x8e,0x76,0xc8,0x01,0xa6,0x25,0x27,
      0x49,0xaf,0xdc,0xf4,0xf6,0xf4,0xce,0x90,0x84,0x15,0x2b,0x4d,0xb3,0xcc,0x77,
      0xdb,0x65,0x71,0x75,0xd3,0x00,0x1d,0x22,0xc5,0x42,0x2f,0x51,0xfa,0x7b,0xeb,
      0x6e,0x03,0xd9,0x41,0xdd,0x2d,0x1a,0xdd,0x07,0x74,0x8b,0xb7,0xa2,0xfa,0xb2,
      0x59,0x0e,0x0e,0x94,0x7c,0x00,0xad,0x95,0x23,0x42,0x91,0x18,0x4c,0x97,0xf1,
      0x27,0x62,0x77]),
    new Uint8Array([0x00,0x03,0x05]),
    new Uint8Array([0x07,0xff,0x57,0x19,0x76,0xfc,0x09,0x6a,0x7a,0xf7,0xba,0xb2,0x42,0xbf,0xcd,
      0x2b,0xc1,0x1a,0x79,0x25,0x8c,0xad,0xf4,0x3a,0x0a,0x7a,0x9b,0x4c,0x46,0x3c,
      0xe0,0x4f,0xcc,0x6e,0xe5,0x7a,0x33,0x3a,0x4e,0x80,0xcb,0xd3,0x62,0xd7,0x8f,
      0xe2,0xc8,0xb0,0xd0,0xcb,0x49,0xc9,0x9e,0x2d,0x97,0x16,0x3a,0x7d,0xb1,0xe1,
      0xd3,0xd9,0xd7,0x3f,0x20,0x60,0xe3,0x3e,0x77,0xea,0x0c,0xe4,0x7b,0xf0,0x39,
      0x1a,0x0d,0xd9,0x8f,0x73,0xd2,0x51,0xb8,0x0c,0x0e,0x15,0x1e,0xad,0x7c,0xd8,
      0x9d,0x74,0x6e,0xa2,0x17,0x6b,0x58,0x14,0x2b,0xb7,0xad,0x8a,0xd7,0x66,0xc0,
      0xdf,0xea,0x2d,0xfc,0xc4,0x6e,0x68,0xb6,0x4c,0x9a,0x16,0xa4,0x3d,0xc2,0x26,
      0x0c,0xb7,0xd4,0x13,0x7b,0x22,0xfd,0x84,0xd7,0x0f,0xdc,0x42,0x75,0x05,0x85,
      0x29,0x00,0x31,0x1d,0xec,0x4e,0x22,0x8b,0xf6,0x37,0x83,0x45,0xe5,0xb3,0x31,
      0x61,0x2c,0x02,0xa1,0xc6,0x9d,0xea,0xba,0x3d,0x8a,0xab,0x0f,0x61,0x5e,0x14,
      0x64,0x69,0x1e,0xa0,0x15,0x48,0x86,0xe5,0x11,0x06,0xe8,0xde,0x34,0xc7,0xa7,
      0x3d,0x35,0xd1,0x76,0xc2,0xbe,0x01,0x82,0x61,0x8d,0xe7,0x7e,0x28,0x1d,0x4e,
      0x8c,0xb9,0xe8,0x7e,0xa4,0x5f,0xa6,0x3a,0x9e,0x5d,0xac,0xf3,0x60,0x22,0x14,
      0xd5,0xd5,0xbe,0x1f,0xf0,0x19,0xe6,0x81,0xfd,0x5d,0xe1,0xf8,0x76,0x5f,0xe3,
      0xda,0xba,0x19,0xf3,0xcb,0x10,0xa0,0x6b,0xd0,0x2d,0xbe,0x40,0x42,0x7b,0x9b,
      0x15,0xa4,0x2d,0xec,0xcf,0x09,0xd6,0xe3,0x92,0xc3,0x8d,0x65,0x6b,0x60,0x97,
      0xda,0x6b,0xca])
  ]);

  const elGamalPrivateKeyMaterial = util.concatUint8Array([
    new Uint8Array([0x01,0x52,0x02,0x80,0x87,0xf6,0xe4,0x49,0xd7,0x2e,0x3e,0xfe,0x60,0xb9,0xa3,
      0x2a,0xf0,0x67,0x58,0xe9,0xf6,0x47,0x83,0xde,0x7e,0xfb,0xbb,0xbd,0xdf,0x48,
      0x12,0x1b,0x06,0x7d,0x13,0xbc,0x3b,0x49,0xf9,0x86,0xd4,0x53,0xed,0x2d,0x68])
  ]);

  const algoRSA = openpgp.enums.publicKey.rsaEncryptSign;
  const RSAPublicParams = crypto.parsePublicKeyParams(algoRSA, RSAPublicKeyMaterial).publicParams;
  const RSAPrivateParams = crypto.parsePrivateKeyParams(algoRSA, RSAPrivateKeyMaterial).privateParams;

  const algoDSA = openpgp.enums.publicKey.dsa;
  const DSAPublicParams = crypto.parsePublicKeyParams(algoDSA, DSAPublicKeyMaterial).publicParams;
  const DSAPrivateParams = crypto.parsePrivateKeyParams(algoDSA, DSAPrivateKeyMaterial).privateParams;

  const algoElGamal = openpgp.enums.publicKey.elgamal;
  const elGamalPublicParams = crypto.parsePublicKeyParams(algoElGamal, elGamalPublicKeyMaterial).publicParams;
  const elGamalPrivateParams = crypto.parsePrivateKeyParams(algoElGamal, elGamalPrivateKeyMaterial).privateParams;

  const data = util.strToUint8Array("foobar");

  describe('Sign and verify', function () {
    it('RSA', async function () {
      const RSAsignedData = await crypto.signature.sign(
        openpgp.enums.publicKey.rsaEncryptSign, openpgp.enums.hash.sha1, RSAPublicParams, RSAPrivateParams, data, await crypto.hash.digest(2, data)
      );
      const success = await crypto.signature.verify(
        openpgp.enums.publicKey.rsaEncryptSign, openpgp.enums.hash.sha1, RSAsignedData, RSAPublicParams, data, await crypto.hash.digest(2, data)
      );
      return expect(success).to.be.true;
    });

    it('DSA', async function () {
      const DSAsignedData = await crypto.signature.sign(
        openpgp.enums.publicKey.dsa, openpgp.enums.hash.sha1, DSAPublicParams, DSAPrivateParams, data, await crypto.hash.digest(2, data)
      );
      const success = await crypto.signature.verify(
        openpgp.enums.publicKey.dsa, openpgp.enums.hash.sha1, DSAsignedData, DSAPublicParams, data, await crypto.hash.digest(2, data)
      );

      return expect(success).to.be.true;
    });
  });

  describe('Encrypt and decrypt', function () {
    let symmAlgos = Object.keys(openpgp.enums.symmetric);
    symmAlgos = symmAlgos.filter(function(algo) {
      return algo !== 'idea' && algo !== 'plaintext';
    });

    async function testCFB(plaintext) {
      await Promise.all(symmAlgos.map(async function(algo) {
        const symmKey = await crypto.generateSessionKey(algo);
        const IV = new Uint8Array(crypto.cipher[algo].blockSize);
        const symmencData = await crypto.cfb.encrypt(algo, symmKey, util.strToUint8Array(plaintext), IV, openpgp.config);
        const text = util.uint8ArrayToStr(await crypto.cfb.decrypt(algo, symmKey, symmencData, new Uint8Array(crypto.cipher[algo].blockSize)));
        expect(text).to.equal(plaintext);
      }));
    }

    function testAESGCM(plaintext, nativeDecrypt) {
      symmAlgos.forEach(function(algo) {
        if (algo.substr(0,3) === 'aes') {
          it(algo, async function() {
            const key = await crypto.generateSessionKey(algo);
            const iv = await crypto.random.getRandomBytes(crypto.gcm.ivLength);
            let modeInstance = await crypto.gcm(algo, key);

            const ciphertext = await modeInstance.encrypt(util.strToUint8Array(plaintext), iv);

            openpgp.config.useNative = nativeDecrypt;
            modeInstance = await crypto.gcm(algo, key);

            const decrypted = await modeInstance.decrypt(util.strToUint8Array(util.uint8ArrayToStr(ciphertext)), iv);
            const decryptedStr = util.uint8ArrayToStr(decrypted);
            expect(decryptedStr).to.equal(plaintext);
          });
        }
      });
    }

    it("Symmetric with OpenPGP CFB", async function () {
      await testCFB("hello");
      await testCFB("1234567");
      await testCFB("foobarfoobar1234567890");
      await testCFB("12345678901234567890123456789012345678901234567890");
    });

    describe('Symmetric AES-GCM (native)', function() {
      let useNativeVal;
      beforeEach(function() {
        useNativeVal = openpgp.config.useNative;
        openpgp.config.useNative = true;
      });
      afterEach(function() {
        openpgp.config.useNative = useNativeVal;
      });

      testAESGCM("12345678901234567890123456789012345678901234567890", true);
    });

    describe('Symmetric AES-GCM (asm.js fallback)', function() {
      let useNativeVal;
      beforeEach(function() {
        useNativeVal = openpgp.config.useNative;
        openpgp.config.useNative = false;
      });
      afterEach(function() {
        openpgp.config.useNative = useNativeVal;
      });

      testAESGCM("12345678901234567890123456789012345678901234567890", false);
    });

    describe('Symmetric AES-GCM (native encrypt, asm.js decrypt)', function() {
      let useNativeVal;
      beforeEach(function() {
        useNativeVal = openpgp.config.useNative;
        openpgp.config.useNative = true;
      });
      afterEach(function() {
        openpgp.config.useNative = useNativeVal;
      });

      testAESGCM("12345678901234567890123456789012345678901234567890", false);
    });

    it('Asymmetric using RSA with eme_pkcs1 padding', async function () {
      const symmKey = await crypto.generateSessionKey('aes256');
      return crypto.publicKeyEncrypt(algoRSA, RSAPublicParams, symmKey).then(RSAEncryptedData => {
        return crypto.publicKeyDecrypt(
          algoRSA, RSAPublicParams, RSAPrivateParams, RSAEncryptedData
        ).then(data => {
          expect(data).to.deep.equal(symmKey);
        });
      });
    });

    it('Asymmetric using Elgamal with eme_pkcs1 padding', async function () {
      const symmKey = await crypto.generateSessionKey('aes256');
      return crypto.publicKeyEncrypt(algoElGamal, elGamalPublicParams, symmKey).then(ElgamalEncryptedData => {
        return crypto.publicKeyDecrypt(
          algoElGamal, elGamalPublicParams, elGamalPrivateParams, ElgamalEncryptedData
        ).then(data => {
          expect(data).to.deep.equal(symmKey);
        });
      });
    });
  });
});
