import type { SinonStub } from 'sinon';
import util from '../src/util';

const webcrypto = typeof crypto !== 'undefined' ? crypto : util.nodeRequire('crypto')?.webcrypto;

type GetRandomValuesFn = typeof crypto.getRandomValues;
let original: GetRandomValuesFn | null = null;

/**
 * Mock `crypto.getRandomValues` using the mocked implementation
 */
export const mockCryptoRandomGenerator = (
  mockedImplementation: GetRandomValuesFn | SinonStub) => {
  if (original !== null) {
    throw new Error('random mock already initialized');
  }

  original = webcrypto.getRandomValues;
  webcrypto.getRandomValues = mockedImplementation;
};

export const restoreCryptoRandomGenerator = () => {
  if (!original) {
    throw new Error('random mock was not initialized');
  }

  webcrypto.getRandomValues = original;
  original = null;
};
