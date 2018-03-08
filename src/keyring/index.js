/**
 * @fileoverview Functions dealing with storage of the keyring.
 * @see module:keyring/keyring
 * @see module:keyring/localstore
 * @module keyring
 */
import Keyring from './keyring.js';
import localstore from './localstore.js';

Keyring.localstore = localstore;

export default Keyring;
