import { type Config } from '../config';
import enums from '../enums';
import util from '../util';

export class GrammarError extends Error {
  constructor(...params: any[]) {
    super(...params);

    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, GrammarError);
    }

    this.name = 'GrammarError';
  }
}


const isValidLiteralMessage = (tagList: enums.packet[]) => tagList.length === 1 && tagList[0] === enums.packet.literalData;
const isValidCompressedMessage = (tagList: enums.packet[]) => tagList.length === 1 && tagList[0] === enums.packet.compressedData;
const isValidEncryptedMessage = (tagList: enums.packet[]) => {
  // Encrypted Message: Encrypted Data | ESK Sequence, Encrypted Data.
  const isValidESKSequence = (tagList: enums.packet[]) => (
    tagList.every(packetTag => new Set([enums.packet.publicKeyEncryptedSessionKey, enums.packet.symEncryptedSessionKey]).has(packetTag))
  );
  const encryptedDataPacketIndex = tagList.findIndex(tag => new Set([enums.packet.aeadEncryptedData, enums.packet.symmetricallyEncryptedData, enums.packet.symEncryptedIntegrityProtectedData]).has(tag));
  if (encryptedDataPacketIndex < 0) {
    return isValidESKSequence(tagList);
  }

  return (encryptedDataPacketIndex === tagList.length - 1) &&
    isValidESKSequence(tagList.slice(0, encryptedDataPacketIndex));
};

const isValidSignedMessage = (tagList: enums.packet[], acceptPartial: boolean) => {
  // Signature Packet, OpenPGP Message | One-Pass Signed Message.
  if (tagList.findIndex(tag => tag === enums.packet.signature) === 0) {
    return isValidOpenPGPMessage(tagList.slice(1), acceptPartial);
  }

  // One-Pass Signed Message:
  //    One-Pass Signature Packet, OpenPGP Message, Corresponding Signature Packet.
  if (tagList.findIndex(tag => tag === enums.packet.onePassSignature) === 0) {
    const correspondingSigPacketIndex = util.findLastIndex(tagList, tag => tag === enums.packet.signature);
    if (correspondingSigPacketIndex !== tagList.length - 1 && !acceptPartial) {
      return false;
    }
    return isValidOpenPGPMessage(tagList.slice(1, correspondingSigPacketIndex < 0 ? undefined : correspondingSigPacketIndex), acceptPartial);
  }

  return false;
};

/**
 * Implements grammar checks based on https://www.rfc-editor.org/rfc/rfc9580.html#section-10.3 .
 * @param packetList - list of packet tags to validate; marker/padding/unknown packet tags are expected to have been already filtered out.
 * @param acceptPartial - whether the list of tags corresponds to a partially-parsed message
 * @returns whether the list of tags is valid
 */
const isValidOpenPGPMessage = (
  packetList: enums.packet[],
  acceptPartial: boolean
): boolean => {
  return isValidLiteralMessage(packetList) ||
    isValidCompressedMessage(packetList) ||
    isValidEncryptedMessage(packetList) ||
    isValidSignedMessage(packetList, acceptPartial);
};

export const getMessageGrammarValidator = () => {
  let logged = false;

  /**
  * @throws on grammar error, provided `config.enforceGrammar` is enabled.
  */
  return (list: number[], isPartial: boolean, config: Config): undefined => {
    if (!isValidOpenPGPMessage(list, isPartial)) {
      const error = new GrammarError(`Data does not respect OpenPGP grammar [${list}]`);
      if (!logged) {
        util.printDebugError(error);
        logged = true;
      }
      if (config.enforceGrammar) {
        throw error;
      }
    }
  };
};
