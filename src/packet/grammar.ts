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
 * @param packetList - list of packet tags to validate
 * @param acceptPartial - whether the list of tags corresponds to a partially-parsed message
 * @returns whether the list of tags is valid
 */
const isValidOpenPGPMessage = (
  packetList: number[],
  acceptPartial: boolean
): boolean => {
  return isValidLiteralMessage(packetList) ||
    isValidCompressedMessage(packetList) ||
    isValidEncryptedMessage(packetList) ||
    isValidSignedMessage(packetList, acceptPartial);
};

/**
 * If `delayReporting === false`, the grammar validator throws as soon as an invalid packet sequence is detected during parsing.
 * This setting MUST NOT be used when parsing unauthenticated decrypted data, to avoid instantiating decryption oracles.
 *  Passing `delayReporting === true` allows checking the grammar validity in an async manner, by
 * only reporting the validity status after parsing is done (i.e. and authentication is expected to
 * have been enstablished)
 */
export const getMessageGrammarValidator = ({ delayReporting }: { delayReporting: boolean }) => {
  let logged = false;

  /**
  * @returns `true` on successful grammar validation; if `delayReporting` is set, `null` is returned
  *   if validation is still pending (partial parsing, waiting for authentication to be confirmed).
  * @throws on grammar error, provided `config.enforceGrammar` is enabled.
  */
  return (list: number[], isPartial: boolean, config: Config): true | null => {
    if (delayReporting && isPartial) return null; // delay until the full message has been parsed (i.e. authenticated)

    if (!isValidOpenPGPMessage(list, isPartial)) {
      const error = new GrammarError(`Data does not respect OpenPGP grammar [${list}]`);
      if (!logged) {
        util.printDebugError(error);
        logged = true;
      }
      if (config.enforceGrammar) {
        throw error;
      } else {
        return true;
      }
    }

    return true;
  };
};
