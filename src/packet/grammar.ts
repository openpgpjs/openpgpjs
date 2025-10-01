/** @access private */
import enums from '../enums';

export class GrammarError extends Error {
  constructor(...params: any[]) {
    super(...params);

    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, GrammarError);
    }

    this.name = 'GrammarError';
  }
}

enum MessageType {
  EmptyMessage, // incl. empty signed message
  PlaintextOrEncryptedData,
  EncryptedSessionKeys,
  StandaloneAdditionalAllowedData
}

/**
 * Implement OpenPGP message grammar based on: https://www.rfc-editor.org/rfc/rfc9580.html#section-10.3 .
 * It is slightly more lenient as it also allows standalone ESK sequences, as well as empty (signed) messages.
 * This latter case is needed to allow unknown packets.
 * A new `MessageGrammarValidator` instance must be created for each packet sequence, as the instance is stateful:
 * - `recordPacket` must be called for each packet in the sequence; the function will throw as soon as
 *  an invalid packet is detected.
 * - `recordEnd` must be called at the end of the packet sequence to confirm its validity.
 * @access private
 */
export class MessageGrammarValidator {
  // PDA validator inspired by https://blog.jabberhead.tk/2022/10/26/implementing-packet-sequence-validation-using-pushdown-automata/ .
  private state: MessageType = MessageType.EmptyMessage;
  private leadingOnePassSignatureCounter: number = 0;

  /**
   * Determine validity of the next packet in the sequence.
   * NB: padding, marker and unknown packets are expected to already be filtered out on parsing,
   * and are not accepted by `recordPacket`.
   * @param packet - packet to validate
   * @param additionalAllowedPackets - object containing packets which are allowed anywhere in the sequence, except they cannot precede a OPS packet
   * @throws {GrammarError} on invalid `packet` input
   */
  recordPacket(packet: enums.packet, additionalAllowedPackets?: { [key in enums.packet]: any }) {
    switch (this.state) {
      case MessageType.EmptyMessage:
      case MessageType.StandaloneAdditionalAllowedData:
        switch (packet) {
          case enums.packet.literalData:
          case enums.packet.compressedData:
          case enums.packet.aeadEncryptedData:
          case enums.packet.symEncryptedIntegrityProtectedData:
          case enums.packet.symmetricallyEncryptedData:
            this.state = MessageType.PlaintextOrEncryptedData;
            return;
          case enums.packet.signature:
            // Signature | <AdditionalAllowedPacketsOnly> and
            // OPS | Signature | <AdditionalAllowedPacketsOnly> | Signature and
            // OPS | <AdditionalAllowedPacketsOnly> | Signature are allowed
            if (this.state === MessageType.StandaloneAdditionalAllowedData) {
              if (--this.leadingOnePassSignatureCounter < 0) {
                throw new GrammarError('Trailing signature packet without OPS');
              }
            }
            // this.state remains EmptyMessage or StandaloneAdditionalAllowedData
            return;
          case enums.packet.onePassSignature:
            if (this.state === MessageType.StandaloneAdditionalAllowedData) {
              // we do not allow this case, for simplicity
              throw new GrammarError('OPS following StandaloneAdditionalAllowedData');
            }
            this.leadingOnePassSignatureCounter++;
            // this.state remains EmptyMessage
            return;
          case enums.packet.publicKeyEncryptedSessionKey:
          case enums.packet.symEncryptedSessionKey:
            this.state = MessageType.EncryptedSessionKeys;
            return;
          default:
            if (!additionalAllowedPackets?.[packet]) {
              throw new GrammarError(`Unexpected packet ${packet} in state ${this.state}`);
            }
            this.state = MessageType.StandaloneAdditionalAllowedData;
            return;
        }
      case MessageType.PlaintextOrEncryptedData:
        switch (packet) {
          case enums.packet.signature:
            if (--this.leadingOnePassSignatureCounter < 0) {
              throw new GrammarError('Trailing signature packet without OPS');
            }
            this.state = MessageType.PlaintextOrEncryptedData;
            return;
          default:
            if (!additionalAllowedPackets?.[packet]) {
              throw new GrammarError(`Unexpected packet ${packet} in state ${this.state}`);
            }
            this.state = MessageType.PlaintextOrEncryptedData;
            return;
        }
      case MessageType.EncryptedSessionKeys:
        switch (packet) {
          case enums.packet.publicKeyEncryptedSessionKey:
          case enums.packet.symEncryptedSessionKey:
            this.state = MessageType.EncryptedSessionKeys;
            return;
          case enums.packet.symEncryptedIntegrityProtectedData:
          case enums.packet.aeadEncryptedData:
          case enums.packet.symmetricallyEncryptedData:
            this.state = MessageType.PlaintextOrEncryptedData;
            return;
          case enums.packet.signature:
            if (--this.leadingOnePassSignatureCounter < 0) {
              throw new GrammarError('Trailing signature packet without OPS');
            }
            this.state = MessageType.PlaintextOrEncryptedData;
            return;
          default:
            if (!additionalAllowedPackets?.[packet]) {
              throw new GrammarError(`Unexpected packet ${packet} in state ${this.state}`);
            }
            this.state = MessageType.EncryptedSessionKeys;
        }
    }
  }

  /**
   * Signal end of the packet sequence for final validity check
   * @throws {GrammarError} on invalid sequence
   */
  recordEnd() {
    switch (this.state) {
      case MessageType.EmptyMessage: // needs to be allowed for PacketLists that only include unknown packets
      case MessageType.PlaintextOrEncryptedData:
      case MessageType.EncryptedSessionKeys:
      case MessageType.StandaloneAdditionalAllowedData:
        if (this.leadingOnePassSignatureCounter > 0) {
          throw new GrammarError('Missing trailing signature packets');
        }
    }
  }
}
