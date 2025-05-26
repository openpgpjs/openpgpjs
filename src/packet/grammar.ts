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

const encryptedDataPackets = new Set([
  enums.packet.aeadEncryptedData,
  enums.packet.symmetricallyEncryptedData,
  enums.packet.symEncryptedIntegrityProtectedData
]);
const dataPackets = new Set([
  enums.packet.literalData,
  enums.packet.compressedData,
  ...encryptedDataPackets
]);

export class MessageGrammarValidator {
  sawDataPacket: boolean = false;
  sawESKs: number = 0;
  sawOPSs: number = 0;
  sawTrailingSigs: number = 0;

  recordPacket(packet: enums.packet) {
    if (packet === enums.packet.publicKeyEncryptedSessionKey || packet === enums.packet.symEncryptedSessionKey) {
      if (this.sawDataPacket) {
        throw new GrammarError('Encrypted session key packet following data packet');
      }
      this.sawESKs++;
    } else if (packet === enums.packet.onePassSignature) {
      if (this.sawDataPacket) {
        throw new GrammarError('One-pass signature packet following data packet');
      }
      if (this.sawESKs) {
        throw new GrammarError('One-pass signature packet following encrypted session key packet');
      }
      this.sawOPSs++;
    } else if (packet === enums.packet.signature) {
      if (this.sawESKs) {
        throw new GrammarError('Signature packet following encrypted session key packet');
      }
      if (this.sawDataPacket) {
        this.sawTrailingSigs++;
      }
    } else if (dataPackets.has(packet)) {
      if (this.sawDataPacket) {
        throw new GrammarError('Multiple data packets in message');
      }
      if (this.sawESKs && !encryptedDataPackets.has(packet)) {
        throw new GrammarError('Non-encrypted data packet following ESK packet');
      }
      this.sawDataPacket = true;
    }
  }

  recordEnd() {
    if (this.sawOPSs !== this.sawTrailingSigs) {
      throw new GrammarError('Mismatched one-pass signature and signature packets');
    }
  }
}
