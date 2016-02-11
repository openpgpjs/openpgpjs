'use strict';

var crypto = require('./crypto.js'),
  message = require('./message.js');

module.exports = {
  MessageStream: message.MessageStream,
  CipherFeedbackStream: crypto.CipherFeedback
}
