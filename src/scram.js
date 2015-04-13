'use strict';

/* ========================================================================== *
 * SCRAM (RFC-5802)                                                           *
 * -------------------------------------------------------------------------- *
 * SaltedPassword  := Hi(Normalize(password), salt, i)                        *
 *                                                                            *
 * ClientKey       := HMAC(SaltedPassword, "Client Key")                      *
 * StoredKey       := H(ClientKey)                                            *
 * ServerKey       := HMAC(SaltedPassword, "Server Key")                      *
 *                                                                            *
 * AuthMessage     := client-first-message-bare + "," +                       *
 *                    server-first-message + "," +                            *
 *                    client-final-message-without-proof                      *
 *                                                                            *
 * ClientSignature := HMAC(StoredKey, AuthMessage)                            *
 * ClientProof     := ClientKey XOR ClientSignature                           *
 *                                                                            *
 * ServerSignature := HMAC(ServerKey, AuthMessage)                            *
 *                                                                            *
 * -------------------------------------------------------------------------- *
 * In our extension:                                                          *
 *                                                                            *
 * - Replace SaltedPassword (PBKDF2 with i iterations) with                   *
 *    -> SaltedPassword := KDF(password, kdf_spec)                            *
 * - Replace "Client Key" (string) with                                       *
 *    -> SharedKey := RANDOM(digest_size_of(H))                               *
 * - Replace "Server Key" (string) with                                       *
 *    -> CipherKey := HMAC(ClientKey, SharedKey)                              *
 * - Rename ServerSignature with ServerProof                                  *
 *                                                                            *
 * ========================================================================== */

var Promise = global.Promise || require('promise');
var KDF = require('key-derivation');
var Cipher = require('./scram/Cipher');
var base64 = require('./base64');
var crypto = require('crypto');
var util = require('util');

/* ========================================================================== */

/* Validate subject and audience, returns them concatenated */
function validateMessage(message) {
  if (! message.subject) throw new Error('No subject available in message');
  if (! util.isString(message.subject)) throw new Error('Message subject must be a string');

  var concatenation = message.subject;
  if (message.audience) {
    if (util.isString(message.audience)) {
      concatenation += message.audience;
    } else if (util.isArray(message.audience)) {
      for (var i = 0; i < message.audience.length; i ++) {
        var audience = message.audience[i];
        if (! audience) {
          throw new TypeError('Invalid audience at index ' + i + ' of message');
        } else if (! util.isString(audience)) {
          throw new TypeError('Audience at index ' + i + ' of message is not a string');
        } else {
          concatenation += audience;
        }
      }
    } else {
      throw new TypeError('Audience must be a string or array of strings');
    }
  }

  return concatenation;
}

function authMessage(message) {
  if (! message.client_nonce) throw new Error('No client_nonce available in message');
  if (! message.server_nonce) throw new Error('No server_nonce available in message');
  if (! message.subject) throw new Error('No subject available in message');

  // Validate & concatenate message subject + audience
  var buffer = new Buffer(validateMessage(message), 'utf8');
  return Buffer.concat([buffer, message.client_nonce, message.server_nonce]);
}

function xor(a, b) {
  if (! util.isBuffer(a)) throw new TypeError('Buffer A is not a buffer');
  if (! util.isBuffer(b)) throw new TypeError('Buffer B is not a buffer');
  if (a.length != b.length) throw new TypeError('Buffer lengths differ');
  var c = new Buffer(a.length);
  for (var i = 0; i < b.length; i++) c[i] = a[i] ^ b[i];
  return c;
}


exports = module.exports = Object.freeze({
  Client: require('./scram/Client'),
  Server: require('./scram/Server'),
  Store:  require('./scram/Store')
});

























