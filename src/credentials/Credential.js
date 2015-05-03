'use strict';

const hashes = require('../util/hashes');
const xor = require('../util/xor');

const util = require('util');

function Credential(cred) {
  if (! util.isObject(cred)) throw new TypeError('Missing credentials definition');

  if (! util.isObject(cred.kdf_spec)) throw new TypeError('Missing or invalid kdf specification');
  var kdf_spec = Object.freeze(JSON.parse(JSON.stringify(cred.kdf_spec)));

  if (! util.isString(cred.hash)) throw new TypeError('Missing or invalid scram hash');
  var hash = cred.hash;

  var stored_key = null;
  if (util.isString(cred.stored_key)) stored_key = new Buffer(cred.stored_key, 'base64');
  else if (util.isBuffer(cred.stored_key)) stored_key = cred.stored_key;
  else if (! util.isNullOrUndefined(cred.stored_key)) throw new TypeError('Invalid stored key');

  var server_key = null;
  if (util.isString(cred.server_key)) server_key = new Buffer(cred.server_key, 'base64');
  else if (util.isBuffer(cred.server_key)) server_key = cred.server_key;
  else if (! util.isNullOrUndefined(cred.server_key)) throw new TypeError('Invalid server key');

  var salt = null;
  if (util.isString(cred.salt)) salt = new Buffer(cred.salt, 'base64');
  else if (util.isBuffer(cred.salt)) salt = cred.salt;
  else throw new TypeError('Invalid or missing salt');

  Object.defineProperties(this, {
    kdf_spec:   { enumerable: true, configurable: false, value: kdf_spec   },
    server_key: { enumerable: true, configurable: false, value: server_key },
    stored_key: { enumerable: true, configurable: false, value: stored_key },
    salt:       { enumerable: true, configurable: false, value: salt       },
    hash:       { enumerable: true, configurable: false, value: hash       }
  });
}

Credential.prototype.verify = function verify(client_proof, auth_message) {
  if (util.isString(client_proof)) client_proof = new Buffer(client_proof, 'base64');
  if (! util.isBuffer(client_proof)) throw new TypeError('Client proof must be a buffer or base64 string');
  if (! util.isBuffer(auth_message)) throw new TypeError('Auth message must be a buffer');

  var server_signature = hashes.createHmac(this.hash, this.stored_key)
                               .update(auth_message)
                               .digest();

  var client_key = xor(client_proof, server_signature);

  var derived_key = hashes.createHash(this.hash)
                          .update(client_key)
                          .digest();

  // Check that the stored key is the same as our derivate, if so we're good!
  if (Buffer.compare(this.stored_key, derived_key) != 0) return;

  // We're still here? Good, send out our proof!
  var server_proof = hashes.createHmac(this.hash, this.server_key)
                           .update(auth_message)
                           .digest();

  // Always use SHA256, as we encrypt in AES-256-GCM
  var encryption_key = hashes.createHmac('sha256', client_key)
                             .update(auth_message)
                             .digest();

  // Return server proof and encryption key
  return {
    encryption_key: encryption_key,
    server_proof: server_proof
  }
}

Credential.prototype.toString = function toString() {
  return Credential + '[' + this.hash + ']';
}

Credential.prototype.toJSON = function toJSON() {
  return {
    kdf_spec:   this.kdf_spec,
    server_key: this.server_key ? this.server_key.toString('base64') : null,
    stored_key: this.stored_key ? this.stored_key.toString('base64') : null,
    salt:       this.salt.toString('base64'),
    hash:       this.hash
  };
}

exports = module.exports = Credential;
