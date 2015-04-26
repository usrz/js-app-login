'use strict';

// Imports
var KDF = require('key-derivation');
var base64 = require('../base64');
var crypto = require('crypto');
var util = require('util');

// Defaults
const DEFAULT_HASH = "SHA256";
const DEFAULT_KDF_SPEC = {
  algorithm: "PBKDF2",
  hash: "SHA256",
  iterations: 10000
}

/* ========================================================================== *
 * Local utility functions                                                    *
 * ========================================================================== */

// -> ServerKey := HMAC(SaltedPassword, "Server Key")
function serverKey(hash, buffer) {
 return crypto.createHmac(hash, buffer)
              .update('Server Key')
              .digest();
}

// -> ClientKey := HMAC(SaltedPassword, "Client Key")
// -> StoredKey := H(ClientKey)
function storedKey(hash, buffer) {
  var clientKey = crypto.createHmac(hash, buffer)
                        .update('Client Key')
                        .digest();
  return crypto.createHash(hash)
               .update(clientKey)
               .digest();
}

/* ========================================================================== *
 * Our "Credentials" class                                                    *
 * ========================================================================== */

function Credentials(serverKey, storedKey, spec) {
  if (util.isBuffer(serverKey)) serverKey = base64.encode(serverKey);
  if (util.isBuffer(storedKey)) storedKey = base64.encode(storedKey);
  if (! util.isString(serverKey)) throw new TypeError("Server Key must be a string");
  if (! util.isString(storedKey)) throw new TypeError("Stored Key must be a string");

  // Freeze spec
  spec = spec ? Object.freeze(JSON.parse(JSON.stringify(spec))) : null;

  // Define our properties
  Object.defineProperties(this, {
    serverKey: { enumerable: true, configurable: false, value: base64.encode(serverKey) },
    storedKey: { enumerable: true, configurable: false, value: base64.encode(storedKey) },
    spec:      { enumerable: true, configurable: false, value: spec }
  });
}

Credentials.generateCredentials = function(key, hash) {
  if (util.isString(key)) key = base64.decode(key);
  if (! util.isBuffer(key)) throw new TypeError('Key must be a buffer');
  if (! hash) hash = DEFAULT_HASH;

  return new Credentials(serverKey(hash, key), storedKey(hash, key));
}

Credentials.deriveCredentials = function(password, hash, kdfSpec) {
  if (! hash) hash = DEFAULT_HASH;

  return new KDF(kdfSpec || DEFAULT_KDF_SPEC)
    .promiseKey(password)
    .then(function(derived) {

      // Put salt in KDF spec
      var spec = derived.kdf_spec;
      spec.salt = base64.encode(derived.salt);

      // Return some credentials
      var key = derived.derived_key;
      return new Credentials(serverKey(hash, key), storedKey(hash, key), spec);
    });
}

/* ========================================================================== *
 * Module exports                                                             *
 * ========================================================================== */
exports = module.exports = Credentials;
