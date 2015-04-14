'use strict';

var KDF = require('key-derivation');
var base64 = require('../base64');
var crypto = require('crypto');
var util = require('util');

/* ========================================================================== */
/* SCRAM STORE                                                                */
/* ========================================================================== */
function Store(options) {
  options = options || {};

  var hash        = KDF.knownHashes.validate(options.hash || 'SHA256');
  var hash_length = KDF.knownHashes.digestLength(hash);
  var secure      = util.isBoolean(options.secure) ? options.secure : false;
  var kdf         = new KDF(options.kdf_spec);

  /* ------------------------------------------------------------------------ */
  /* Generate secrets suitable for being stored                               */
  /* ------------------------------------------------------------------------ */

  function generate(secret_key, salt) {

    return Promise.resolve(secret_key)

      // Validate secret_key and derive
      .then(function(secret_key) {
        if (util.isBuffer(secret_key)) {
          return kdf.promiseKey(secret_key, salt);
        } else {
          throw new TypeError('Secret key must be a buffer');
        }
      })

      // Properly perform our SCRAM hashing
      .then(function(derived_key) {

        // First thing here, let's wipe the secret key
        secret_key.fill(0);

        // Calculate a random shared key
        // -> SharedKey := RANDOM(digest_size_of(H))
        var random = secure ? crypto.randomBytes : crypto.pseudoRandomBytes;
        var shared_key = random.call(crypto, hash_length);

        // Our derived salted password
        // -> SaltedPassword := KDF(password, kdf_spec)
        var hashed_key = derived_key.derived_key;

        // Calculate the client, stored, master and server keys

        // -> ClientKey := HMAC(SaltedPassword, SharedKey)
        var client_key = crypto.createHmac(hash, hashed_key)
                               .update(shared_key)
                               .digest();

        // -> StoredKey := H(ClientKey)
        var stored_key = crypto.createHash(hash)
                               .update(client_key)
                               .digest();

        // -> MasterKey := HMAC(ClientKey, SharedKey)
        var master_key = crypto.createHmac(hash, client_key)
                               .update(shared_key)
                               .digest();

        // -> ServerKey := HMAC(SaltedPassword, MasterKey)
        var server_key = crypto.createHmac(hash, hashed_key)
                               .update(master_key)
                               .digest();

        // Remember all that we need to save
        var credentials = {
          hash:       hash,
          salt:       base64.encode(derived_key.salt),
          shared_key: base64.encode(shared_key),
          stored_key: base64.encode(stored_key),
          server_key: base64.encode(server_key),
          kdf_spec:   derived_key.kdf_spec
        };

        // Clean up after ourselfves
        hashed_key.fill(0);
        client_key.fill(0);
        stored_key.fill(0);
        master_key.fill(0);
        server_key.fill(0);

        // All done
        return credentials;
      })

      // If something above goes wrong, wipe key, do not rescue
      .catch(function(error) {
        if (util.isBuffer(secret_key)) secret_key.fill(0);
        throw error;
      })
  }

  // Immutables
  Object.defineProperties(this, {
    'generate': { configurable: false, enumerable: true, value: generate }
  });
}

/* ========================================================================== */
/* MODULE EXPORTS                                                             */
/* ========================================================================== */
exports = module.exports = Store;
