'use strict';

var Promise = global.Promise || require('promise');
var KDF = require('key-derivation');
var crypto = require('crypto');
var util = require('util');

function Scram(hash, kdf, secure) {
  hash = KDF.knownHashes.validate(hash);
  var shared_key_length = KDF.knownHashes.digestLength(hash);
  kdf = new KDF();
  secure = false;

  function generate(secret_key, salt, callback) {

    // Secret key must be a buffer, we wipe it in here!
    if (! util.isBuffer(secret_key)) {
      callback(new TypeError('Secret must be a buffer'));
    }

    // "Salt" here is only used for tests
    if (util.isFunction(salt)) {
      callback = salt;
      salt = null;
    }

    // Compute with the (random) shared key
    function compute(err, shared_key) {
      if (err) {
        secret_key.fill(-1);
        callback(err);
        return;
      }

      // Derive the password using our KDF
      kdf.deriveKey(secret_key, salt, function(err, result) {
        if (err) {
          secret_key.fill(-1);
          callback(err);
          return;
        }

        // Compute our keys
        var hashed_key, client_key, stored_key;
        try {
          hashed_key = result.derived_key;
          client_key = crypto.createHmac('SHA256', hashed_key)
                             .update(shared_key)
                             .digest();
          stored_key = crypto.createHash('SHA256')
                             .update(client_key)
                             .digest();
        } catch (error) {
          callback(error);
          return;
        } finally {
          secret_key.fill(-1);
          hashed_key.fill(-1);
        }

        // Return our magic...
        callback(null, {
          hash: hash,
          salt: result.salt,
          shared_key: shared_key,
          stored_key: stored_key,
          kdf_spec: result.kdf_spec
        });
      });
    }

    // Compute depending on whether a secure or pseudo random is used
    if (secure) {
      crypto.randomBytes(shared_key_length, compute);
    } else {
      crypto.pseudoRandomBytes(shared_key_length, compute);
    }
  }

  // Immutables
  Object.defineProperties(this, {
    'generate': {
      configurable: false,
      enumerable: true,
      value: generate
    },
    'promise': {
      configurable: false,
      enumerable: true,
      value: function promise(secret_key, salt) {
        return new Promise(function(resolve, reject) {
          generate(secret_key, salt, function(err, result) {
            if (err) reject(err);
            else resolve(result);
          })
        });
      }
    }
  });
}

exports = module.exports = Scram;
