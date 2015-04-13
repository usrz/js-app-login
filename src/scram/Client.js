'use strict';

var KDF = require('key-derivation');
var base64 = require('../base64');
var crypto = require('crypto');
var util = require('util');

var Cipher = require('./Cipher');

var xor = require('./tools').xor;
var normalize = require('./tools').normalize;
var flatten = require('./tools').flatten;

/* ========================================================================== */
/* SCRAM CLIENT                                                               */
/* ========================================================================== */
function Client(options) {
  options = options || {};

  // Calculate an initial random client_nonce
  var nonce_length = Number(options.nonce_length) || 32;
  var secure       = util.isBoolean(options.secure) ? options.secure : false;
  var random       = secure ? crypto.randomBytes : crypto.pseudoRandomBytes;
  var client_nonce = random.call(crypto, nonce_length);

  // Our derived key and auth message for validation
  var derived_key = null;
  var store_key = null;

  function request(subject, audience) {
    return Promise.resolve(flatten(arguments, [], true))
      .then(function(args) {
        return normalize({
          subject: args[0],
          audience: args.splice(1)
        });
      })
  }

  function respond(secret_key, session) {

    return Promise.resolve()

      // Validate parameters and calculate the derived key
      .then(function() {

        // Validate secret key
        if (! util.isBuffer(secret_key)) throw new TypeError('Secret key must be a buffer');

        // Required parameters
        if (! session.client_nonce) throw new Error('No client_nonce available in session');
        if (! session.server_nonce) throw new Error('No server_nonce available in session');
        if (! session.shared_key) throw new Error('No shared_key available in session');
        if (! session.kdf_spec) throw new Error('No kdf_spec specified in session');
        if (! session.salt) throw new Error('No salt specified in session');
        if (! session.hash) throw new Error('No hash specified in session');

        // Validate the client_nonce in the session
        if (Buffer.compare(client_nonce, base64.decode(session.client_nonce)) != 0) {
          throw new Error('Client nonces mismatch');
        }

        // Parameters for SCRAM
        var hash = KDF.knownHashes.validate(session.hash);
        var shared_key = base64.decode(session.shared_key);
        var server_nonce = base64.decode(session.server_nonce);
        var auth_message = Buffer.concat([ client_nonce, server_nonce ]);

        // Salt and spec for KDF
        var salt = base64.decode(session.salt);
        var kdf_spec = session.kdf_spec;

        // Calculate the derived key and continue
        return new KDF(kdf_spec).promiseKey(secret_key, salt)
          .then(function(hashed_key) {

            // Wipe the secret key
            secret_key.fill(0);

            // Remember the derived key for verification
            derived_key = hashed_key.derived_key;

            // Compute the client_key
            var client_key = crypto.createHmac(hash, derived_key)
                                   .update(shared_key)
                                   .digest();

            // Compute and remember the store key
            store_key = crypto.createHmac(hash, client_key)
                               .update(shared_key)
                               .digest();


            // Compute our stored_key
            var stored_key = crypto.createHash(hash)
                                   .update(client_key)
                                   .digest();

            // Compute the client signature
            var client_signature = crypto.createHmac(hash, stored_key)
                                         .update(auth_message)
                                         .digest();

            // Compute and return the client proof
            var client_proof = xor(client_key, client_signature);

            // Wipe our internal buffers
            client_key.fill(0);
            stored_key.fill(0);
            client_signature.fill(0);

            // Return nonces and proof
            return {
              client_nonce: base64.encode(client_nonce),
              server_nonce: base64.encode(server_nonce),
              client_proof: base64.encode(client_proof)
            }
          })
      })
  }

  function verifyAndReplace(validation, secret) {

    return Promise.resolve()
      .then(function() {

        // Require keys for validation
        if (! store_key) throw new Error('No store key available for verification');

        // Check that we have nonces and proof
        if (! validation.client_nonce) throw new Error('No client nonce available in validation');
        if (! validation.server_nonce) throw new Error('No server nonce available in validation');
        if (! validation.server_proof) throw new Error('No server proof available in validation');
        if (! validation.hash) throw new Error('No hash specified in hash');

        // Validate the client_nonce in the session, server_nonce can be switched
        if (Buffer.compare(client_nonce, base64.decode(validation.client_nonce)) != 0) {
          throw new Error('Client nonces mismatch');
        }

        // Local variables for computation
        var hash = KDF.knownHashes.validate(validation.hash);
        var server_proof = base64.decode(validation.server_proof);
        var server_nonce = base64.decode(validation.server_nonce);
        var auth_message = Buffer.concat([ client_nonce, server_nonce ]);

        // Calculate the "server_key" as stored by the server
        // server_key := HMAC ( salted_password, store_key )
        var server_key = crypto.createHmac(hash, derived_key)
                               .update(store_key)
                               .digest();

        // Verify the "server_proof" with "auth_message"
        var derived_proof = crypto.createHmac(hash, server_key)
                                  .update(auth_message)
                                  .digest();
        if (Buffer.compare(derived_proof, server_proof) != 0) throw new Error('Verification failure');

        // If no password to update, bail!
        if (! secret) return true;

        var result = new Cipher('A256GCM').encrypt(server_key, secret, auth_message);

        result.server_nonce = base64.encode(server_nonce);
        result.client_nonce = base64.encode(client_nonce);

        return result;
      });
  }

  function replace(validation, secret) {
    return verifyAndReplace(validation, secret);
  }

  function verify(validation) {
    return verifyAndReplace(validation);
  }

  // Immutables
  Object.defineProperties(this, {
    'request': { configurable: false, enumerable: true, value: request },
    'respond': { configurable: false, enumerable: true, value: respond },
    'replace': { configurable: false, enumerable: true, value: replace },
    'verify':  { configurable: false, enumerable: true, value: verify  },
  });
}

/* ========================================================================== */
/* MODULE EXPORTS                                                             */
/* ========================================================================== */
exports = module.exports = Client;
