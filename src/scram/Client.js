'use strict';

var KDF = require('key-derivation');
var base64 = require('../base64');
var crypto = require('crypto');
var util = require('util');

var Cipher = require('./Cipher');

var xor = require('./tools').xor;
var normalize = require('./tools').normalize;
var flatten = require('./tools').flatten;
var randomBuffer = require('./tools').randomBuffer;

/* ========================================================================== */
/* SCRAM CLIENT                                                               */
/* ========================================================================== */
function Client(options) {
  options = options || {};

  // Calculate an initial random client_nonce
  var nonce_length = Number(options.nonce_length) || 32;
  var secure       = util.isBoolean(options.secure) ? options.secure : false;

  // Our derived key and auth message for validation
  var client_nonce = null;
  var derived_key = null;
  var store_key = null;
  var hash = null;
  var ecdh = null;

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

        // Required parameters from the session
        if (! session.server_nonce) throw new Error('No server_nonce available in session');
        if (! session.shared_key) throw new Error('No shared_key available in session');
        if (! session.kdf_spec) throw new Error('No kdf_spec specified in session');
        if (! session.salt) throw new Error('No salt specified in session');
        if (! session.hash) throw new Error('No hash specified in session');

        // Salt and spec for KDF
        var salt = base64.decode(session.salt);
        var kdf_spec = session.kdf_spec;

        // Calculate the derived key and continue
        return new KDF(kdf_spec).promiseKey(secret_key, salt)
          .then(function(hashed_key) {

            // First of all, wipe the secret key
            secret_key.fill(0);

            // Start with a new response
            var response = normalize(session);

            // Parameters for SCRAM from the session
            hash = KDF.knownHashes.validate(session.hash);
            var shared_key = base64.decode(session.shared_key);
            var server_nonce = base64.decode(session.server_nonce);

            // Compute and remember the client nonce, then auth message
            client_nonce = randomBuffer(nonce_length, secure);
            var auth_message = Buffer.concat([ client_nonce, server_nonce ]);

            // Remember the derived key for verification
            derived_key = hashed_key.derived_key;

            // Compute the client_key
            var client_key = crypto.createHmac(hash, derived_key)
                                   .update(shared_key)
                                   .digest();

            // Compute and remember the store key // TODO find better name!!!
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

            // Create a new ECDH
            ecdh = crypto.createECDH('prime256v1');
            ecdh.generateKeys();

            // Instrument our response
            response.client_nonce = base64.encode(client_nonce);
            response.server_nonce = base64.encode(server_nonce);
            response.client_proof = base64.encode(client_proof);

            response.ecdh_session = {
              public_key: base64.encode(ecdh.getPublicKey()),
              curven_name: 'p-256',
            }

            // Wipe our internal buffers
            client_key.fill(0);
            stored_key.fill(0);
            shared_key.fill(0);
            server_nonce.fill(0);
            auth_message.fill(0);
            client_proof.fill(0);
            client_signature.fill(0);

            // Return nonces and proof
            return response;
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

        // Validate the client_nonce in the session, server_nonce can be switched
        if (Buffer.compare(client_nonce, base64.decode(validation.client_nonce)) != 0) {
          throw new Error('Client nonces mismatch');
        }

        // Local variables for computation
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
        if (Buffer.compare(derived_proof, server_proof) != 0) {
          throw new Error('Verification failure');
        }

        var shared_secret = ecdh.computeSecret(base64.decode(validation.ecdh_session.public_key));
        console.log('SHARED SECRET CLIENT', shared_secret.toString('hex'));

        // If no password to update, bail!
        if (! secret) return true;

        // Replace the client proof and authentication message
        client_nonce = randomBuffer(nonce_length, secure);
        auth_message = Buffer.concat([ client_nonce, server_nonce ]);

        // Compute the result
        var result = new Cipher('A256GCM').encrypt(shared_secret, secret, auth_message);

        result.server_nonce = base64.encode(server_nonce);
        result.client_nonce = base64.encode(client_nonce);

        // TODO wipe buffers

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
