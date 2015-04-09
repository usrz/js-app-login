'use strict';

var Promise = global.Promise || require('promise');
var KDF = require('key-derivation');
var base64 = require('./base64');
var crypto = require('crypto');
var util = require('util');

/* ========================================================================== */

function xor(a, b) {
  if (! util.isBuffer(a)) throw new TypeError('Buffer A is not a buffer');
  if (! util.isBuffer(b)) throw new TypeError('Buffer B is not a buffer');
  if (a.length != b.length) throw new TypeError('Buffer lengths differ');
  var c = new Buffer(a.length);
  for (var i = 0; i < b.length; i++) c[i] = a[i] ^ b[i];
  return c;
}

/* ========================================================================== */
/* SCRAM SERVER                                                               */
/* ========================================================================== */
function Server(options) {
  options = options || {};

  var hash              = KDF.knownHashes.validate(options.hash || 'SHA256');
  var shared_key_length = KDF.knownHashes.digestLength(hash);
  var signing_key       = util.isBuffer(options.signing_key) ? options.signing_key : null;
  var secure            = util.isBoolean(options.secure)     ? options.secure      : false;
  var kdf               = new KDF(options.kdf_spec);

         var nonce_length = 32;


  if (! signing_key) throw new Error('Signing key unavailable');

  /* ------------------------------------------------------------------------ */
  /* Generate SCRAM credentials                                               */
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
      .then(function(hashed_key) {

        // First thing here, let's wipe the secret key
        secret_key.fill(0);

        // Calculate a random shared key
        var random = secure ? crypto.randomBytes : crypto.pseudoRandomBytes;
        var shared_key = random.call(crypto, shared_key_length);

        // Let's start with what we have
        var credentials = {
          hash:       hash,
          kdf_spec:   hashed_key.kdf_spec,
          salt:       base64.encode(hashed_key.salt),
          shared_key: base64.encode(shared_key)
        };

        // Our derived key
        var derived_key = hashed_key.derived_key;

        // client_key := HMAC ( salted_password, shared_key )
        var client_key = crypto.createHmac(hash, derived_key)
                               .update(shared_key)
                               .digest();

        // stored_key := HASH ( client_key )
        var stored_key = crypto.createHash(hash)
                               .update(client_key)
                               .digest();

        // signed_key := HMAC ( salted_password, signing_key )
        var signed_key = crypto.createHmac(hash, derived_key)
                               .update(signing_key)
                               .digest();

        // Remember stored and signed key
        credentials.stored_key = base64.encode(stored_key);
        credentials.signed_key = base64.encode(signed_key);

        // Clean up after ourselfves
        derived_key.fill(0);
        client_key.fill(0);

        // All done
        return credentials;
      })

      // If something above goes wrong, wipe key, do not rescue
      .catch(function(error) {
        if (util.isBuffer(secret_key)) secret_key.fill(0);
        throw error;
      })
  }

  /* ------------------------------------------------------------------------ */
  /* Initiate a SCRAM session                                                 */
  /* ------------------------------------------------------------------------ */

  function initiate(credentials, request) {
    return Promise.resolve(credentials)
      .then(function(credentials) {
        if (!credentials) throw new Error('No credentials available');
        if (!request) throw new Error('No request available');

        // Required from credentials
        if (! credentials.hash) throw new Error('No hash available in credentials');
        if (! credentials.salt) throw new Error('No salt available in credentials');
        if (! credentials.kdf_spec) throw new Error('No kdf_spec available in credentials');
        if (! credentials.shared_key) throw new Error('No shared_key available in credentials');

        // Required from request
        if (! request.client_nonce) throw new Error('No client_nonce available in request');
        var client_nonce = base64.decodeBuffer(request.client_nonce);

        // Generate our server nonce
        var random = secure ? crypto.randomBytes : crypto.pseudoRandomBytes;
        var server_nonce = random.call(crypto, nonce_length);

        // Just wrap what we got
        return {
          hash:       credentials.hash,
          salt:       credentials.salt,
          kdf_spec:   credentials.kdf_spec,
          shared_key: credentials.shared_key,
          server_nonce: base64.encode(server_nonce),
          client_nonce: base64.encode(client_nonce)
        }
      });
  }

  //
  function validate(session, credentials) {

    return Promise.resolve()

      .then(function() {

        // Required from credentials
        if (! credentials.stored_key) throw new Error('No stored_key available in credentials');
        if (! credentials.signed_key) throw new Error('No signed_key available in credentials');
        if (! credentials.hash) throw new Error('No hash available in credentials');

        // Required session parameters
        if (! session.client_nonce) throw new Error('No client_nonce available in session');
        if (! session.server_nonce) throw new Error('No server_nonce available in session');
        if (! session.client_proof) throw new Error('No client_proof available in session');

        // Local variables
        var stored_key = base64.decodeBuffer(credentials.stored_key);
        var signed_key = base64.decodeBuffer(credentials.signed_key);
        var hash = KDF.knownHashes.validate(credentials.hash);

        var client_proof = base64.decodeBuffer(session.client_proof);
        var client_nonce = base64.decodeBuffer(session.client_nonce);
        var server_nonce = base64.decodeBuffer(session.server_nonce);
        var auth_message = Buffer.concat([ client_nonce, server_nonce ]);

        // Server signature
        var server_signature = crypto.createHmac(hash, stored_key)
                                     .update(auth_message)
                                     .digest();

        // Derive client key
        var client_key = xor(client_proof, server_signature);

        // Derive Stored key
        var derived_key = crypto.createHash(hash)
                                .update(client_key)
                                .digest();

        // Compare derived and stored key
        if (Buffer.compare(derived_key, stored_key) != 0) {
          throw new Error("Authentication failure");
        }

        //
        if (signed_key) {
          var server_proof = crypto.createHmac(hash, signed_key)
                                   .update(auth_message)
                                   .digest();
          return { server_proof: server_proof };
        } else {
          return true;
        }

      });


  }



  // Immutables
  Object.defineProperties(this, {
    'generate': { configurable: false, enumerable: true, value: generate },
    'initiate': { configurable: false, enumerable: true, value: initiate },
    'validate': { configurable: false, enumerable: true, value: validate },
  });
}

/* ========================================================================== */
/* SCRAM CLIENT                                                               */
/* ========================================================================== */
function Client() {
  // No configuration options
  var secure = false;
  var nonce_length = 32;

  function request() {
    return Promise.resolve()
      .then(function() {

        // Calculate a random client_nonce
        var random = secure ? crypto.randomBytes : crypto.pseudoRandomBytes;
        var client_nonce = random.call(crypto, nonce_length);

        return { client_nonce: base64.encode(client_nonce) }
      });
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
        if (! session.hash) throw new Error('No salt specified in session');

        // Parameters for SCRAM
        var parameters = {
          hash: KDF.knownHashes.validate(session.hash),
          shared_key: base64.decodeBuffer(session.shared_key),
          client_nonce: base64.decodeBuffer(session.client_nonce),
          server_nonce: base64.decodeBuffer(session.server_nonce)
        };

        // Salt and spec for KDF
        var salt = base64.decodeBuffer(session.salt);
        var kdf_spec = session.kdf_spec;

        // Calculate the derived key and inject it in the params
        return new KDF(kdf_spec).promiseKey(secret_key, salt)
          .then(function(hashed_key) {

            // Wipe the secret key
            secret_key.fill(0);

            // Inject the derived key in our parameters and go
            parameters.derived_key = hashed_key.derived_key;
            return parameters;
          });
      })

      .then(function(parameters) {

        // Local variables
        var hash = parameters.hash;
        var shared_key = parameters.shared_key;
        var derived_key = parameters.derived_key;
        var client_nonce = parameters.client_nonce;
        var server_nonce = parameters.server_nonce;
        var auth_message = Buffer.concat([ client_nonce, server_nonce ]);

        // Compute the client_key
        var client_key = crypto.createHmac(hash, derived_key)
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
  }

  // Immutables
  Object.defineProperties(this, {
    'request': { configurable: false, enumerable: true, value: request },
    'respond': { configurable: false, enumerable: true, value: respond },
  });
}


exports = module.exports = Object.freeze({
  Server: Server,
  Client: Client
});

























