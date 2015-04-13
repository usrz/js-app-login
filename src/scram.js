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
 * - Replace "Client Key" (string) with SharedKey (random)                    *
 * - Replace "Server Key" (string) with HMAC(ClientKey, SharedKey)            *
 * - Rename ServerSignature with ServerProof                                  *
 * ========================================================================== */

var Promise = global.Promise || require('promise');
var KDF = require('key-derivation');
var Cipher = require('./cipher');
var base64 = require('./base64');
var crypto = require('crypto');
var util = require('util');
var ursa = require('ursa');

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
/* SCRAM STORE                                                                */
/* ========================================================================== */
function Store(options) {
  options = options || {};

  var hash        = KDF.knownHashes.validate(options.hash || 'SHA256');
  var hash_length = KDF.knownHashes.digestLength(hash);
  var secure      = util.isBoolean(options.secure)   ? options.secure    : false;
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
      .then(function(hashed_key) {

        // First thing here, let's wipe the secret key
        secret_key.fill(0);

        // Calculate a random shared key
        var random = secure ? crypto.randomBytes : crypto.pseudoRandomBytes;
        var shared_key = random.call(crypto, hash_length);

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

        var store_key = crypto.createHmac(hash, client_key)
                               .update(shared_key)
                               .digest();

        // server_key := HMAC ( salted_password, store_key )
        var server_key = crypto.createHmac(hash, derived_key)
                               .update(store_key)
                               .digest();

        // Remember stored and signed key
        credentials.stored_key = base64.encode(stored_key);
        credentials.server_key = base64.encode(server_key);

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

  // Immutables
  Object.defineProperties(this, {
    'generate': { configurable: false, enumerable: true, value: generate }
  });
}


/* ========================================================================== */
/* SCRAM SERVER                                                               */
/* ========================================================================== */
function Server(options) {
  options = options || {};

  var nonce_length = Number(options.nonce_length) || 32;
  var secure       = util.isBoolean(options.secure) ? options.secure : false;

  if (! options.private_key) throw new Error('Signing key unavailable');
  var private_key = ursa.coercePrivateKey(options.private_key);

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
        var client_nonce = base64.decode(request.client_nonce);

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

  /* ------------------------------------------------------------------------ */
  /* Validate a SCRAM response                                                */
  /* ------------------------------------------------------------------------ */
  function validate(credentials, response) {

    return Promise.resolve()

      .then(function() {

        // Required from credentials
        if (! credentials.stored_key) throw new Error('No stored_key available in credentials');
        if (! credentials.server_key) throw new Error('No server_key available in credentials');
        if (! credentials.hash) throw new Error('No hash available in credentials');

        // Required response parameters
        if (! response.client_nonce) throw new Error('No client_nonce available in response');
        if (! response.server_nonce) throw new Error('No server_nonce available in response');
        if (! response.client_proof) throw new Error('No client_proof available in response');

        // Local variables
        var stored_key = base64.decode(credentials.stored_key);
        var server_key = base64.decode(credentials.server_key);
        var hash = KDF.knownHashes.validate(credentials.hash);

        var client_proof = base64.decode(response.client_proof);
        var client_nonce = base64.decode(response.client_nonce);
        var server_nonce = base64.decode(response.server_nonce);
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

        // Sign our "server_key" and "auth_message"
        var server_proof = crypto.createHmac(hash, server_key)
                                 .update(auth_message)
                                 .digest();
        // var signer = ursa.createSigner(hash)
        // signer.update(server_key);
        // signer.update(auth_message);
        // var server_proof = signer.sign(private_key);

        // Return our server proof
        return {
          hash: hash,
          client_nonce: response.client_nonce,
          server_nonce: response.server_nonce,
          server_proof: base64.encode(server_proof)
        };
      });
  }

  /* ------------------------------------------------------------------------ */
  /* Replace the SCRAM secret                                                 */
  /* ------------------------------------------------------------------------ */
  function update(credentials, replacement) {

    // Required replacement parameters
    if (! replacement.client_nonce) throw new Error('No client_nonce available in replacement');
    if (! replacement.server_nonce) throw new Error('No server_nonce available in replacement');


    var client_nonce = base64.decode(replacement.client_nonce);
    var server_nonce = base64.decode(replacement.server_nonce);
    var auth_message = Buffer.concat([ client_nonce, server_nonce ]);

    /// WRONG !!!! SIGNED KEY IS
    var server_key = base64.decode(credentials.server_key);

    var decrypted = new Cipher('A256GCM').decrypt(server_key, replacement, auth_message);

    return decrypted;

  }

  // Immutables
  Object.defineProperties(this, {
    'initiate': { configurable: false, enumerable: true, value: initiate },
    'validate': { configurable: false, enumerable: true, value: validate },
    'update':   { configurable: false, enumerable: true, value: update   },
  });
}

/* ========================================================================== */
/* SCRAM CLIENT                                                               */
/* ========================================================================== */
function Client(options) {
  options = options || {};

  // Calculate a random client_nonce
  var nonce_length = Number(options.nonce_length) || 32;
  var secure       = util.isBoolean(options.secure) ? options.secure : false;
  var random       = secure ? crypto.randomBytes : crypto.pseudoRandomBytes;
  var client_nonce = random.call(crypto, nonce_length);

  var public_key = options.public_key && ursa.coercePublicKey(options.public_key);

  // Our derived key and auth message for validation
  var derived_key = null;
  var store_key = null;

  function request() {
    return Promise.resolve(client_nonce)
      .then(function() {
        return {
          // TODO
          subject: 'subject',
          audience: ['foo', 'bar', 'baz' ],
          client_nonce: base64.encode(client_nonce)
        }
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
        if (! public_key) throw new Error('No public key available for verification');
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

        // TODO TODO TODO
        // var verifier = ursa.createVerifier(hash)
        // verifier.update(server_key);
        // verifier.update(auth_message);

        // // Verify the signature and fail if wrong
        // var result = verifier.verify(public_key, server_proof);
        // if (result !== true) throw new Error('Verification failure');

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


exports = module.exports = Object.freeze({
  Store:  Store,
  Server: Server,
  Client: Client
});

























