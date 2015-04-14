'use strict';

var KDF = require('key-derivation');
var util = require('util');
var crypto = require('crypto');
var base64 = require('../base64');
var xor = require('./tools').xor;
var randomBase64 = require('./tools').randomBase64;
var normalize = require('./tools').normalize;
var Cipher = require('./Cipher');

/* ========================================================================== */
/* SCRAM SERVER                                                               */
/* ========================================================================== */
function Server(options) {
  options = options || {};

  var nonce_length = Number(options.nonce_length) || 32;
  var secure       = util.isBoolean(options.secure) ? options.secure : false;

  /* ------------------------------------------------------------------------ */
  /* Initiate a SCRAM session                                                 */
  /* ------------------------------------------------------------------------ */

  function initiate(credentials, request) {
    return Promise.resolve(credentials)
      .then(function(credentials) {
        if (!request) throw new Error('No request available');
        if (!credentials) throw new Error('No credentials available');

        // Required from credentials
        if (! credentials.hash) throw new Error('No hash available in credentials');
        if (! credentials.salt) throw new Error('No salt available in credentials');
        if (! credentials.kdf_spec) throw new Error('No kdf_spec available in credentials');
        if (! credentials.shared_key) throw new Error('No shared_key available in credentials');

        // Normalize the basic request
        var session = normalize(request);

        // Add in our session fields
        session.server_nonce = randomBase64(nonce_length, secure),
        session.hash =         credentials.hash,
        session.salt =         credentials.salt,
        session.kdf_spec =     credentials.kdf_spec,
        session.shared_key =   credentials.shared_key

        // Return the session
        return session;
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
/* MODULE EXPORTS                                                             */
/* ========================================================================== */
exports = module.exports = Server;