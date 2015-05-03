'use strict';

const base64 = require('../util/base64');
const hashes = require('../util/hashes');

const log = require('errorlog')('credential store');
const crypto = require('crypto');
const util = require('util');

const DEFAULT_SCRAM_HASH = "SHA-256";
const DEFAULT_PBKDF2_HASH = "SHA-1";
const DEFAULT_SALT_LENGTH = hashes.bytes(DEFAULT_PBKDF2_HASH);
const DEFAULT_KEY_LENGTH = DEFAULT_SALT_LENGTH; // same as above
const DEFAULT_ITERATIONS = 100000;
const MINIMUM_ITERATIONS = 5000;

function Credentials(fetch, store, options) {
  if (!(this instanceof Credentials)) return new Credentials(fetch, store, options);

  if (! util.isFunction(fetch)) throw new TypeError('Parameter "fetch" is not a function');
  if (! util.isFunction(store)) throw new TypeError('Parameter "store" is not a function');

  var scram_hash  = DEFAULT_SCRAM_HASH;
  var pbkdf2_hash = DEFAULT_PBKDF2_HASH;
  var salt_length = DEFAULT_SALT_LENGTH;
  var key_length  = DEFAULT_KEY_LENGTH;
  var iterations  = DEFAULT_ITERATIONS;
  var fake_salt   = null;

  if (options) {
    // Scram hash
    if (options.scram_hash) scram_hash = hashes.normalize(options.scram_hash);

    // PBKDF2 Hash
    if (options.pbkdf2_hash) {
      pbkdf2_hash = hashes.normalize(options.pbkdf2_hash);
      salt_length = key_length = hashes.bytes(pbkdf2_hash);
    }

    // Iterations
    if (options.iterations) iterations = parseInt(options.iterations);
    if (!(iterations >= MINIMUM_ITERATIONS)) // Catch NaN
      throw new TypeError('Invalid iterations ' + iterations + " (min=" + MINIMUM_ITERATIONS + ')');

    // Salt length
    if (options.salt_length) salt_length = parseInt(options.salt_length);
    if (!(salt_length >= hashes.bytes(pbkdf2_hash))) // Catch NaN, too
      throw new TypeError('Unwilling to truncate salts to ' + salt_length + ' bytes (min=' + hashes.bytes(pbkdf2_hash) + ')');

    // Derived key length
    if (options.key_length) key_length = parseInt(options.key_length);
    if (!(key_length >= hashes.bytes(pbkdf2_hash))) // Catch NaN, too
      throw new TypeError('Unwilling to truncate hashes to ' + key_length + ' bytes (min=' + hashes.bytes(pbkdf2_hash) + ')');

    // Fake salt
    if (options.fake_salt) {
      if (util.isString(options.fake_salt)) fake_salt = new Buffer(options.fake_salt, 'utf8');
      else if (util.isBuffer(options.fake_salt)) fake_salt = options.fake_salt;
      else throw new TypeError('Fake salt must be a string or buffer');
    }
  }

  // Randomize fake salt
  if (fake_salt == null) {
    log.warn('Fake salt not specified, using random bytes');
    // TODO: enable console.warn('Fake salt not specified');
    fake_salt = crypto.randomBytes(salt_length);
  }

  // Algorithm for PBKDF2
  var algorithm = hashes.algorithm(pbkdf2_hash);

  // Expose our config what we have
  Object.defineProperties(this, {
    scram_hash:  { enumerable: true, configurable: false, value: scram_hash  },
    pbkdf2_hash: { enumerable: true, configurable: false, value: pbkdf2_hash },
    salt_length: { enumerable: true, configurable: false, value: salt_length },
    key_length:  { enumerable: true, configurable: false, value: key_length  },
    iterations:  { enumerable: true, configurable: false, value: iterations  },
  });

  log.debug('Configured with', this);

  /* ======================================================================== *
   * Fake credentials                                                         *
   * ======================================================================== */

  this.fake = function(identifier) {
    if (! identifier) throw new TypeError('No identifer specified');
    if (! util.isString(identifier)) throw new TypeError('Identifier must be a string');

    // No credentials... Fake it, using PBKDF2 to generate a salt!
    var salt = crypto.pbkdf2Sync(identifier, fake_salt, 1, salt_length, "sha1");

    return {
      kdf_spec: {
        algorithm: 'PBKDF2',
        hash: pbkdf2_hash,
        iterations: iterations,
        derived_key_length: key_length,
      },
      fake: true,
      hash: scram_hash,
      server_key: '',
      stored_key: '',
      salt: base64.encode(salt)
    };
  }

  /* ======================================================================== *
   * Fetch/get credentials                                                    *
   * ======================================================================== */

  this.get = function(identifier) {
    return new Promise(function(resolve, reject) {

      if (! identifier) throw new TypeError('No identifer specified');
      if (! util.isString(identifier)) throw new TypeError('Identifier must be a string');

      resolve(fetch(identifier));
    });

  }

  /* ======================================================================== *
   * Set/store a new password                                                 *
   * ======================================================================== */

  this.set = function(identifier, password) {
    return new Promise(function(resolve, reject) {

      if (! identifier) throw new TypeError('No identifer specified');
      if (! util.isString(identifier)) throw new TypeError('Identifier must be a string');

      if (util.isString(password)) password = new Buffer(password, 'utf8');
      if (! util.isBuffer(password)) throw new TypeError('Password must be a string or buffer');
      if (password.length < 6) throw new TypeError('Corwardly refusing to save short password');

      var salt = crypto.randomBytes(salt_length);
      var buffer = new Buffer(password, 'utf8');

      crypto.pbkdf2(buffer, salt, iterations, key_length, algorithm, function(err, key) {
        if (err) return reject(err);

        try {
          var server_key = hashes.createHmac(scram_hash, key)
                                 .update(new Buffer('Server Key', 'utf8'))
                                 .digest();

          var client_key = hashes.createHmac(scram_hash, key)
                                 .update(new Buffer('Client Key', 'utf8'))
                                 .digest();

          var stored_key = hashes.createHash(scram_hash)
                                 .update(client_key)
                                 .digest();

          /* Credentials */
          var credentials = {
            kdf_spec: {
              algorithm: 'PBKDF2',
              hash: pbkdf2_hash,
              iterations: iterations,
              derived_key_length: key_length
            },
            hash: scram_hash,
            server_key: base64.encode(server_key),
            stored_key: base64.encode(stored_key),
            salt: base64.encode(salt)
          }

          /* Save, then from this callback return resolve the returned promise */
          Promise.resolve(store(identifier, credentials))
            .then(function() {
              resolve(credentials);
            }, reject);

        } catch(error) {
          reject(error);
        }
      });
    });
  }
}

exports = module.exports = Credentials;
