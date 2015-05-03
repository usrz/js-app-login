'use strict';

const Promise = global.Promise || require('promise');
const request = require('request');
const crypto = require('crypto');
const log = require('errorlog')('login client');

const hashes = require('./util/hashes');
const xor = require('./util/xor');
const ECKey = require('./eckey');
const util = require('util');
const url = require('url');

const CURVE = "P-521";

const SERVER_KEY = new Buffer('Server Key', 'utf8');
const CLIENT_KEY = new Buffer('Client Key', 'utf8');

function Client(login_url, curve) {
  if (!(this instanceof Client)) return new Client(login_url, curve);

  if (! login_url) throw new TypeError('No login URL specified');
  if (! util.isString(login_url)) throw new TypeError('Login URL must be a string');

  // Normalize curve
  if (! curve) curve = CURVE;

  // Initial client data
  var self = this;
  var private_key = ECKey.createECKey(curve);

  var nonce = null;
  var session_url = null;

  var salt = null;
  var pbkdf2_hash = null;
  var iterations = null;
  var derived_key_length = null;
  var hash_length = null;

  var scram_hash = null;
  var requirements = null;

  var client_first = null;
  var client_first_buffer = null;
  var server_first = null;
  var server_first_buffer = null;

  /* ======================================================================== *
   * Client First                                                             *
   * ======================================================================== */
  this.clientFirst = function clientFirst(subject) {

    return new Promise(function(resolve, reject) {
      if (requirements) throw new Error('Client first already completed');

      if (! subject) throw new TypeError('No subject specified');
      if (! util.isString(subject)) throw new TypeError('Subject must be a string');

      var decoded = {
        public_key: private_key.toString('spki'),
        subject: subject
      };

      client_first_buffer = new Buffer(JSON.stringify(decoded), 'utf8');
      client_first = client_first_buffer.toString('base64');

      var message = {
        url: login_url,
        method: 'POST',
        json: true,
        body: { client_first: client_first }
      }

      // Debugging data
      log.debug('>>> POST %s: %j', login_url, client_first, decoded);

      request(message, function(err, res, body) {
        if (err) return reject(err);

        try {
          if (res.statusCode != 201) throw new Error('Invalid server status ' + res.statusCode);

          // Discover/resolve location
          var location = res.headers.location;
          if (! location) throw new Error('Unable to determine session location');
          session_url = url.resolve(login_url, location);

          // Validate client first/server first
          if (client_first != body.client_first) throw new Error('Unable to validate client_first');
          if (! body.server_first) throw new Error('Server did not issue a server_first');

          // Decode server first
          server_first = body.server_first;
          server_first_buffer = new Buffer(server_first, 'base64');
          var decoded = JSON.parse(server_first_buffer.toString('utf8'));

          // Debugging data
          log.debug('<<< POST %s: %j', login_url, server_first, decoded);

          // Get the server's ECDHE key and calculate the nonce
          if (! decoded.public_key) throw new Error('Server did not issue a public key');
          var public_key = new ECKey(decoded.public_key, 'spki');
          nonce = private_key.computeSecret(public_key);

          // Get the server's SCRAM HASH
          if (! decoded.scram_hash) throw new Error('Server did not issue a scram hash');
          if (! hashes.validate(decoded.scram_hash)) throw new Error('Invalid scram hash ' + decoded.scram_hash);
          scram_hash = hashes.normalize(decoded.scram_hash);

          // Validate salt
          if (! util.isString(decoded.scram_salt)) throw new Error('Server did not issue a salt');
          salt = new Buffer(decoded.scram_salt, 'base64');

          // Get the server's specified "kdf spec"
          if (! decoded.kdf_spec) throw new Error('Server did not issue a KDF specification');
          var kdf_spec = decoded.kdf_spec;

          // Validate the KDF specification
          if (kdf_spec.algorithm != 'PBKDF2') throw new Error('KDF specification is not for PBKDF2');

          // Parameters for KDF2
          pbkdf2_hash = hashes.normalize(kdf_spec.hash);
          iterations = Number(kdf_spec.iterations);
          derived_key_length = Number(kdf_spec.derived_key_length);
          hash_length = hashes.bytes(pbkdf2_hash);

          // Server requirements for the shared secret
          if (!decoded.require) throw new Error('Server did not specify requirements');
          requirements = decoded.require;
          return resolve(requirements);

        } catch (error) {
          reject(error);
        }
      }).on('error', reject);
    })
  }

  /* ======================================================================== *
   * Client Proof                                                             *
   * ======================================================================== */

  this.clientProof = function(password, secret) {
    return new Promise(function(resolve, reject) {
      if (! requirements) throw new Error('Client first was not successful');

      if (! password) throw new TypeError('No password specified');
      if (! util.isString(password)) throw new TypeError('Password must be a string');
      password = new Buffer(password, 'utf8');

      if (! secret) throw new TypeError('No secret specified');
      if (util.isString(secret)) secret = new Buffer(secret, 'utf8');
      if (! util.isBuffer(secret)) throw new TypeError('Secret must be a utf 8 string or buffer');

      if (! util.isBuffer(salt)) throw new Error('Salt never decoded');
      if (!(salt.length >= hash_length)) throw new Error('Refusing to generate key with short (' + salt_length + ' bytes) salt');
      if (!(derived_key_length >= hash_length)) throw new Error('Refusing to generate short (' + salt_length + ' bytes) key');
      if (!(iterations >= 10000)) throw new Error('Refusing to honor low (' + kdf_spec.iterations + ')  iterations');

      var hash = hashes.algorithm(pbkdf2_hash);

      crypto.pbkdf2(password, salt, iterations, derived_key_length, hash, function(err, key) {
        if (err) return reject(err);

        try {
          /* ================================================================ *
           * SaltedPassword  := Hi(Normalize(password), salt, i)              *
           *                                                                  *
           * ClientKey       := HMAC(SaltedPassword, "Client Key")            *
           * StoredKey       := H(ClientKey)                                  *
           * ServerKey       := HMAC(SaltedPassword, "Server Key")            *
           *                                                                  *
           * AuthMessage     := client-first-message-bare + "," +             *
           *                    server-first-message + "," +                  *
           *                    client-final-message-without-proof            *
           *                                                                  *
           * ClientSignature := HMAC(StoredKey, AuthMessage)                  *
           * ClientProof     := ClientKey XOR ClientSignature                 *
           *                                                                  *
           * ServerProof     := HMAC(ServerKey, AuthMessage)                  *
           * ================================================================ */

          var auth_message = Buffer.concat([ nonce,
                                             client_first_buffer,
                                             server_first_buffer,
                                             secret ]);

          var client_key = hashes.createHmac(scram_hash, key)
                                 .update(CLIENT_KEY)
                                 .digest();

          var stored_key = hashes.createHash(scram_hash)
                                 .update(client_key)
                                 .digest();

          var client_signature = hashes.createHmac(scram_hash, stored_key)
                                       .update(auth_message)
                                       .digest();

          var client_proof = xor(client_key, client_signature).toString('base64');

          var message = {
            url: session_url,
            method: 'POST',
            json: true,
            body: {
              client_first: client_first,
              server_first: server_first,
              client_proof: client_proof
            }
          }

          // Debugging data
          log.debug('>>> POST %s: %s', session_url, client_proof);

          request(message, function(err, res, body) {
            if (err) return reject(err);

            try {
              if (res.statusCode == 401) throw new Error('Authentication failed');
              if (res.statusCode != 200) throw new Error('Invalid status code ' + res.statusCode);

              // Validate client first/server first
              if (client_first != body.client_first) throw new Error('Unable to validate client_first');
              if (server_first != body.server_first) throw new Error('Unable to validate client_first');
              if (! body.server_proof) throw new Error('Server did not issue a server_proof');

              log.debug('<<< POST %s: %s', session_url, server_proof);

              var server_key = hashes.createHmac(scram_hash, key)
                                     .update(SERVER_KEY)
                                     .digest();

              var server_proof = hashes.createHmac(scram_hash, server_key)
                                       .update(auth_message)
                                       .digest();

              if (Buffer.compare(server_proof, new Buffer(body.server_proof, 'base64')) != 0) {
                reject(new Error('Failed to validate server proof'));
              }

              var encryption_key = hashes.createHash(scram_hash)
                                         .update(nonce)
                                         .update(client_key)
                                         .update(secret)
                                         .digest()

              // Return our encryption key (TODO: token)
              return resolve(encryption_key);

            } catch (error) {
              reject(error);
            }
          });

        } catch(error) {
          reject(error);
        }

      });


    });
  }
}


exports = module.exports = Client;
