'use strict'

const util = require('util');

const log = require('errorlog')('login server');
const app = require('express')();

const parser = require('body-parser');
const typeis = require('type-is');

const e = require('./util/HttpError');
const hashes = require('./util/hashes');
const xor = require('./util/xor');
const ECKey = require('./eckey');

var serverSessions = null;
var credentials = null;
var totp = null;

app.on('mount', function(parent) {
  if (! parent.locals.serverSessions) throw new Error('Application "serverSessions" not in locals');
  if (! parent.locals.credentials) throw new Error('Application "credentials" not in locals');
  if (! parent.locals.totp) throw new Error('Application "totp" not in locals');

  serverSessions = parent.locals.serverSessions;
  credentials = parent.locals.credentials;
  totp = parent.locals.totp;

  log.info('Mounted under "' + app.mountpath + '"');
});

// Accept only POST, restrict content type to application/json
// and application/x-www-form-urlencoded only.
app.use(function(req, res, next) {
  if (req.method != 'POST') throw new e.MethodNotAllowed();
  if (typeis(req, [ 'application/x-www-form-urlencoded',
                    'application/json', ])) return next();
  throw new e.UnsupportedMediaType();
});

// Parse JSON or Form Data
app.use(parser.urlencoded({extended: false}));
app.use(parser.json());

/* ========================================================================== *
 * INITIATE AUTHENTICATION SESSION                                            *
 * ========================================================================== */

app.post('/', function(req, res, next) {

  // Validate body
  var body = req.body;
  if (! body) throw e.BadRequest('Missing request body');
  if (! body.client_first) throw e.BadRequest('Missing "client_first"');

  // Parse client first
  var client_first = null;
  var client_first_buffer = null;
  try {
    client_first_buffer = new Buffer(body.client_first, 'base64');
    client_first = JSON.parse(client_first_buffer.toString('utf8'));
  } catch (error) {
    throw e.BadRequest('Unable to parse "client_first"');
  }

  // Validate client first
  if (! client_first.subject) throw e.BadRequest('No "client_first.subject" found');
  if (! client_first.public_key) throw e.BadRequest('No "client_first.public_key" found');
  if (! util.isString(client_first.subject)) throw e.BadRequest('Invalid "client_first.subject"');
  if (! util.isString(client_first.public_key)) throw e.BadRequest('Invalid "client_first.public_key"');

  // Parse the public key
  var public_key = null;
  try {
    public_key = new ECKey(client_first.public_key, 'spki');
  } catch (error) {
    throw e.BadRequest('Unable to parse "client_first.public_key"');
  }

  // Create a private key matching the public key curve
  var private_key = ECKey.createECKey(public_key.curve);

  // Get the credentials for the user
  credentials.get(client_first.subject).then(function(cred) {
    try {
      if (! cred) {
        log.debug('Continuing authentication for unknown user %s', client_first.subject);
        cred = credentials.fake(client_first.subject);
      }

      // Prepare our server first message
      var server_first = {
        public_key: private_key.toString('spki'),
        kdf_spec: cred.kdf_spec,
        scram_hash: cred.hash,
        scram_salt: cred.salt.toString('base64'),
        require: 'one-time-password'
      };

      // As a buffer
      var server_first_buffer = new Buffer(JSON.stringify(server_first), 'utf8');

      // Message ready for session
      var message = {
        client_first: body.client_first,
        server_first: server_first_buffer.toString('base64')
      };

      // Nonce, session and verification
      var nonce = private_key.computeSecret(public_key);
      var session = serverSessions.create(nonce, client_first_buffer, server_first_buffer);

      // Created!
      res.location(req.baseUrl.replace(/\/+$/, '') + '/' + session)
         .status(201)
         .json(message)
         .end();

    } catch (error) {
      next(error);
    }
  })

  .catch(next);

});

/* ========================================================================== *
 * VALIDATE AUTHENTICATION SESSION                                            *
 * ========================================================================== */

app.post('/:session', function(req, res, next) {

  // Validate body
  var body = req.body;
  if (! body) throw e.BadRequest('Missing request body');
  if (! body.client_first) throw e.BadRequest('Missing "client_first"');
  if (! body.server_first) throw e.BadRequest('Missing "server_first"');
  if (! body.client_proof) throw e.BadRequest('Missing "client_proof"');

  var client_first_buffer = new Buffer(body.client_first, 'base64');
  var server_first_buffer = new Buffer(body.server_first, 'base64');

  // Validate session (will throw an error)
  var nonce = serverSessions.validate(req.params.session, client_first_buffer, server_first_buffer);

  // Parse client first
  var client_first = null;
  try {
    client_first = JSON.parse(client_first_buffer.toString('utf8'));
  } catch (error) {
    throw e.BadRequest('Unable to parse "client_first"');
  }

  // Get the credentials and token for the user
  var cred = null;

  credentials.get(client_first.subject)
    .then(function(c) {
      if (! (cred = c)) throw e.Unauthorized();
      return totp.get(client_first.subject)
    })

    .then(function(token) {
      if (! token) throw e.Unauthorized();
      return token.many('2 min');
    })

    .then(function(secrets) {

      /* ================================================================ *
       * AuthMessage     := client-first-message-bare + "," +             *
       *                    server-first-message + "," +                  *
       *                    client-final-message-without-proof            *
       *                                                                  *
       * ServerSignature := HMAC(StoredKey, AuthMessage)                  *
       * ClientKey       := ClientProof XOR ServerSignature               *
       *                                                                  *
       * DerivedKey      := HASH(ClientKey)                               *
       * ServerProof     := HMAC(ServerKey, AuthMessage)                  *
       * ================================================================ */

      var invalidate = new Array();

      for (var i = 0; i < secrets.length; i ++) {
        var secret = new Buffer(secrets[i], 'utf8');
        invalidate.push(secrets[i]);

        var server_signature = hashes.createHmac(cred.hash, cred.stored_key)
                                     .update(nonce)
                                     .update(client_first_buffer)
                                     .update(server_first_buffer)
                                     .update(secret)
                                     .digest();

        var client_proof = new Buffer(body.client_proof, 'base64');
        var client_key = xor(client_proof, server_signature);

        var derived_key = hashes.createHash(cred.hash)
                                .update(client_key)
                                .digest();

        // Check that the stored key is the same as our derivate, if so we're good!
        if (Buffer.compare(cred.stored_key, derived_key) != 0) continue;
        // TODO console.log('SERVER SECRET', secrets[i], 'INVALIDATE', invalidate);

        // We're still here? Good, send out our proof!
        var server_proof = hashes.createHmac(cred.hash, cred.server_key)
                                 .update(nonce)
                                 .update(client_first_buffer)
                                 .update(server_first_buffer)
                                 .update(secret)
                                 .digest();

        var encryption_key = hashes.createHash(cred.hash)
                                   .update(nonce)
                                   .update(client_key)
                                   .update(secret)
                                   .digest()

        // Send out our server final
        var message = {
          client_first: body.client_first,
          server_first: body.server_first,
          server_proof: server_proof.toString('base64')
        };

        return res.status(200).json(message).end();
      }

      // We finished our secrets...
      throw new e.Unauthorized();
    })
    .catch(next);

});




// Error handling
app.use(function(error, req, res, next) {
  if (error instanceof e.HttpError) {
    if (error.status == 401) log.debug('Authentication failure', error);
    else if (error.status == 405) log.debug('Bad client method', error);
    else if (error.status == 400) log.info('Bad client request', error);
    else log.warn('Login error', error);
  } else {
    log.error('Uncaught exception', error);
    error = e.InternalServerError("Internal Server Error", error);
  }

  /* This is an HTTP error */
  return res.status(error.status)
            .json(error)
            .end();
});

/* ========================================================================== */
/* Export our application                                                     */
/* ========================================================================== */

exports = module.exports = app;
