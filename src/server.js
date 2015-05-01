'use strict'


const app = require('express')();
const parser = require('body-parser');
const typeis = require('type-is');
const base64 = require('./util/base64');
const hashes = require('./util/hashes');
const xor = require('./util/xor');
const util = require('util');
const e = require('./util/HttpError');
const ECKey = require('./eckey');

const log = require('errorlog')('login server');

var sessionManager = null;
var credentials = null;
var totp = null;

app.on('mount', function(parent) {
  if (! parent.locals.sessionManager) throw new Error('Application "sessionManager" not in locals');
  if (! parent.locals.credentials) throw new Error('Application "credentials" not in locals');
  sessionManager = parent.locals.sessionManager;
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

// Receive a client first
app.post('/', function(req, res, next) {

  // Validate body
  var body = req.body;
  if (! body) throw e.BadRequest('Missing request body');
  if (! body.client_first) throw e.BadRequest('Missing "client_first"');

  // Parse client first
  var client_first = null;
  try {
    client_first = base64.decode_json(body.client_first);
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
    public_key = new ECKey(client_first.public_key, 'spki-urlsafe');
  } catch (error) {
    throw e.BadRequest('Unable to parse "client_first.public_key"');
  }

  // Create a private key matching the public key curve
  var private_key = ECKey.createECKey(public_key.curve);

  // Get the credentials for the user
  credentials.get(client_first.subject).then(function(cred) {

    // Prepare our server first message
    var server_first = {
      public_key: private_key.toString('spki-urlsafe'),
      kdf_spec: cred.kdf_spec,
      scram_hash: cred.hash,
      require: 'one-time-password'
    };

    // Message ready for session
    var message = {
      client_first: body.client_first,
      server_first: base64.encode(new Buffer(JSON.stringify(server_first), 'utf8'))
    };

    // Nonce, session and verification
    var nonce = private_key.computeSecret(public_key);
    var session = sessionManager.create(nonce, message);

    // Created!
    res.location(req.baseUrl.replace(/\/+$/, '') + '/' + session)
       .status(201)
       .json(message)
       .end();


  })

  .catch(next);

});

// Receive a client final
app.post('/:session', function(req, res, next) {

  // Validate body
  var body = req.body;
  if (! body) throw e.BadRequest('Missing request body');
  if (! body.client_first) throw e.BadRequest('Missing "client_first"');
  if (! body.server_first) throw e.BadRequest('Missing "server_first"');
  if (! body.client_proof) throw e.BadRequest('Missing "client_proof"');

  // Validate session (will throw an error)
  var nonce = sessionManager.validate(req.params.session, body);

  // Parse client first
  var client_first = null;
  try {
    client_first = base64.decode_json(body.client_first);
  } catch (error) {
    throw e.BadRequest('Unable to parse "client_first"');
  }

  // Get the credentials for the user
  credentials.get(client_first.subject).then(function(cred) {

    if (cred.fake) log.debug('Continuing authentication for unknowm subject');

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

    try {
      var stored_key = base64.decode(cred.stored_key);
      var secrets = totp.many('2 min');
      var invalidate = new Array();

      for (var i = 0; i < secrets.length; i ++) {
        var secret = new Buffer(secrets[i], 'utf8');
        invalidate.push(secrets[i]);


        var server_signature = hashes.createHmac(cred.hash, stored_key)
                                     .update(nonce)
                                     .update(base64.decode(body.client_first))
                                     .update(base64.decode(body.server_first))
                                     .update(secret)
                                     .digest();

        var client_key = xor(base64.decode(body.client_proof), server_signature);

        var derived_key = hashes.createHash(cred.hash)
                                .update(client_key)
                                .digest();

        // Check that the stored key is the same as our derivate, if so we're good!
        if (Buffer.compare(stored_key, derived_key) != 0) continue;
        console.log('SERVER SECRET', secrets[i], 'INVALIDATE', invalidate);

        // We're still here? Good, send out our proof!
        var server_proof = hashes.createHmac(cred.hash, base64.decode(cred.server_key))
                                 .update(nonce)
                                 .update(base64.decode(body.client_first))
                                 .update(base64.decode(body.server_first))
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
          server_proof: base64.encode(server_proof)
        };

        return res.status(200).json(message).end();
      }
    } catch (error) {
      next(error);
    }

    // We finished our secrets...
    next(e.Unauthorized());

  });
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


app.use(function(err, req, res, next) {
  console.log('Error1:', err, err.toString());
  console.log('Error2:', JSON.stringify(err));
  res.status(Number(err.status) || 500);
  return res.json(err);
});








/* ========================================================================== */
/* Export our application                                                     */
/* ========================================================================== */

exports = module.exports = app;
