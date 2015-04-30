'use strict'


const app = require('express')();
const parser = require('body-parser');
const typeis = require('type-is');
const base64 = require('./util/base64');
const util = require('util');
const e = require('./errors');
const ECKey = require('./eckey');

var sessionManager = null;
app.on('mount', function(parent) {
  if (! parent.locals.sessionManager) throw new Error('Application "sessionManager" not in locals');
  sessionManager = parent.locals.sessionManager;

  console.log('Login application mounted under "' + app.mountpath + '"');
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
    client_first = JSON.parse(base64.decode(body.client_first));
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

  // Prepare our server first message
  var server_first = {
    public_key: private_key.toString('spki-urlsafe')
  }

  // Message ready for session
  var message = {
    client_first: body.client_first,
    server_first: base64.encode(new Buffer(JSON.stringify(server_first), 'utf8'))
  };

  // Nonce, session and verification
  var nonce = private_key.computeSecret(public_key);
  var session = sessionManager.create(nonce, message);
  if (Buffer.compare(nonce, sessionManager.validate(session, message)) != 0) {
    throw e.InternalServerError(); // just triple check
  }

  console.log("SESSION", session);
  console.log("NONXX", nonce);

  // Created!
  return res.location(req.baseUrl.replace(/\/+$/, '') + '/' + session)
            .status(201)
            .json(message);
});

// Receive a client final
app.post('/:session', function(req, res, next) {

  // Validate body
  var body = req.body;
  if (! body) throw e.BadRequest('Missing request body');
  if (! body.client_first) throw e.BadRequest('Missing "client_first"');
  if (! body.server_first) throw e.BadRequest('Missing "server_first"');
  if (! body.client_final) throw e.BadRequest('Missing "client_final"');

  // Validate session
  var nonce = sessionManager.validate(req.params.session, body);

  console.log("NONCE", nonce);

  return res.status(200).json({});
});






// Error handling
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
