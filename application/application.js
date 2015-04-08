'use strict';

var S = require('express-statuses');
var ms = require('ms');
var crypto = require('crypto');
var base64 = require('base64-url');

var validate = require('validate.js');
validate.validators.base64 = require('./base64validator');

var constraints = {
  sub: {
    presence: true,
  },
  client_nonce: {
    presence: true,
    base64: {
      format: 'urlsafe',
      length: { minimum: 32 }
    }
  }
}

var sessionKey = null;
crypto.randomBytes(32, function(err, buf) {
  if (err) throw err;
  console.log('Session key', buf.toString('hex'));
  sessionKey = buf;
})

exports = module.exports = function login(options) {

  var app = require('express')();
  var parser = require('body-parser');
  var typeis = require('type-is');

  app.set('json spaces', 2);

  app.on('mount', function(parent) {
    console.log('Login application mounted under "' + app.mountpath + '"');
  });

  // Accept only GET and POST, and restrict content type to application/json
  // and application/x-www-form-urlencoded only.
  app.use(function(req, res, next) {
    if (req.method === 'POST') {
      if (typeis(req, [ 'application/x-www-form-urlencoded',
                        'application/json', ])) {
        return next();
      } else {
        return next(S.UNSUPPORTED_MEDIA_TYPE);
      }
    } else if (req.method !== 'GET') {
      return next(S.METHOD_NOT_ALLOWED('foo'));
    } else {
      return next();
    }
  });

  // Parse JSON or Form Data
  app.use(parser.urlencoded({extended: false}));
  app.use(parser.json());

  // Create a session!
  app.post('/', function(req, res, next) {
    console.log('BODY', req.body);
    var result = validate(req.body, constraints);
    if (result != null) return next(S.BAD_REQUEST({details: result}));
    crypto.randomBytes(32, function(err, buffer) {
      // Fail on error
      if (err) return next(S.INTERNAL_SERVER_ERROR({error: err}));

      // Add our server nonce
      req.body.server_nonce = base64.escape(buffer.toString('base64'));

      // Calculate our expiry date
      var expires = new Date().getTime() + ms('5m');
      var expiresBuffer = new Buffer(8);
      expiresBuffer.writeUIntBE(expires, 0, 8);

      console.log('EXPIRES', new Date(expires), expiresBuffer);

      var hmac = crypto.createHmac('sha256', sessionKey);
      hmac.update(new Buffer(req.body.sub, 'utf8'));
      hmac.update(new Buffer(req.body.client_nonce, 'base64'));
      hmac.update(new Buffer(req.body.server_nonce, 'base64'));
      hmac.update(expiresBuffer);
      var digest = hmac.digest();

      var session = new Buffer(digest.length + 8);
      expiresBuffer.copy(session);
      digest.copy(session, 8)

      req.body.session = base64.escape(session.toString('base64'));



      //console.log('SESSION', session + "." + expiresBuffer.toString('hex'));


      res.status(201)
         .header('Expires', new Date(expires).toUTCString())
         .header('Location', req.originalUrl + req.body.session)
         .send(req.body);
    });

  });

  app.use(function(err, req, res, next) {
    res.status(Number(err.status) || 500);
    return res.json(err);
  });

  return app;
};
