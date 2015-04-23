'use strict';

const HASH = "SHA256";
const CURVE = "P-256";
const NONCE_LENGTH = 32;

var util = require('util');
var crypto = require('crypto');
var base64 = require('../base64');
var ECKey = require('../eckey');


function sign(buffer, eckey, key) {
  if (util.isObject(buffer)) buffer = new Buffer(JSON.stringify(buffer), 'utf8');
  if (! util.isBuffer(buffer)) throw new TypeError("Need an object or buffer to sign");

  var signature = eckey.createSign(HASH)
                       .update(buffer)
                       .sign();

  return {
    msg: base64.encode(buffer),
    sig: base64.encode(signature)
  }
}


function Client(eckey) {
  if (!(this instanceof Client)) return new Client(ecdsa);

  var ecdsa, ecdhe;

  /* Validate (optional) EC Key used for signature */
  if (eckey) {
    if (eckey instanceof ECKey) ecdsa = eckey;
    else throw new TypeError("Argument not an instance of ECKey");
  } else {
    ecdsa = ECKey.createECKey(CURVE);
  }

  /* Generate ephemeral EC Key used for deriving a shared secret */
  ecdhe = ECKey.createECKey(CURVE);

  /* Create a "client_first" message */
  this.clientFirst = function(subject, service) {
    if (! subject) throw new TypeError("Subject not specified");
    if (! util.isString(subject)) throw new TypeError("Subject must be a string");

    var message = {
      nonce: base64.encode(crypto.randomBytes(32)),
      ecdhe: ecdhe.toString('spki-urlsafe'),
      ecdsa: ecdsa.toString('spki-urlsafe'),
      subject: subject
    };

    if (service) {
      if (util.isString(service)) message.service = service;
      else throw new TypeError("Service must be a string");
    }

    return sign(message, ecdsa, "msg");
  }
}


exports = module.exports = Client;
