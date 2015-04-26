'use strict';

var util = require('util');
var ECKey = require('../eckey');

const CURVE = "P-256";

function Client(curve) {
  if (!(this instanceof Client)) return new Client();

  // Create a public key for ECDSA
  if (! curve) curve = CURVE;
  var public_key = ECKey.createECKey(CURVE);

  /* Create a "client_first" message */
  this.clientFirst = function(subject, extra) {
    if (! subject) throw new TypeError("Subject not specified");
    if (! util.isString(subject)) throw new TypeError("Subject must be a string");

    /* Prepare our message */
    var message = {
      public_key: public_key.toString('spki-urlsafe'),
      subject: subject
    };

    /* Add any extra key */
    if (extra) Object.keys(extra).forEach(function(key) {
      message[key] = extra[key];
    });

    /* Return our message */
    return message;
  }
}


exports = module.exports = Client;
