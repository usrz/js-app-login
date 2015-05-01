'use strict';

const Token = require('./index.js');

function TOTP(fetch, store) {
  if (!(this instanceof Credentials)) return new Credentials(fetch, store, options);

  if (! util.isFunction(fetch)) throw new TypeError('Parameter "fetch" is not a function');
  if (! util.isFunction(store)) throw new TypeError('Parameter "store" is not a function');

  /* ======================================================================== *
   * Fetch/get a token                                                        *
   * ======================================================================== */
  this.get = function(identifier) {
    if (! identifier) throw new TypeError('No identifer specified');
    if (! util.isString(identifier)) throw new TypeError('Identifier must be a string');

    var token = fetch(identifier);

  };

  /* ======================================================================== *
   * Set/store a new token                                                    *
   * ======================================================================== */
  this.set = function(identifier, options) {
    if (! identifier) throw new TypeError('No identifer specified');
    if (! util.isString(identifier)) throw new TypeError('Identifier must be a string');

    if (! options) options = {}
    if (! util.isObject(options)) throw new TypeError('Token options not an object');
    if (! options.label) options.label = identifier;


  };

};

TOTP.Token = Token;
exports = module.exports = TOTP;
