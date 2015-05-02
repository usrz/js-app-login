'use strict';

const Token = require('./Token');
const util = require('util');

function TOTP(fetch, store) {
  if (!(this instanceof TOTP)) return new TOTP(fetch, store);

  if (! util.isFunction(fetch)) throw new TypeError('Parameter "fetch" is not a function');
  if (! util.isFunction(store)) throw new TypeError('Parameter "store" is not a function');

  /* ======================================================================== *
   * Fetch/get a token                                                        *
   * ======================================================================== */
  this.get = function(identifier) {
    return new Promise(function(resolve, reject) {

      if (! identifier) throw new TypeError('No identifer specified');
      if (! util.isString(identifier)) throw new TypeError('Identifier must be a string');

      Promise.resolve(fetch(identifier))
        .then(function(token) {
          if (! token) resolve(null);
          if (token instanceof Token) resolve(token);
          resolve(new Token(token));
        }, reject);
    });
  };

  /* ======================================================================== *
   * Set/store a new token                                                    *
   * ======================================================================== */
  this.set = function(identifier, options) {
    return new Promise(function(resolve, reject) {

      if (! identifier) throw new TypeError('No identifer specified');
      if (! util.isString(identifier)) throw new TypeError('Identifier must be a string');

      if (! options) options = {}
      if (! util.isObject(options)) throw new TypeError('Token options not an object');
      if (! options.label) options.label = identifier;

      var token = new Token(options);

      Promise.resolve(store(identifier, token))
        .then(function() {
          resolve(token);
        }, reject);
    });
  };

};

TOTP.Token = Token;
exports = module.exports = TOTP;
