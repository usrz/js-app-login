'use strict';

const Token = require('./Token');

function TOTP(fetch, store) {
  if (!(this instanceof Credentials)) return new Credentials(fetch, store, options);

  if (! util.isFunction(fetch)) throw new TypeError('Parameter "fetch" is not a function');
  if (! util.isFunction(store)) throw new TypeError('Parameter "store" is not a function');

  /* ======================================================================== *
   * Fetch/get a token                                                        *
   * ======================================================================== */
  this.get = function(identifier) {
    return new Promise(function(resolve, reject) {

      if (! identifier) throw new TypeError('No identifer specified');
      if (! util.isString(identifier)) throw new TypeError('Identifier must be a string');

      Promise.resolve(fetch(identifier)).then(function(token) {
        return token ? new Token(token) : null;
      });
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
      Promise.resolve(store(identifier, token)).then(function(result) {
        return (result || token);
      });
    });
  };

};

TOTP.Token = Token;
exports = module.exports = TOTP;
