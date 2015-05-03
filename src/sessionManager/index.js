'use strict';

const TokenManager = require('../tokens');
const base64 = require('../util/base64');
const e = require('../util/HttpError');

const util = require('util');
const ms = require('ms');

const DEFAULT_TIMEOUT = ms('3 min');
const MINIMUM_TIMEOUT = ms('1 min');


function SessionManager(secret, timeout) {
  if (!(this instanceof SessionManager)) return new SessionManager(secret, timeout);

  TokenManager.call(this, secret);

  // Validate/normalize timeout
  if (! timeout) timeout = DEFAULT_TIMEOUT;
  if (util.isString(timeout)) timeout = ms(timeout) || timeout;
  if (! util.isNumber(timeout)) throw new TypeError('Invalid timeout "' + timeout + '"');
  if (timeout < MINIMUM_TIMEOUT) throw new TypeError('Timeout must be at least ' + ms(MINIMUM_TIMEOUT));

  // Timeout is a public value...
  Object.defineProperty(this, 'timeout', {
    enumerable: true,
    configurable: false,
    value: timeout
  });

  var _create = this.create;
  this.create = function(nonce, message) {

    // Decode client and server first messages
    var client_first = base64.decode(message.client_first);
    var server_first = base64.decode(message.server_first);

    // Our authenticated data
    var extra_auth_data = Buffer.concat([client_first, server_first]);

    return _create.call(this, timeout, nonce, extra_auth_data);
  }

  var _validate = this.validate;
  this.validate = function(session, message) {

    // Client first and server first
    var client_first = base64.decode(message.client_first);
    var server_first = base64.decode(message.server_first);

    // Our authenticated data including time buffer!
    var extra_auth_data = Buffer.concat([client_first, server_first]);

    try {
      var nonce = _validate.call(this, session, extra_auth_data);
      if (nonce == null) throw e.Gone();
      return nonce;
    } catch (error) {
      throw new e.FailedDependency('Decryption Error', error);
    }
  }
}

util.inherits(SessionManager, TokenManager);

exports = module.exports = SessionManager;
