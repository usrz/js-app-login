'use strict';

const util = require('util');

function Credential(cred) {
  if (! util.isObject(cred)) throw new TypeError('Missing credentials definition');

  if (! util.isObject(cred.kdf_spec)) throw new TypeError('Missing or invalid kdf specification');
  var kdf_spec = Object.freeze(JSON.parse(JSON.stringify(cred.kdf_spec)));

  if (! util.isString(cred.hash)) throw new TypeError('Missing or invalid scram hash');
  var hash = cred.hash;

  var stored_key = null;
  if (util.isString(cred.stored_key)) stored_key = new Buffer(cred.stored_key, 'base64');
  else if (util.isBuffer(cred.stored_key)) stored_key = cred.stored_key;
  else if (! util.isNullOrUndefined(cred.stored_key)) throw new TypeError('Invalid stored key');

  var server_key = null;
  if (util.isString(cred.server_key)) server_key = new Buffer(cred.server_key, 'base64');
  else if (util.isBuffer(cred.server_key)) server_key = cred.server_key;
  else if (! util.isNullOrUndefined(cred.server_key)) throw new TypeError('Invalid server key');

  var salt = null;
  if (util.isString(cred.salt)) salt = new Buffer(cred.salt, 'base64');
  else if (util.isBuffer(cred.salt)) salt = cred.salt;
  else throw new TypeError('Invalid or missing salt');

  Object.defineProperties(this, {
    kdf_spec:   { enumerable: true, configurable: false, value: kdf_spec   },
    server_key: { enumerable: true, configurable: false, value: server_key },
    stored_key: { enumerable: true, configurable: false, value: stored_key },
    salt:       { enumerable: true, configurable: false, value: salt       },
    hash:       { enumerable: true, configurable: false, value: hash       }
  });
}

Credential.prototype.toString = function toString() {
  return Credential + '[' + this.hash + ']';
}

Credential.prototype.toJSON = function toJSON() {
  return {
    kdf_spec:   this.kdf_spec,
    server_key: this.server_key ? this.server_key.toString('base64') : null,
    stored_key: this.stored_key ? this.stored_key.toString('base64') : null,
    salt:       this.salt.toString('base64'),
    hash:       this.hash
  };
}

exports = module.exports = Credential;
