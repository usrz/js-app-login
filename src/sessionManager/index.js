'use strict';

const base64 = require('../base64');
const e = require('../errors');

const log = require('errorlog')();
const crypto = require('crypto');
const util = require('util');

const DEFAULT_TIMEOUT = 60000; // 1 minute

const secrets = new WeakMap();

function SessionManager(secret, timeout) {
  if (!(this instanceof SessionManager)) return new SessionManager(secret, timeout);

  // Validate secret
  if (! secret) throw new TypeError('Missing session manager secret');
  if (util.isString(secret)) secret = base64.decode(secret);
  if (! util.isBuffer(secret)) throw new TypeError('Session manager secret must be a buffer');
  if (secret.length <= 0) throw new TypeError('Session manager secret is empty');

  // We use AES-256-GCM, need 256 bits for the secret...
  secrets.set(this, crypto.createHash('sha256').update(secret).digest());

  // Validate/normalize timeout
  if (! timeout) timeout = DEFAULT_TIMEOUT;
  if (util.isString(timeout)) timeout = ms(timeout) || timeout;
  if (! util.isNumber(timeout)) throw new TypeError('Invalid timeout "' + timeout + '"');
  if (timeout < DEFAULT_TIMEOUT) throw new TypeError('Minimum timeout must be at least 1 minute');

  // Timeout is a publi value...
  Object.defineProperty(this, 'timeout', {
    enumerable: true,
    configurable: false,
    value: timeout
  });
}

SessionManager.prototype.create = function(nonce, message) {
  // Time buffer, number of seconds from the epoch
  var time_buffer = new Buffer(4);
  time_buffer.writeUInt32BE(Math.ceil((new Date().getTime() + this.timeout) / 1000));

  // Decode client and server first messages
  var client_first = base64.decode(message.client_first);
  var server_first = base64.decode(message.server_first);

  // Our authenticated data including time buffer!
  var authenticated_data = Buffer.concat([time_buffer, client_first, server_first]);

  // Good random initialization data
  var initialization_vector = crypto.randomBytes(12);

  // Encypher up the nonce for this session
  var cipher = crypto.createCipheriv('aes-256-gcm', secrets.get(this), initialization_vector);
  cipher.setAAD(authenticated_data);
  cipher.write(nonce);
  cipher.end();

  // Get the encrypted nonce and auth tag
  var encrypted_data = cipher.read();
  var authentication_tag = cipher.getAuthTag();

  // Encode all in base64, big URL
  return base64.encode(time_buffer) + '.'
       + base64.encode(initialization_vector) + '.'
       + base64.encode(encrypted_data) + '.'
       + base64.encode(authentication_tag);
}

SessionManager.prototype.validate = function(session, message) {
  // Split the URL in 4 parts (and check)
  var components = session.split('.');
  if (components.length !== 4) throw e.NotFound();

  // Parse out the buffers for decryption
  var time_buffer = base64.decode(components[0]);
  var initialization_vector = base64.decode(components[1]);
  var encrypted_data = base64.decode(components[2]);
  var authentication_tag = base64.decode(components[3]);

  // Client first and server first
  var client_first = base64.decode(message.client_first);
  var server_first = base64.decode(message.server_first);

  // Our authenticated data including time buffer!
  var authenticated_data = Buffer.concat([time_buffer, client_first, server_first]);

  // Attempt to decrypt
  var decrypted_data = null;
  try {
    var decipher = crypto.createDecipheriv('aes-256-gcm', secrets.get(this), initialization_vector);
    decipher.setAAD(authenticated_data);
    decipher.setAuthTag(authentication_tag);
    decipher.write(encrypted_data);
    decipher.end();
    decrypted_data = decipher.read();
  } catch (error) {
    console.log('error', error);
    throw new e.FailedDependency();
  }

  // Check expiration time
  var expiry = time_buffer.readUInt32BE() * 1000;
  if (new Date().getTime() > expiry) throw e.Gone();

  return decrypted_data;
}

exports = module.exports = SessionManager;
