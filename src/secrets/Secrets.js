'use strict'

const crypto = require('crypto');
const util = require('util');
const ms = require('ms');

const keys = new WeakMap();

function getTimeBuffer(time) {
  if (!(time >= new Date().getTime())) throw new Error('Wrong time "' + time + '"');
  if (time > 8640000000000000) time = 8640000000000000;
  var time_buffer = new Buffer(8);
  time_buffer.writeUInt32BE(time / 0x100000000, 0);
  time_buffer.writeUInt32BE(time % 0x100000000, 4);

  return time_buffer;
}

function getAuthenticatedData(time_buffer, extra_auth_data) {

  if ((!util.isBuffer(time_buffer)) || (time_buffer.length != 8)) {
    throw new Error('Time must be a 8 bytes long buffer');
  }

  if (! extra_auth_data) return time_buffer;
  if (util.isBuffer(extra_auth_data)) return Buffer.concat([time_buffer, extra_auth_data]);
  throw new Error('Extra authenticated data must be a buffer or null');

}

function Secrets(key) {
  if (!(this instanceof Secrets)) throw new Error('Can not create a Secrets');

  // Validate key
  if (! util.isBuffer(key)) throw new TypeError('Encryption key must be buffer');
  if (key.length < 1) throw new TypeError('Encryption key is empty');

  // We use AES-256-GCM, need 256 bits for the key...
  keys.set(this, crypto.createHash('sha256').update(key).digest());
}

Secrets.prototype.create = function create(timeout, secret, extra_auth_data) {

  // Validate/normalize timeout
  if (! timeout) throw new TypeError('Missing timeout');
  if (util.isString(timeout)) timeout = ms(timeout) || timeout;
  if (! util.isNumber(timeout)) throw new TypeError('Invalid timeout "' + timeout + '"');
  if (timeout < 0) throw new TypeError('Timeout must be non negative');

  // Validate secret and authenticated data
  if (! util.isBuffer(secret)) throw new Error('Secret must be a buffer');

  // Our authenticated data including time!
  var expires_at = new Date().getTime() + timeout;
  var time_buffer = getTimeBuffer(expires_at);
  var auth_data = getAuthenticatedData(time_buffer, extra_auth_data);

  // Good random initialization data
  var init_vector = crypto.randomBytes(12);

  // Encypher up the secret for this session
  var key = keys.get(this);
  var cipher = crypto.createCipheriv('aes-256-gcm', key, init_vector);
  cipher.setAAD(auth_data);
  cipher.write(secret);
  cipher.end();

  // Get the encrypted secret and auth tag
  var encrypted_data = cipher.read();
  var auth_tag = cipher.getAuthTag();

  // Encode all in base64, big URL
  return ( time_buffer.toString('base64') + '.'
         + init_vector.toString('base64') + '.'
         + encrypted_data.toString('base64') + '.'
         + auth_tag.toString('base64')
         ).replace(/\+/g, '-') // URL-safe!!!
          .replace(/\//g, '_') // decode will work...
          .replace(/=/g,   '');
}

Secrets.prototype.validate = function validate(token, extra_auth_data) {

  // Validate and split token in 4 parts
  if (! util.isString(token)) throw new Error('Token must be a string');
  var components = token.split('.');
  if (components.length !== 4) throw new Error('Invalid token');

  // Parse out the buffers for decryption
  var time_buffer = new Buffer(components[0], 'base64');
  var init_vector = new Buffer(components[1], 'base64');
  var encrypted_data = new Buffer(components[2], 'base64');
  var auth_tag = new Buffer(components[3], 'base64');

  // Check expiration time
  var expires_at = time_buffer.readUInt32BE(0) * 0x100000000 +
                   time_buffer.readUInt32BE(4);

  if (new Date().getTime() > expires_at) return null;

  // Our authenticated data including time buffer!
  var auth_data = getAuthenticatedData(time_buffer, extra_auth_data);

  // Attempt to decrypt
  var key = keys.get(this);
  var decipher = crypto.createDecipheriv('aes-256-gcm', key, init_vector);
  decipher.setAAD(auth_data);
  decipher.setAuthTag(auth_tag);
  decipher.write(encrypted_data);
  decipher.end();

  // Return the decrypted secret
  return decipher.read();
}

exports = module.exports = Secrets;
