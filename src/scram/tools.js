'use strict';

var base64 = require('../base64');
var crypto = require('crypto');
var util = require('util');

function xor(a, b) {
  if (! util.isBuffer(a)) throw new TypeError('Buffer A is not a buffer');
  if (! util.isBuffer(b)) throw new TypeError('Buffer B is not a buffer');
  if (a.length != b.length) throw new TypeError('Buffer lengths differ');
  var c = new Buffer(a.length);
  for (var i = 0; i < b.length; i++) c[i] = a[i] ^ b[i];
  return c;
}

/**
 * Prepare some random bytes, return a Buffer
 */
function randomBuffer(length, secure) {
  if (secure === undefined) secure = true;
  if (length < 32) throw new RangeError('Cowardly refusing to return less than 32 bytes');

  var generator = secure ? crypto.randomBytes : crypto.pseudoRandomBytes;
  return generator.call(crypto, length);
}

/**
 * Prepare some random bytes, encoded in Base64 URL
 */
function randomBase64(length, secure) {
  return base64.encode(randomBuffer(length, secure));
}


/**
 * Normalize "subject" and "audience" in a message, returning a clone containing
 * only those two fields.
 */
function normalize(message) {
  if (! util.isObject(message)) throw new TypeError('Message is not an object');

  if (! message.subject) throw new TypeError('Subject not specified or empty');
  if (! util.isString(message.subject)) throw new TypeError('Subject is not a string');

  /* Normalize audience */
  var audience = [];
  if (message.audience) try {
    audience = flatten(message.audience, audience, false);
  } catch (error) {
    throw new TypeError('Unable to normalize audience: ' + error.message);
  }

  /* Prepare our clone */
  var clone = { subject: message.subject };
  if (audience.length == 1) {
    clone.audience = audience[0];
  } else if (audience.length > 1) {
    clone.audience = audience;
  }

  /* Return our clone */
  return clone;
}

/**
 * Basic validation of a message, checking for subject and audience array
 */
//function validate


/**
 * Flatten some data (a string, an array of strings, or some function arguments)
 * into the specified array, recursively.
 * Arguments are supported *only* when `isargs` is set to `true`.
 */
function flatten(data, array, isargs) {
  /* Need an array to flatten things into */
  if (! util.isArray(array)) {
    throw new Error('Need an array');
  }

  /* If an object and arguments, convert to an array */
  if (util.isObject(data) && isargs) {
    data = Array.prototype.slice.call(data);
  }

  /* If this is an array, process one-by-one */
  if (util.isArray(data)) {
    for (var i = 0; i < data.length; i ++) {
      array = flatten(data[i], array, false);
    }
  } else if (util.isString(data)) {
    if (!data) throw new TypeError('String must be non-empty');
    array.push(data);
  } else {
    throw new TypeError('Invalid non-string type ' + typeof(object));
  }

  /* Return our array */
  return array;
}

exports = module.exports = {
  randomBuffer: randomBuffer,
  randomBase64: randomBase64,
  normalize: normalize,
  flatten: flatten,
  xor: xor
}
