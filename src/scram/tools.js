'use strict';

var util = require('util');

function xor(a, b) {
  if (! util.isBuffer(a)) throw new TypeError('Buffer A is not a buffer');
  if (! util.isBuffer(b)) throw new TypeError('Buffer B is not a buffer');
  if (a.length != b.length) throw new TypeError('Buffer lengths differ');
  var c = new Buffer(a.length);
  for (var i = 0; i < b.length; i++) c[i] = a[i] ^ b[i];
  return c;
}

function normalize(message) {
  var subject = message.subject;
  var audience = [];

  if (! subject) throw new Error('Subject not specified or empty');
  if (! util.isString(subject)) throw new Error('Subject is not a string');

  if (message.audience) {
    if (util.isString(message.audience)) {
      audience.push(message.audience);
    } else if (util.isArray(message.audience)) {
      for (var i = 0; i < message.audience.length; i ++) {
        var current = message.audience[i];
        if (! current) throw new Error('Audience at index ' + i + ' is empty or null');
        if (! util.isString(current)) throw new Error('Audience at index ' + i + ' is not a string');
        audience.push(current);
      }
    } else {
      throw new Error('Audience must be a string or an array');
    }
  }

  var result = { subject: subject };
  if (audience.length == 1) result.audience = audience[0];
  else if (audience.length > 1) result.audience = audience;

  return result;
}

function flatten(data, array, isargs) {
  if (! util.isArray(array)) throw new Error('Need an array');
  if (isargs) data = Array.prototype.slice.call(data);
  if (util.isArray(data)) {
    for (var i = 0; i < data.length; i ++) {
      array = flatten(data[i], array);
    }
  } else if (util.isString(data)) {
    array.push(data);
  }
  return array;
}

exports = module.exports = {
  flatten: flatten,
  normalize: normalize,
  xor: xor
}
