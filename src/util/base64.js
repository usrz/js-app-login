'use strict';

var util = require('util');

function escape(string) {
  return string.replace(/\+/g, '-')
               .replace(/\//g, '_')
               .replace(/=+$/g, '');
}

function unescape(string) {
  return string.replace(/\-/g, '+')
               .replace(/_/g,  '/') +
    new Array(5 - string.length % 4).join('=');
};

function encode(data) {
  if (util.isString(data)) {
    data = new Buffer(data, 'utf8');
  } else if (! util.isBuffer(data)) {
    throw new Error('Data must be a Buffer or utf8 string');
  }

  return escape(data.toString('base64'));
};

function encode_json(object) {
  if (! util.isObject(object)) throw new TypeError('Data must be an object');
  return encode(new Buffer(JSON.stringify(object), 'utf8'));
}

function decode(string) {
  if (! util.isString(string)) throw new Error('Data must be a string');

  return new Buffer(unescape(string), 'base64');
}

function decode_json(string) {
  var buffer = decode(string);
  return JSON.parse(buffer.toString('utf8'));
}

exports = module.exports = {
  encode: encode,
  decode: decode,
  encode_json: encode_json,
  decode_json: decode_json
};
