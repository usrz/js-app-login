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
  var buffer;

  if (! data) {
    throw new TypeError('Cowardly refusing to encode null data');
  } else if (util.isString(data)) {
    buffer = new Buffer(data, 'utf8');
  } else if (util.isBuffer(data)) {
    buffer = data;
  } else {
    throw new TypeError('Only Buffer or strings can be encoded');
  }

  return escape(buffer.toString('base64'));
};

function decodeBuffer(data) {
  if (! data) {
    throw new TypeError('Cowardly refusing to decode null data');
  } else if (util.isString(data)) {
    return new Buffer(unescape(data), 'base64');
  } else {
    throw new TypeError('Only strings can be decoded');
  }
}

function decodeString(data) {
  if (! data) {
    throw new TypeError('Cowardly refusing to decode null data');
  } else {
    return deocdeBuffer(data).toString('utf8');
  }
}

exports = module.exports = {
  encode:       encode,
  decodeBuffer: decodeBuffer,
  decodeString: decodeString
}
