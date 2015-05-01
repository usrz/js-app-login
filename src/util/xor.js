'use strict'

const util = require('util');

exports = module.exports = function xor(buffer1, buffer2) {
  if (! util.isBuffer(buffer1)) throw new TypeError('Buffer 1 is not a buffer');
  if (! util.isBuffer(buffer2)) throw new TypeError('Buffer 2 is not a buffer');
  if (buffer1.length != buffer2.length) throw new Error('Buffer lengths mismatch');
  var buffer = new Buffer(buffer1.length);
  for (var i = 0; i < buffer2.length; i ++) {
    buffer[i] = buffer1[i] ^ buffer2[i];
  }
  return buffer;
}
