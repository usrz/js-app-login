'use strict';

var util = require('util');

var chr = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
var val = new Buffer(128).fill(255);

for (var i = 0; i < 32; i++) {
  val[chr[i].toUpperCase().charCodeAt(0)] = i;
  val[chr[i].toLowerCase().charCodeAt(0)] = i;
}

function decode(string) {

  // Check!
  if (! util.isString(string)) throw new Error('Data must be a string');


  // Wipe trailing padding
  while (string[string.length - 1] == '=') {
    string = string.substr(0, string.length - 1);
  }

  // Variables
  var index = 0, offset = 0;
  var buffer = new Buffer(Math.floor(string.length * 5 / 8)).fill(0);

  // Main Loop
  for (var i = 0; i < string.length; i ++) {
    var c = string[i];
    var d = val[string.charCodeAt(i)];

    // Check that what we got is right
    if ((d > 32) || (d == null)) {
      throw new Error('Invalid character \'' + c + '\' at index '+ i + ' in base32 string \'' + string + '\'');
    }

    // Decode the character

    if (index <= 3) {
      index = (index + 5) % 8;
      if (index == 0) {
        buffer[offset] |= d;
        offset++;
        if (offset >= buffer.length) break;
      } else {
        buffer[offset] |= d << (8 - index);
      }
    } else {

      index = (index + 5) % 8;
      buffer[offset] |= (d >>> index);
      offset++;
      if (offset >= buffer.length) break;
      buffer[offset] |= d << (8 - index);

    }
  }

  return buffer;
}

function encode(data) {

  // If data is a string, convert to a buffer
  if (util.isString(data)) {
    data = new Buffer(data, 'utf8');
  } else if (! util.isBuffer(data)) {
    throw new Error('Data must be a Buffer or utf8 string');
  }

  var i = 0, index = 0, digit = 0, end = data.length;
  var currByte, nextByte;
  var base32 = new Array();

  while (i < end) {
    currByte = (data[i] >= 0) ? data[i] : (data[i] + 256);

    /* Is the current digit going to span a byte boundary? */
    if (index > 3) {
      if ((i + 1) < end) {
        nextByte = (data[i + 1] >= 0) ? data[i + 1] : (data[i + 1] + 256);
      } else {
        nextByte = 0;
      }

      digit = currByte & (0xFF >> index);
      index = (index + 5) % 8;
      digit <<= index;
      digit |= nextByte >> (8 - index);
      i++;
    } else {
      digit = (currByte >> (8 - (index + 5))) & 0x1F;
      index = (index + 5) % 8;
      if (index == 0) i++;
    }

    base32.push(chr[digit]);
  }

  return base32.join('');
}

exports = module.exports = {
  encode: encode,
  decode: decode
}



// console.log(decode("").toString('utf8'));
// console.log(decode("MY").toString('utf8'));
// console.log(decode("MZXQ").toString('utf8'));
// console.log(decode("MZXW6").toString('utf8'));
// console.log(decode("MZXW6YQ").toString('utf8'));
// console.log(decode("MZXW6YTB").toString('utf8'));
// console.log(decode("MZXW6YTBOI").toString('utf8'));

// console.log(decode("").toString('utf8'));
// console.log(decode("my").toString('utf8'));
// console.log(decode("mzxq").toString('utf8'));
// console.log(decode("mzxw6").toString('utf8'));
// console.log(decode("mzxw6yq").toString('utf8'));
// console.log(decode("mzxw6ytb").toString('utf8'));
// console.log(decode("mzxw6ytboi").toString('utf8'));

// console.log(encode(""),         "");
// console.log(encode("f"),        "MY");
// console.log(encode("fo"),       "MZXQ");
// console.log(encode("foo"),      "MZXW6");
// console.log(encode("foob"),     "MZXW6YQ");
// console.log(encode("fooba"),    "MZXW6YTB");
// console.log(encode("foobar"),   "MZXW6YTBOI");
