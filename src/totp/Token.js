'use strict';

var base32 = require('./base32');
var crypto = require('crypto');
var util = require('util');
var ms = require('ms');

/* =========================================================================== */

function Token(options) {
  if (!(this instanceof Token)) return new Token(options);

  // Constructed with a label
  if (util.isString(options)) {
    options = { label: options };
  } else if (! util.isObject(options)) {
    throw new TypeError('Must be constructed with a label string or options object');
  }

  var label = options.label || null;
  var issuer = options.issuer || null;
  var secret = options.secret || null;
  var algorithm = options.algorithm || 'sha1';
  var digits = options.digits || 6;
  var period = options.period || 30;

  // Secret must be a string or buffer
  if (! secret) secret = crypto.randomBytes(32);
  if (util.isString(secret)) secret = base32.decode(secret);
  if ((!util.isBuffer(secret)) || (secret.length < 1)) {
    throw new TypeError('The \'secret\' must be a non-empty Buffer or a base32 string');
  }

  // Label must be specified
  if (! util.isString(label)) {
    throw new TypeError('The \'label\' must be a string');
  }

  // Issuer must be a string or unspecified
  if (issuer && (! util.isString(issuer))) {
    throw new TypeError('The \'issuer\' must be a string');
  }

  // Algorithm normalization
  if (util.isFunction(algorithm.toUpperCase)) algorithm = algorithm.toUpperCase();
  if (['SHA1', 'SHA256', 'SHA512'].indexOf(algorithm) < 0) {
    throw new TypeError('Unsupported algorithm \'' + algorithm + '\'');
  }

  // Check digits
  if ((! util.isNumber(digits)) || (digits < 6) || (digits > 8)) {
    throw new TypeError('The \'digits\' must be between 6 and 8');
  }

  // Period normalization
  if (util.isString(period)) {
    var millis = ms(period);
    if (! millis) throw new TypeError('The \'period\' is invalid:' + period);
    period = millis / 1000;
  }

  // Period validation
  if (! util.isNumber(period)) {
    throw new TypeError('The \'period\' must be a number');
  } else if ((period < 15) || (period > 120)) {
    throw new TypeError('The \'period\' must be from 15 to 120 seconds');
  }

  // Read-only properties
  Object.defineProperties(this, {
    'algorithm': { enumerable: true, configurable: false, value: algorithm },
    'label':     { enumerable: true, configurable: false, value: label },
    'digits':    { enumerable: true, configurable: false, value: digits },
    'period':    { enumerable: true, configurable: false, value: period },
    'secret':    { enumerable: true, configurable: false, get: function() {
      return new Buffer(secret); // always clone
    }}
  });

  // Optional issuer
  if (issuer) Object.defineProperty(this, 'issuer', {
    enumerable: true, configurable: false, value: issuer
  });
}

Token.prototype.many = function many(drift, from) {
  if (! from) from = new Date().getTime();
  else if (util.isDate(from)) from = from.getTime();
  else if (! util.isNumber(from)) throw new Error('Must be called with a date (or ms from epoch)');

  if (util.isString(drift)) drift = ms(drift);
  drift = drift ? Math.round(drift) : 0;
  if (!(drift >= 0)) throw new Error('Drift can not be negative');

  var results = new Array();

  // Our counters...
  var min = Math.floor((from - drift) / 1000 / this.period);
  var max = Math.floor((from + drift) / 1000 / this.period);

  // For each "counter", compute
  for (var i = min; i <= max; i ++) {
    var at = i * this.period * 1000;
    results.push(this.compute(at));
  }

  return results;
}

Token.prototype.compute = function compute(at) {
  if (! at) at = new Date().getTime();
  else if (util.isDate(at)) at = at.getTime();
  else if (! util.isNumber(at)) throw new Error('Must be called with a date (or ms from epoch)');

  // Our counter as a 8-byte big-endian number
  var timeslot = Math.floor(at / 1000 / this.period);
  var counter = new Buffer(8).fill(0);
  counter.writeUInt32BE(timeslot, 4);

  // Our HMAC derived from the counter
  var hmac = crypto.createHmac(this.algorithm.toLowerCase(), this.secret)
                   .update(counter)
                   .digest();

  // Calculate the offset of the 4-bytes to read
  var offset = hmac[hmac.length - 1] & 0x0f;
  var sbits = hmac.readUInt32BE(offset) & 0x07fffffff;

  // Calculate and pad the number displayed on the TOTP generator
  var number = (sbits % (Math.pow(10, this.digits))).toString();
  while (number.length < this.digits) number = '0' + number;

  // Done!
  return number;
}

Token.prototype.toJSON = function toJSON() {
  var json = {
    'algorithm': this.algorithm,
    'label':     this.label,
    'digits':    this.digits,
    'period':    this.period,
    'secret':    base32.encode(this.secret)
  }
  if (this.issuer != null) json.issuer = this.issuer;
  return json;
}

Token.prototype.toString = function toString() {
  var string = "otpauth://totp/";

  if (this.issuer != null) string += encodeURI(this.issuer) + ':';

  string += encodeURI(this.label);
  string += '?secret=' + base32.encode(this.secret);

  if (this.issuer != null)      string += '&issuer='    + encodeURIComponent(this.issuer);
  if (this.algorithm != 'SHA1') string += '&algorithm=' + this.algorithm;
  if (this.period != 30)        string += '&period='    + this.period;
  if (this.digits != 6)         string += '&digits='    + this.digits;

  return string;
}

exports = module.exports = Token;
