'use strict';

var util = require('util');

exports = module.exports = {
  isGreaterThan: function isGreaterThan(number, than) {
    if (! util.isNumber(than)) throw new TypeError('Comparison value must be a number');
    if (util.isNumber(number)) return number > than;
    return false;
  },

  isNonEmptyString: function isNonEmptyString(string) {
    if (util.isString(string)) return string.length > 0;
    return false;
  },
};

for (var i in util) exports[i] = util[i];
