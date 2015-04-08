exports = module.exports = function(value, options) {
  // Let "presence" do its job
  if (!value) return;

  // Anything else we are given must be a string
  if (typeof(value) !== 'string') {
    return 'can not be base64-decoded from a ' + typeof(value);
  }

  // Lengths
  var dminlen = 0,
      eminlen = 0,
      dmaxlen = 0,
      emaxlen = 0;

  if (options.length) {
    dminlen = options.length.minimum || 0;
    eminlen = Math.ceil(dminlen * 8 / 6);
    dmaxlen = options.length.maximum || 0;
    emaxlen = Math.ceil(dmaxlen * 8 / 6);
    emaxlen += 4 - (emaxlen % 4);
  }

  // Minimum length encoded
  if (dminlen && (value.length < eminlen))
    return 'must be at least ' + dminlen + ' bytes (' + eminlen + ' characters in base64)';

  // Maximum length encoded
  if (dmaxlen && (value.length > emaxlen))
    return 'must be at most ' + dmaxlen + ' bytes (' + emaxlen + ' characters in base64)';

  // Lenient format (accept standard or url safe)
  var format = options.format || /^[-_\+\/A-Za-z0-9]*=*$/;
  if (typeof(format) === 'string') {
    if (format.toLowerCase() == 'standard') {
      format = /^[\+\/A-Za-z0-9]*=*$/;
    } else if (format.toLowerCase() == 'urlsafe') {
      format = /^[-_A-Za-z0-9]*=*$/;
    }
  }

  // Check format
  if (value.match(format) == null) {
    return 'is not a valud base64-encoded string';
  }

  // Decode to a buffer and check length
  var buffer = new Buffer(value, 'base64');

  // Minumum length decoded
  if (dminlen && (buffer.length < dminlen))
    return 'must decode to at least ' + dminlen + ' bytes';

  // Maximum length decoded
  if (dmaxlen && (buffer.length > dmaxlen))
    return 'must decode to at most ' + dmaxlen + ' bytes';
}
