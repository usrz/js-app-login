var expect = require('chai').expect;
var validate = require('validate.js');
validate.validators.base64 = require('../src/base64validator');

function test(string, options, expected) {
  return function() {
    var result = validate({ string: string }, {
        string: {
          presence: true,
          base64: options || {}
        }
      });

    if (result) {
      var message = result.string[0];
      expect(message).to.exist;
      expect(message).to.equal(expected);
    } else {
      expect(result).to.equal(expected);
    }
  }
}

function encode(what) {
  return new Buffer(what).toString('base64');
}

describe('Base64 Validator', function() {

  // Basics
  it('should validate a simple string',
    test("abcd"));

  it('should validate a simple string with padding',
    test("aa=="));

  it('should validate a simple string with no padding',
    test("a"));

  // Characters
  it('should validate a string with characters from both alphabets',
    test("-_+/"));

  it('should not validate a string with wrong characters',
    test("%", {},
         "String is not a valud base64-encoded string"));

  it('should validate a string with standard characters',
    test("+/==", { format: 'standard' }));

  it('should not validate a string with wrong standard characters',
    test("-_==", { format: 'standard' },
    "String is not a valud base64-encoded string"));

  it('should validate a string with urlsafe characters',
    test("-_==", { format: 'urlsafe' }));

  it('should not validate a string with wrong urlsafe characters',
    test("+/==", { format: 'urlsafe' },
    "String is not a valud base64-encoded string"));

  // Encoded length
  it('should validate the minimum required length',
    test(new Buffer(10).toString('base64'), { length: {minimum: 10 }}));

  it('should not validate the minimum required length for short strings',
    test(new Buffer(9).toString('base64'), { length: {minimum: 10 }},
         "String must be at least 10 bytes (14 characters in base64)"));

  it('should validate the maximum required length',
    test(new Buffer(10).toString('base64'), { length: {maximum: 10 }}));

  it('should not validate the maximum required length for short strings',
    test(new Buffer(13).toString('base64'), { length: {maximum: 10 }},
         "String must be at most 10 bytes (16 characters in base64)"));

  // Decoded length (edge cases for paddings...)
  it('should not validate the decoded minimum required length for short strings',
    test('AAAAAAAAAAAAA=', { length: {minimum: 10 }},
         "String must decode to at least 10 bytes"));

  it('should not validate the decoded maximum required length for short strings',
    test('AAAAAAAAAAAAAAA', { length: {maximum: 10 }},
         "String must decode to at most 10 bytes"));

});
