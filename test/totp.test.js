'use strict';

var expect = require('chai').expect;
var Token = require('../src/totp');

var testVectorsHOTP = [ '755224', '287082', '359152', '969429', '338314',
                        '254676', '287922', '162583', '399871', '520489' ];

var testVectorsTOTP = [
  [ new Date('1970-01-01T00:00:59.000Z'), 'SHA1',   '94287082', '12345678901234567890'                                             ],
  [ new Date('1970-01-01T00:00:59.000Z'), 'SHA256', '46119246', '12345678901234567890123456789012'                                 ],
  [ new Date('1970-01-01T00:00:59.000Z'), 'SHA512', '90693936', '1234567890123456789012345678901234567890123456789012345678901234' ],
  [ new Date('2005-03-18T01:58:29.000Z'), 'SHA1',   '07081804', '12345678901234567890'                                             ],
  [ new Date('2005-03-18T01:58:29.000Z'), 'SHA256', '68084774', '12345678901234567890123456789012'                                 ],
  [ new Date('2005-03-18T01:58:29.000Z'), 'SHA512', '25091201', '1234567890123456789012345678901234567890123456789012345678901234' ],
  [ new Date('2005-03-18T01:58:31.000Z'), 'SHA1',   '14050471', '12345678901234567890'                                             ],
  [ new Date('2005-03-18T01:58:31.000Z'), 'SHA256', '67062674', '12345678901234567890123456789012'                                 ],
  [ new Date('2005-03-18T01:58:31.000Z'), 'SHA512', '99943326', '1234567890123456789012345678901234567890123456789012345678901234' ],
  [ new Date('2009-02-13T23:31:30.000Z'), 'SHA1',   '89005924', '12345678901234567890'                                             ],
  [ new Date('2009-02-13T23:31:30.000Z'), 'SHA256', '91819424', '12345678901234567890123456789012'                                 ],
  [ new Date('2009-02-13T23:31:30.000Z'), 'SHA512', '93441116', '1234567890123456789012345678901234567890123456789012345678901234' ],
  [ new Date('2033-05-18T03:33:20.000Z'), 'SHA1',   '69279037', '12345678901234567890'                                             ],
  [ new Date('2033-05-18T03:33:20.000Z'), 'SHA256', '90698825', '12345678901234567890123456789012'                                 ],
  [ new Date('2033-05-18T03:33:20.000Z'), 'SHA512', '38618901', '1234567890123456789012345678901234567890123456789012345678901234' ],
  [ new Date('2603-10-11T11:33:20.000Z'), 'SHA1',   '65353130', '12345678901234567890'                                             ],
  [ new Date('2603-10-11T11:33:20.000Z'), 'SHA256', '77737706', '12345678901234567890123456789012'                                 ],
  [ new Date('2603-10-11T11:33:20.000Z'), 'SHA512', '47863826', '1234567890123456789012345678901234567890123456789012345678901234' ],
];

describe('TOTP', function() {

  describe('RFC-4226 test vectors', function() {

    // HOTP / RFC-4266 test vectors with precalculated time -> counter
    for (var i = 0; i < testVectorsHOTP.length; i++) (function(i) {
      var timestamp = (i * 1000 * 30) + 1; // add 1, math precision on floats
      var expected = testVectorsHOTP[i];

      var details = '(HOTP SHA1 with counter ' + i + ')';
      it('should validate test vector ' + i + ' ' + details, function() {
        var token = new Token({
          label: 'foo',
          secret: new Buffer('12345678901234567890', 'utf8'),
          period: '30s',
          digits: 6
        });

        expect(token.compute(timestamp)).to.equal(expected);
      });
    })(i);
  });

  describe('RFC-6238 test vectors', function() {

    // TOTP / RFC-6238 test vectors
    for (var i = 0; i < testVectorsTOTP.length; i++) (function(i) {
      var test = testVectorsTOTP[i];
      var timestamp = test[0];
      var algorithm = test[1];
      var expected = test[2];
      var secret =  new Buffer(test[3], 'utf8');

      var details = '(TOTP+' + algorithm + ' at ' + timestamp.toISOString() + ')';
      it('should validate test vector ' + i + ' ' + details, function() {
        var token = new Token({
          label: 'foo',
          algorithm: algorithm,
          secret: secret,
          period: '30s',
          digits: 8
        });

        expect(token.compute(timestamp)).to.equal(expected);
      });
    })(i);
  });

  // Just check with Google Authenticator... RFC-6238 makes assumptions when dealing with
  // SHA256 and 512 (the secret is *NOT* 12345678901234567890, but a repetition thereof
  describe('Google Validator compliance (results generated manually - see comments)', function() {

    it('should validate a known value with a long secret', function() {
      var secret = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01234567890!@#$%^&*()ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01234567890!@#$%^&*()ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01234567890!@#$%^&*()';
      var buffer = new Buffer(secret, 'utf8');
      var token = new Token({
        label: 'Long secret',
        issuer: 'USRZ Tests',
        algorithm: 'SHA512',
        secret: buffer,
        period: '2 min',
        digits: 8
      });

      // A QR code for updating tests...
      // console.log('Scan the code at https://chart.googleapis.com/chart?chs=500x500&cht=qr&choe=UTF-8&chl=' + encodeURIComponent(token.toString()));
      // console.log('Now the time is ' + new Date().toISOString());
      // console.log('Now the token is ' + token.compute());

      // Timestamp when test was made, and associated result
      var timestamp = new Date('2015-04-10T15:49:18.000Z');
      var result = '2693' + '9240';

      // Check
      expect(token.compute(timestamp)).to.equal(result);
    });

    it('should validate a known value with a long secret', function() {
      var secret = 'a';
      var buffer = new Buffer(secret, 'utf8');
      var token = new Token({
        label: 'Short secret',
        issuer: 'USRZ Tests',
        algorithm: 'SHA512',
        secret: buffer,
        period: 15,
        digits: 7
      });

      // A QR code for updating tests...
      // console.log('Scan the code at https://chart.googleapis.com/chart?chs=500x500&cht=qr&choe=UTF-8&chl=' + encodeURIComponent(token.toString()));
      // console.log('Now the time is ' + new Date().toISOString());
      // console.log('Now the token is ' + token.compute());

      // Timestamp when test was made, and associated result
      var timestamp = new Date('2015-04-10T15:49:18.001Z');
      var result = '497' + '3263';

      // Check
      expect(token.compute(timestamp)).to.equal(result);
    });


  });

});
