'use strict';

var expect = require('chai').expect;
var TOTP = require('../src/totp');
var Token = TOTP.Token;

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

  describe('BASE32', function() {

    var base32 = require('../src/totp/base32');

    // Incredibly enough, "foobar" is in the RFC :-)
    var testVectors = [
      [ "f"      , "MY"         ],
      [ "fo"     , "MZXQ"       ],
      [ "foo"    , "MZXW6"      ],
      [ "foob"   , "MZXW6YQ"    ],
      [ "fooba"  , "MZXW6YTB"   ],
      [ "foobar" , "MZXW6YTBOI" ],
    ];

    for (var i = 0; i < testVectors.length; i++) (function(i) {
      var decoded = testVectors[i][0];
      var encoded = testVectors[i][1];

      it('should encode test vector ' + i, function() {
        expect(base32.encode(decoded)).to.equal(encoded);
      });

      it('should decode test vector ' + i, function() {
        expect(base32.decode(encoded).toString('utf8')).to.equal(decoded);
      });

    })(i);
  });

  describe('Token storage', function() {

    var secrets = {}, totp;
    before(function() {
      totp = new TOTP(function(id) {
        if (! secrets[id]) return null;
        return Promise.resolve(JSON.parse(secrets[id]));
      }, function(id, token) {
        secrets[id] = JSON.stringify(token);
        return Promise.resolve(JSON.parse(secrets[id]));
      })
    });

    it('should store and retrieve a token with no options', function(done) {
      var t = null;
      totp.set('test@example.org')
        .then(function(token) {
          expect(token).to.be.instanceof(Token);
          expect(token.toString()).to.match(/^otpauth:\/\/totp\/test@example.org\?secret=/);
          t = token;
          return totp.get('test@example.org');
        })
        .then(function(token) {
          expect(token).to.be.instanceof(Token);
          expect(token).to.not.equal(t);
          expect(token).to.eql(t);
          done();
        })
        .catch(done);
    });

    it('should not return a token for an unknown user', function(done) {
      totp.get('nosuchuser@example.org')
        .then(function(token) {
          expect(token).to.be.null;
          done();
        })
        .catch(done);
    });

    it('should should reject when fetch throws an error', function(done) {
      var totp = new TOTP(function(id) {
        throw new Error('Thrown for ' + id);
      }, function(id, token) {});

      totp.get('test@example.org')
        .then(function(token) {
          done(new Error('Should have thrown an error'));
        })
        .catch(function(error) {
          expect(error).to.be.instanceof(Error);
          expect(error.message).to.equal('Thrown for test@example.org');
          done();
        })
        .catch(done);
    });

    it('should should reject when store throws an error', function(done) {
      var totp = new TOTP(function(id) {}, function(id, token) {
        throw new Error('Thrown for ' + id);
      });

      totp.set('test@example.org')
        .then(function(token) {
          done(new Error('Should have thrown an error'));
        })
        .catch(function(error) {
          expect(error).to.be.instanceof(Error);
          expect(error.message).to.equal('Thrown for test@example.org');
          done();
        })
        .catch(done);
    });
  });

  /* ======================================================================== */

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

  /* ======================================================================== */

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

  /* ======================================================================== */

  describe('Convesion to string/json', function() {
    it('should validate a minimal token', function() {
      var secret = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
      var token = new Token({label: 'test label', secret: secret});

      expect(token.toString()).to.equal('otpauth://totp/test%20label?secret=' + secret);

      var json = JSON.stringify(token);
      expect(JSON.parse(json)).to.eql({
        algorithm: 'SHA1',
        label: 'test label',
        digits: 6,
        period: 30,
        secret: secret
      });

      expect(new Token(JSON.parse(json))).to.eql(token);
    });

    it('should validate a fully specced token', function() {
      var secret = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
      var token = new Token({
        algorithm: 'SHA512',
        label: 'test label',
        issuer: 'test issuer',
        digits: 8,
        period: 60,
        secret: secret
      });

      expect(token.toString()).to.equal('otpauth://totp/test%20issuer:test%20label?secret=' + secret + '&issuer=test%20issuer&algorithm=SHA512&period=60&digits=8');

      var json = JSON.stringify(token);
      expect(JSON.parse(json)).to.eql({
        algorithm: 'SHA512',
        label: 'test label',
        issuer: 'test issuer',
        digits: 8,
        period: 60,
        secret: secret
      });

      expect(new Token(JSON.parse(json))).to.eql(token);
    });
  });

  /* ======================================================================== */

  describe('Multiple results', function() {

    var token = new Token({
      label: 'Testing secret',
      secret: new Buffer('a simple secret', 'utf8'),
      period: '2 min',
      digits: 8
    });

    // At is precisely at our period clock..
    var at = new Date('2015-01-01T00:30:00.000Z');
    var atless1 = new Date('2015-01-01T00:29:59.000Z');
    var atplus1 = new Date('2015-01-01T00:30:00.000Z');

    it('should validate a single result', function() {
      expect(token.compute(at)).to.equal('94402263');
      expect(token.compute(atless1)).to.equal('80619832');
      expect(token.compute(atplus1)).to.equal('94402263');
    });

    it('should produce one result with no drift', function() {
      expect(token.many(0, at)).to.eql(['94402263']);
      expect(token.many(0, atless1)).to.eql(['80619832']);
      expect(token.many(0, atplus1)).to.eql(['94402263']);
    });

    it('should produce two result with minimal drift', function() {
      expect(token.many('1 min', at)).to.eql(['80619832', '94402263']);
    });

    it('should produce three result with drift same as period', function() {
      expect(token.many('2 min', at)).to.eql(['80619832', '94402263', '85972092']);
      expect(token.many('2 min', atless1)).to.eql(['75356764', '80619832', '94402263']);
      expect(token.many('2 min', atplus1)).to.eql(['80619832', '94402263', '85972092']);
    });

    it('should produce a bunch of result with normal drift', function() {
      expect(token.many('5 min', at)).to.eql(['19216581', '75356764', '80619832', '94402263', '85972092', '41742200']);
    });
  });

  /* ======================================================================== */

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
