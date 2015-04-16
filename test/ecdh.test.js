'use strict';

var expect = require('chai').expect;
var crypto = require('crypto');
var base64 = require('../src/base64');

var ecdh = require('../src/ecdh');
var ECDH = ecdh.ECDH;

describe('ECDH', function() {

  it ('should contain all standard curves', function() {
    var curves = [ 'P-192', 'P-224', 'P-256', 'P-384', 'P-521' ];
    expect(ecdh.curves).to.have.members(curves);
  });

  // Repeat for each of the curve we tested above

  for (var i = 0; i < ecdh.curves.length; i ++) (function(curve) {

    it('should derive a secret correctly with ' + curve, function() {

      var ecdh = new ECDH(curve.toLowerCase());
      var request = ecdh.request();

      expect(request.ecdh_curve).to.equal(curve.toUpperCase()); // uppercase!
      expect(request.public_key).to.be.a('string');

      var secret = new ECDH(curve).respond(request);

      expect(secret).to.be.instanceof(Buffer);
      expect(secret.length).to.be.equal(Math.ceil(Number(curve.substr(2))/8));
    });

  })(ecdh.curves[i]);

  // Negative tests (must throw stuff)

  it('should not work with garbage', function() {
    expect(function() {
      var request = new ECDH('P-256').request();
      var buffer = base64.decode(request.public_key);
      request.public_key = base64.encode(crypto.pseudoRandomBytes(buffer.length));
      new ECDH('P-256').respond(request);
    }).to.throw('Failed to translate Buffer to a EC_POINT');
  });

  it('should not construct with unknown curves', function() {
    expect(function() {
      new ECDH('P-512');
    }).to.throw('Unsupported curve "P-512"');
  });

  it('should not derive with mismatching curves', function() {
    expect(function() {
      new ECDH('P-521').respond(new ECDH('P-192').request());
    }).to.throw('ECDH curves mismatch');
  });

});
