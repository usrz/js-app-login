var ECDH = require('../ecdh');
var expect = require('chai').expect;
var fs = require('fs');

describe.only('ECDH 2', function() {

  var names = [ 'prime256v1', 'secp384r1', 'secp521r1' ];
  var curves = {};

  before(function() {
    for (var i = 0; i < names.length; i ++) (function(name) {
      curves[name] = {
        pkcs8: fs.readFileSync('./curves/' + name + '.priv-pkcs8.pem', 'utf8'),
        priv: fs.readFileSync('./curves/' + name + '.priv.pem', 'utf8'),
        pub: fs.readFileSync('./curves/' + name + '.pub.pem', 'utf8'),
        jwk: JSON.parse(fs.readFileSync('./curves/' + name + '.priv.json', 'utf8')),
      }
    })(names[i]);
  });

  for (var i = 0; i < names.length; i ++) (function(name) {

    describe('Curve ' + name, function() {

      it('should parse an OpenSSL PEM private key', function() {
        var curve = curves[name];
        var key = new ECDH(curve.priv);
        expect(key.c, "name").to.equal(name);
        expect(key.x, "x").to.equal(curve.jwk.x);
        expect(key.y, "y").to.equal(curve.jwk.y);
        expect(key.d, "d").to.equal(curve.jwk.d);
      });

      it.skip('should parse a PKCS8 private key', function() {
        var curve = curves[name];
        var key = new ECDH(curve.pkcs8);
        expect(key.c, "name").to.equal(name);
        expect(key.x, "x").to.equal(curve.jwk.x);
        expect(key.y, "y").to.equal(curve.jwk.y);
        expect(key.d, "d").to.equal(curve.jwk.d);
      });

      it('should parse a SPKI public key', function() {
        var curve = curves[name];
        var key = new ECDH(curve.pub);
        expect(key.c, "name").to.equal(name);
        expect(key.x, "x").to.equal(curve.jwk.x);
        expect(key.y, "y").to.equal(curve.jwk.y);
      });

    });
  })(names[i]);
});
