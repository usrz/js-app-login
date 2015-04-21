var ECDH = require('../ecdh');
var expect = require('chai').expect;
var fs = require('fs');

describe.only('ECDH 2', function() {

  var names = [ 'prime256v1', 'secp384r1', 'secp521r1' ];
  var curves = {};

  before(function() {
    for (var i = 0; i < names.length; i ++) (function(name) {
      curves[name] = {
        // PEM FILES
        pkcs8: fs.readFileSync('./curves/' + name + '.priv-pkcs8.pem', 'utf8'),
        priv: fs.readFileSync('./curves/' + name + '.priv-openssl.pem', 'utf8'),
        pub: fs.readFileSync('./curves/' + name + '.pub.pem', 'utf8'),
        // JWK FILES
        privJwk: JSON.parse(fs.readFileSync('./curves/' + name + '.priv.json', 'utf8')),
        pubJwk: JSON.parse(fs.readFileSync('./curves/' + name + '.pub.json', 'utf8')),
      }
    })(names[i]);
  });

  for (var i = 0; i < names.length; i ++) (function(name) {

    describe('Curve ' + name, function() {

      it('should parse an OpenSSL PEM private key', function() {
        var curve = curves[name];
        var key = new ECDH(curve.priv);
        expect(key.curve, "curve name").to.equal(name);
        expect(key.toJSON(), "jwk").to.eql(curve.privJwk);
      });

      it('should parse a PKCS8 private key', function() {
        var curve = curves[name];
        var key = new ECDH(curve.pkcs8);
        expect(key.curve, "curve name").to.equal(name);
        expect(key.toJSON(), "jwk").to.eql(curve.privJwk);
      });

      it('should parse a SPKI public key', function() {
        var curve = curves[name];
        var key = new ECDH(curve.pub);
        expect(key.curve, "curve name").to.equal(name);
        expect(key.toJSON(), "jwk").to.eql(curve.pubJwk);
      });

    });
  })(names[i]);
});
