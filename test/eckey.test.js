var ECKey = require('../src/eckey');
var expect = require('chai').expect;
var fs = require('fs');

describe('EC Key', function() {

  var re = /-+BEGIN .* KEY-+([\s\S]+)-+END .* KEY-+/m;
  var names = [ 'prime256v1', 'secp384r1', 'secp521r1' ];
  var curves = {};

  before(function() {
    for (var i = 0; i < names.length; i ++) (function(name) {
      curves[name] = {
        // PEM FILES
        pkcs8: fs.readFileSync('./test/eckey/' + name + '.priv-pkcs8.pem', 'utf8'),
        priv: fs.readFileSync('./test/eckey/' + name + '.priv-openssl.pem', 'utf8'),
        pub: fs.readFileSync('./test/eckey/' + name + '.pub.pem', 'utf8'),
        // JWK FILES
        privJwk: JSON.parse(fs.readFileSync('./test/eckey/' + name + '.priv.json', 'utf8')),
        pubJwk: JSON.parse(fs.readFileSync('./test/eckey/' + name + '.pub.json', 'utf8')),
      }
    })(names[i]);
  });

  for (var i = 0; i < names.length; i ++) (function(name) {

    describe('Curve ' + name, function() {

      function testPublicKey(curve, key, name) {
        // Curve name
        expect(key.curve, "curve name").to.equal(name);

        // JWK representation
        expect(key.toJSON(), "jwk").to.eql(curve.pubJwk);

        // Buffer: spki
        expect(key.toBuffer('spki').toString('base64'))
          .to.equal(curve.pub.match(re)[1].replace(/[\s-]/g, ''));

        // Strings: spki normal and url safe
        expect(key.toString('spki'))
          .to.equal(curve.pub.match(re)[1].replace(/[\s-]/g, ''));
        expect(key.toString('spki-urlsafe'))
          .to.equal(curve.pub.match(re)[1].replace(/[\s-]/g, '')
                                          .replace(/\+/g, '-')
                                          .replace(/\//g, '_')
                                          .replace(/=+$/g, ''));
      }

      function testPrivateKey(curve, key, name) {
        // Curve name
        expect(key.curve, "curve name").to.equal(name);

        // JWK representation
        expect(key.toJSON(), "jwk").to.eql(curve.privJwk);

        // Buffers: pkcs8, openssl and spki (public)
        expect(key.toBuffer('pkcs8').toString('base64'))
          .to.equal(curve.pkcs8.match(re)[1].replace(/[\s-]/g, ''));
        expect(key.toBuffer('openssl').toString('base64'))
          .to.equal(curve.priv.match(re)[1].replace(/[\s-]/g, ''));
        expect(key.toBuffer('spki').toString('base64'))
          .to.equal(curve.pub.match(re)[1].replace(/[\s-]/g, ''));

        // Strings: pem, rfc5951 (openssl)
        expect(key.toString('pem')).to.equal(curve.pkcs8);
        expect(key.toString('rfc5915')).to.equal(curve.priv);

        // Strings: pkcs8 and spki (public) normal and url safe
        expect(key.toString('pkcs8'))
          .to.equal(curve.pkcs8.match(re)[1].replace(/[\s-]/g, ''));
        expect(key.toString('spki'))
          .to.equal(curve.pub.match(re)[1].replace(/[\s-]/g, ''));
        expect(key.toString('pkcs8-urlsafe'))
          .to.equal(curve.pkcs8.match(re)[1].replace(/[\s-]/g, '')
                                            .replace(/\+/g, '-')
                                            .replace(/\//g, '_')
                                            .replace(/=+$/g, ''));
        expect(key.toString('spki-urlsafe'))
          .to.equal(curve.pub.match(re)[1].replace(/[\s-]/g, '')
                                          .replace(/\+/g, '-')
                                          .replace(/\//g, '_')
                                          .replace(/=+$/g, ''));

        // Conversion to public key and test
        testPublicKey(curve, key.toPublicECKey(), name);
      }

      /* Run the tests per each source file */

      it('should parse a OpenSSL PEM private key', function() {
        var curve = curves[name];
        var key = new ECKey(curve.priv);
        testPrivateKey(curve, key, name);
      });

      it('should parse a PKCS8 private key', function() {
        var curve = curves[name];
        var key = new ECKey(curve.pkcs8);
        testPrivateKey(curve, key, name);
      });

      it('should parse a JWK private key', function() {
        var curve = curves[name];
        var key = new ECKey(curve.privJwk);
        testPrivateKey(curve, key, name);
      });

      it('should parse a SPKI public key', function() {
        var curve = curves[name];
        var key = new ECKey(curve.pub);
        testPublicKey(curve, key, name);
      });

      it('should parse a JWK public key', function() {
        var curve = curves[name];
        var key = new ECKey(curve.pubJwk);
        testPublicKey(curve, key, name);
      });

    });
  })(names[i]);
});