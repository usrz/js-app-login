var ECKey = require('../src/eckey');
var expect = require('chai').expect;
var fs = require('fs');

describe.only('EC Key', function() {

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

  describe('Others', function() {

    it('should create a key with an OpenSSL curve name', function() {
      var key = ECKey.create('secp521r1');
      expect(key.curve).to.equal('secp521r1');
      expect(key.d).to.be.instanceof(Buffer);
      expect(key.x).to.be.instanceof(Buffer);
      expect(key.y).to.be.instanceof(Buffer);
      expect(key.d.length).to.be.lt(67); // might be 65, 64, ...
      expect(key.x.length).to.be.equal(66);
      expect(key.y.length).to.be.equal(66);
    });

    it('should create a key with a JWK/NIST curve name', function() {
      var key = ECKey.create('P-256');
      expect(key.curve).to.equal('prime256v1');
      expect(key.d).to.be.instanceof(Buffer);
      expect(key.x).to.be.instanceof(Buffer);
      expect(key.y).to.be.instanceof(Buffer);
      expect(key.d.length).to.be.lt(33);
      expect(key.x.length).to.be.equal(32);
      expect(key.y.length).to.be.equal(32);
    });

    it('should not create a key with an unknown curve name', function() {
      expect(function() { ECKey.create('gonzo') }).to.throw('Invalid/unknown curve "gonzo"');
    });

    it('should create a couple of ECDH and negotiate a secret from existing keys', function() {
      var key1 = new ECKey(fs.readFileSync('./test/eckey/ecdh1.pem', 'utf8'));
      var key2 = new ECKey(fs.readFileSync('./test/eckey/ecdh1.pem', 'utf8'));
      var ecdh1 = key1.createECDH();
      var ecdh2 = key2.createECDH();
      // Use code points (we test keys below)
      var secret1 = ecdh1.computeSecret(key2.publicCodePoint);
      var secret2 = ecdh2.computeSecret(key1.publicCodePoint);
      // HEX to display errors in a sane way
      expect(secret1.toString('hex')).to.equal('620dee6f38472543ff87459fa37bc8cf9c04337aff5652327fe0ddfac88c715a');
      expect(secret2.toString('hex')).to.equal('620dee6f38472543ff87459fa37bc8cf9c04337aff5652327fe0ddfac88c715a');
    });

    it('should create a couple of ECDH and negotiate a secret from random keys', function() {
      var key1 = new ECKey.create('P-521');
      var key2 = new ECKey.create('P-521');
      var ecdh1 = key1.createECDH();
      var ecdh2 = key2.createECDH();
      // Use keys (we test code points above)
      var secret1 = ecdh1.computeSecret(key2);
      var secret2 = ecdh2.computeSecret(key1);
      // HEX to display errors in a sane way
      expect(secret1.toString('hex')).to.eql(secret2.toString('hex'));
    });

  });
});
