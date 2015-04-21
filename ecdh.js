var crypto = require('crypto');
var asn = require('asn1.js');
var util = require('util');
var base64 = require('./src/base64');

/* ========================================================================== *
 * From RFC-4492 (Appendix A) Equivalent Curves (Informative)                 *
 * ========================================================================== *
 *                                                                            *
 * +------------------------------------------------------------------------+ *
 * |                         Curve names chosen by                          | *
 * |                   different standards organizations                    | *
 * +-----------+------------+------------+------------+---------------------+ *
 * |   SECG    | ANSI X9.62 |    NIST    |  OpenSSL   |      ASN.1 OID      | *
 * +-----------+------------+------------+------------+---------------------+ *
 * | secp256r1 | prime256v1 | NIST P-256 | prime256v1 | 1.2.840.10045.3.1.7 | *
 * | secp384r1 |            | NIST P-384 | secp384r1  | 1.3.132.0.34        | *
 * | secp521r1 |            | NIST P-521 | secp521r1  | 1.3.132.0.35        | *
 * +-----------+------------+------------+------------+---------------------+ *
 * ========================================================================== */

/* Byte lengths for validation */
var lengths = {
  prime256v1 : Math.ceil(256 / 8),
   secp384r1 : Math.ceil(384 / 8),
   secp521r1 : Math.ceil(521 / 8),
}

/* JWK curve names */
var jwkCurves = {
  prime256v1 : 'P-256',
   secp384r1 : 'P-384',
   secp521r1 : 'P-521',
}

/* OpenSSL curve names */
var curves = {
 'P-256' : 'prime256v1',
 'P-384' : 'secp384r1',
 'P-521' : 'secp521r1',
}

/* ========================================================================== *
 * ASN.1                                                                      *
 * ========================================================================== */

var ASN1ECRfc5915Key = asn.define('Rfc5915Key', function() {
  this.seq().obj(
    this.key('version').int(),
    this.key('privateKey').octstr(),
    this.key('parameters').optional().explicit(0).objid({
      '1 2 840 10045 3 1 7' : 'prime256v1',
      '1 3 132 0 34'        : 'secp384r1',
      '1 3 132 0 35'        : 'secp521r1',
    }),
    this.key('publicKey').optional().explicit(1).bitstr()
  );
});

var ASN1ECPkcs8Key = asn.define('Pkcs8Key', function() {
  this.seq().obj(
    this.key('version').int(),
    this.key('algorithmIdentifier').seq().obj(
      this.key('privateKeyType').objid({
        '1 2 840 10045 2 1': 'EC'
      }),
      this.key('parameters').objid({
        '1 2 840 10045 3 1 7' : 'prime256v1',
        '1 3 132 0 34'        : 'secp384r1',
        '1 3 132 0 35'        : 'secp521r1',
      })
    ),
    this.key('privateKey').octstr()
  );
});


var ASN1ECSpkiKey = asn.define('SpkiKey', function() {
  this.seq().obj(
    this.key('algorithmIdentifier').seq().obj(
      this.key('publicKeyType').objid({
        '1 2 840 10045 2 1': 'EC'
      }),
      this.key('parameters').objid({
        '1 2 840 10045 3 1 7' : 'prime256v1',
        '1 3 132 0 34'        : 'secp384r1',
        '1 3 132 0 35'        : 'secp521r1',
      })
    ),
    this.key('publicKey').bitstr()
  );
});

/* ========================================================================== *
 * ASN.1 PARSING                                                              *
 * ========================================================================== */

/* Parse a public key buffer, split X and Y */
function parsePublicKeyBuffer(curve, buffer) {
  var bytes = lengths[curve];
  if (buffer[0] == 4) {
    if (buffer.length != ((bytes * 2) + 1)) throw new TypeError('Invalid uncompressed key size');
    return {
      c: curve,
      x: buffer.slice(1, bytes + 1),
      y: buffer.slice(bytes + 1),
    }
  } else {
    throw new TypeError("Compressed key unsupported");
  }
}

/* Parse PKCS8 from RFC 5208 */
function parsePkcs8(buffer) {
  var key = ASN1ECPkcs8Key.decode(buffer, 'der');
  var privateKeyWrapper = ASN1ECRfc5915Key.decode(key.privateKey, 'der');
  var curve = key.algorithmIdentifier.parameters;
  var bytes = lengths[curve];

  var privateKey = privateKeyWrapper.privateKey;
  if (privateKey.length < bytes) {
    var remaining = bytes - privateKey.length;
    privateKey = Buffer.concat([new Buffer(remaining).fill(0), privateKey]);

  } else if (privateKey.length > bytes) {
    throw new TypeError('Invalid private key size: expected ' + bytes + ' gotten ' + privateKey.length);
  }

  var components = parsePublicKeyBuffer(curve, privateKeyWrapper.publicKey.data);
  components.d = privateKey;
  return components;
}

/* Parse EC from RFC 5915 */
function parseRfc5915(buffer) {
  var key = ASN1ECRfc5915Key.decode(buffer, 'der');
  var bytes = lengths[key.parameters];

  var privateKey = key.privateKey;
  if (privateKey.length < bytes) {
    var remaining = bytes - privateKey.length;
    privateKey = Buffer.concat([new Buffer(remaining).fill(0), privateKey]);

  } else if (privateKey.length > bytes) {
    throw new TypeError('Invalid private key size: expected ' + bytes + ' gotten ' + privateKey.length);
  }

  var components = parsePublicKeyBuffer(key.parameters, key.publicKey.data);
  components.d = privateKey;
  return components;
}

/* Parse SPKI from RFC 5280 */
function parseSpki(buffer) {
  var key = ASN1ECSpkiKey.decode(buffer, 'der');
  return parsePublicKeyBuffer(key.algorithmIdentifier.parameters, key.publicKey.data);
}

/* ========================================================================== *
 * PEM PARSING                                                                *
 * ========================================================================== */

var pemRfc5915RE = /-+BEGIN EC PRIVATE KEY-+([\s\S]+)-+END EC PRIVATE KEY-+/m;
var pemPkcs8RE   = /-+BEGIN PRIVATE KEY-+([\s\S]*)-+END PRIVATE KEY-+/m;
var pemSpkiRE    = /-+BEGIN PUBLIC KEY-+([\s\S]*)-+END PUBLIC KEY-+/m;

function parsePem(pem) {
  if (! util.isString(pem)) throw new TypeError("PEM must be a string");

  var match = null;
  if (match = pem.match(pemRfc5915RE)) {
    var buffer = new Buffer(match[1].replace(/[\s-]/mg, ''), 'base64');
    return parseRfc5915(buffer);

  } else if (match = pem.match(pemPkcs8RE)) {
    var buffer = new Buffer(match[1].replace(/[\s-]/mg, ''), 'base64');
    return parsePkcs8(buffer);

  } else if (match = pem.match(pemSpkiRE)) {
    var buffer = new Buffer(match[1].replace(/[\s-]/mg, ''), 'base64');
    return parseSpki(buffer);

  } else {
    console.log(pem);
    throw new TypeError('Unrecognized PEM key structure');
  }
}

/* ========================================================================== *
 * CLASS DEFINITION                                                           *
 * ========================================================================== */

function ECDH(key) {
  var curve, d, x, y;

  if (util.isString(key)) {
    var k = parsePem(key);
    curve = k.c;
    x = k.x;
    y = k.y;
    d = k.d;
  } else if (util.isObject(key)) {
    // Curves
    if (util.isString(key.curve)) {
      curve = key.curve;
    } else if (util.isString(key.crv)) {
      curve = curves[key.crv] || key.crv;
    }

    // Private key or "d"
    if (util.isBuffer(key.privateKey)) {
      d = key.privateKey;
    } else if (util.isString(key.privateKey)) {
      d = base64.decode(key.privateKey);
    } else if (util.isBuffer(key.d)) {
      d = key.d;
    } else if (util.isString(key.d)) {
      d = base64.decode(key.d);
    }

    // Public key, or x and y
    if (util.isBuffer(key.publicKey)) {
      var k = parsePublicKeyBuffer(curve, key.publicKey);
      x = k.x;
      y = k.y;

    } else if (util.isString(key.publicKey)) {
      var k = parsePublicKeyBuffer(curve, base64.decode(key.publicKey));
      x = k.x;
      y = k.y;

    } else {
      // Need to get x and y
      if (util.isBuffer(key.x)) {
        x = key.x;
      } else if (util.isString(key.x)) {
        x = base64.decode(key.x);
      }

      if (util.isBuffer(key.y)) {
        y = key.y;
      } else if (util.isString(key.y)) {
        y = base64.decode(key.y);
      }
    }

  } else {
    throw new TypeError('Unrecognized format for EC key');
  }

  // Validate curve, d, x and y
  if (! curve) throw new TypeError("EC Key curve not specified");
  if ((! x) || (! y)) throw new TypeError("Public EC Key point unavailable");

  var length = lengths[curve];
  if (! length) throw new TypeError("EC Key curve \"" + curve + "\" invalid");
  if (x.length != length) throw new TypeError("Public EC Key point X of wrong length");
  if (y.length != length) throw new TypeError("Public EC Key point Y of wrong length");
  if (d && (y.length != length)) throw new TypeError("Private EC Key of wrong length");

  // Define our properties
  Object.defineProperties(this, {
    'curve': {
      enumerable: true,
      configurable: false,
      value: curve
    },
    'isPrivateECKey': {
      enumerable: true,
      configurable: false,
      value: (d != null)
    },
    'x': {
      enumerable: true,
      configurable: false,
      get: function() {
        return new Buffer(x)
      }
    },
    'y': {
      enumerable: true,
      configurable: false,
      get: function() {
        return new Buffer(y)
      }
    },
  });

  // The "d" (private key) is optional
  if (d) Object.defineProperty(this, 'd', {
    enumerable: true,
    configurable: false,
    get: function() {
      return new Buffer(d)
    }
  });
}

/* ========================================================================== *
 * CONVERSION                                                                 *
 * ========================================================================== */

ECDH.prototype.toPublicECKey = function() {
  if (! this.isPrivateECKey) return this;
  return new ECDH({
    curve: this.curve,
    x: this.x,
    y: this.y
  });
}

ECDH.prototype.toBuffer = function(format) {
  if (this.isPrivateECKey) {
    // Strip leading zeroes from private key
    var d = this.d;
    while (d[0] == 0) d = d.slice(1);

    // Known formats: "pkcs8" (default), "pem", "openssl"
    if (! format) format = "pkcs8";
    if ((format == "pkcs8") || (format == "rfc5208")) {

      // Encode in PKCS8
      return ASN1ECPkcs8Key.encode({
        version: 0,
        algorithmIdentifier: {
          privateKeyType: 'EC',
          parameters: this.curve,
        },
        // Private key is RFC5915 minus curve
        privateKey: ASN1ECRfc5915Key.encode({
          version: 1,
          privateKey: d,
          publicKey: { data: Buffer.concat([new Buffer([0x04]), this.x, this.y]) }
        }, 'der')
      }, 'der');

    } else if ((format == "openssl") || (format == "rfc5915")) {

      // Simply encode in ASN.1
      return ASN1ECRfc5915Key.encode({
        version: 1,
        privateKey: d,
        parameters: this.curve,
        publicKey: { data: Buffer.concat([new Buffer([0x04]), this.x, this.y]) }
      }, 'der');

    } else if ((format == "spki") || (format == "rfc5280")) {
      return this.toPublicECKey().toBuffer("spki");

    } else {
      throw new TypeError("Unknown format for private key \"" + format + "\"");
    }

  } else {

    if (! format) format = "spki";
    if ((format == "spki") || (format == "rfc5280")) {
      return ASN1ECSpkiKey.encode({
        algorithmIdentifier: {
          publicKeyType: 'EC',
          parameters: this.curve
        },
        publicKey: { data: Buffer.concat([new Buffer([0x04]), this.x, this.y]) }
      }, 'der');

    } else {
      throw new TypeError("Unknown format for public key \"" + format + "\"");
    }
  }
}

ECDH.prototype.toString = function(format) {
  if (this.isPrivateECKey) {
    if (! format) format = "pem";
    if (format == "pem") { // pkcs8, wrapped
      return '-----BEGIN PRIVATE KEY-----\n'
           + this.toBuffer('pkcs8').toString('base64').match(/.{1,64}/g).join('\n')
           + '\n-----END PRIVATE KEY-----\n';

    } else if (format == "rfc5915") { // rfc5915, wrapped
      return '-----BEGIN EC PRIVATE KEY-----\n'
           + this.toBuffer('rfc5915').toString('base64').match(/.{1,64}/g).join('\n')
           + '\n-----END EC PRIVATE KEY-----\n';

    } else if ((format == "pkcs8") || (format == "rfc5208")) {
      return this.toBuffer('pkcs8').toString('base64');

    } else if ((format == "pkcs8-urlsafe") || (format == "rfc5208-urlsafe")) {
      return base64.encode(this.toBuffer('pkcs8'));

    } else if ((format == "spki") || (format == "rfc5280")) {
      return this.toBuffer('spki').toString('base64');

    } else if ((format == "spki-urlsafe") || (format == "rfc5280-urlsafe")) {
      return base64.encode(this.toBuffer('spki'));

    } else {
      throw new TypeError("Unknown format for private key \"" + format + "\"");
    }

  } else {
    if ((format == "spki") || (format == "rfc5280")) {
      return this.toBuffer('spki').toString('base64');

    } else if ((format == "spki-urlsafe") || (format == "rfc5280-urlsafe")) {
      return base64.encode(this.toBuffer('spki'));

    } else {
      throw new TypeError("Unknown format for public key \"" + format + "\"");
    }
  }
}

ECDH.prototype.toJSON = function() {
  var jwk = {
    kty: "EC",
    crv: jwkCurves[this.curve],
    x: base64.encode(this.x),
    y: base64.encode(this.y),
  };

  var d = this.d;
  if (d) jwk.d = base64.encode(d);

  return jwk;
}


/* ========================================================================== *
 * EXPORTS                                                                    *
 * ========================================================================== */

exports = module.exports = ECDH;

