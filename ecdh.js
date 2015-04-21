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

var ASN1ECOpenSSLKey = asn.define('OpenSSLKey', function() {
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
      this.key('publicKeyType').objid({
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
  var privateKeyWrapper = ASN1ECOpenSSLKey.decode(key.privateKey, 'der');
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

function parseOpenSSL(buffer) {
  var key = ASN1ECOpenSSLKey.decode(buffer, 'der');
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

var pemOpenSSLRE = /-+BEGIN EC PRIVATE KEY-+([\s\S]+)-+END EC PRIVATE KEY-+/m;
var pemPkcs8RE   = /-+BEGIN PRIVATE KEY-+([\s\S]*)-+END PRIVATE KEY-+/m;
var pemSpkiRE    = /-+BEGIN PUBLIC KEY-+([\s\S]*)-+END PUBLIC KEY-+/m;

function parsePem(pem) {
  if (! util.isString(pem)) throw new TypeError("PEM must be a string");

  var match = null;
  if (match = pem.match(pemOpenSSLRE)) {
    var buffer = new Buffer(match[1].replace(/\s/mg, ''), 'base64');
    return parseOpenSSL(buffer);

  } else if (match = pem.match(pemPkcs8RE)) {
    var buffer = new Buffer(match[1].replace(/\s/mg, ''), 'base64');
    return parsePkcs8(buffer);

  } else if (match = pem.match(pemSpkiRE)) {
    var buffer = new Buffer(match[1].replace(/\s/mg, ''), 'base64');
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
  var curve, privateKey, publicKey, x, y;

  if (util.isString(key)) {
    var k = parsePem(key);
    curve = k.c;
    x = k.x;
    y = k.y;
    privateKey = k.d;
    publicKey = Buffer.concat([new Buffer([0x04]), x, y]);
  } else {
    throw new TypeError('Unrecognized format for EC key');
  }

  Object.defineProperties(this, {
    'curve': {
      enumerable: true,
      configurable: false,
      value: curve
    },
    'publicKey': {
      enumerable: true,
      configurable: false, get:
      function() {
        return new Buffer(publicKey)
      }
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

  if (privateKey) Object.defineProperty(this, 'privateKey', {
    enumerable: true,
    configurable: false,
    get: function() {
      return new Buffer(privateKey)
    }
  });
}

ECDH.prototype.toJSON = function() {
  var jwk = {
    kty: "EC",
    crv: jwkCurves[this.curve],
    x: base64.encode(this.x),
    y: base64.encode(this.y),
  };

  var privateKey = this.privateKey;
  if (privateKey) jwk.d = base64.encode(privateKey);

  return jwk;
}


/* ========================================================================== *
 * EXPORTS                                                                    *
 * ========================================================================== */

exports = module.exports = ECDH;

