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

var ASN1ECPublicKey = asn.define('PublicKey', function() {
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
  throw new Error('Not yet');
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
  var key = ASN1ECPublicKey.decode(buffer, 'der');
  return parsePublicKeyBuffer(key.algorithmIdentifier.parameters, key.publicKey.data);
}

/* ========================================================================== *
 * PEM HANDLING                                                               *
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
 * EXPORTS                                                                    *
 * ========================================================================== */

function ECDH(key) {
  if (util.isString(key)) {
    var k = parsePem(key);
    this.c = k.c;
    this.x = base64.encode(k.x);
    this.y = base64.encode(k.y);
    this.d = k.d ? base64.encode(k.d) : null;
  }
}

exports = module.exports = ECDH;

// private
// --> PEM (BASE64 of PKCS8)
// --> PKCS8 (der)
// --> JWK (kty="EC", crv, d, x, y)
// public
// --> PEM (BASE64 of SPKI)
// --> SPKI (der)
// --> JWK (kty="EC", crv, x, y)
//
