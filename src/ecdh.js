'use strict';

var base64 = require('./base64');
var crypto = require('crypto');
var util = require('util');

/* ========================================================================== *
 * RFC-4492 - Appendix A - Equivalent Curves (Informative)                    *
 * ========================================================================== *
 *                                                                            *
 * All of the NIST curves [11] and several of the ANSI curves [7] are         *
 * equivalent to curves listed in Section 5.1.1.  In the following            *
 * table, multiple names in one row represent aliases for the same            *
 * curve.                                                                     *
 *                                                                            *
 *          +--------------------------------------------------+              *
 *          |              Curve names chosen by               |              *
 *          |        different standards organizations         |              *
 *          +-----------+------------+------------+------------+              *
 *          |   SECG    | ANSI X9.62 |    NIST    |  OpenSSL   |              *
 *          +-----------+------------+------------+------------+              *
 *          | secp192r1 | prime192v1 | NIST P-192 | prime192v1 |              *
 *          | secp224r1 |            | NIST P-224 | secp224r1  |              *
 *          | secp256r1 | prime256v1 | NIST P-256 | prime256v1 |              *
 *          | secp384r1 |            | NIST P-384 | secp384r1  |              *
 *          | secp521r1 |            | NIST P-521 | secp521r1  |              *
 *          +-----------+------------+------------+------------+              *
 *                                                                            *
 * ========================================================================== */

var curves = {
  'P-192': 'prime192v1',
  'P-224': 'secp224r1',
  'P-256': 'prime256v1',
  'P-384': 'secp384r1',
  'P-521': 'secp521r1',
};

function normalize(curve) {
  if (! util.isString(curve)) throw new TypeError("ECDH Curve Type unspecified or not a string");

  var name = curve.trim().toUpperCase();
  var algorithm = curves[name];
  if (! algorithm) throw new TypeError('Unsupported curve "' + curve + '"');
  return { name: name, algorithm: algorithm };
}

function ECDH(curve) {
  if (!(this instanceof ECDH)) return new ECDH(curve);

  /* Normalize/validate our curve name and OpenSSL algorithm */
  if (util.isObject(curve) && curve.ecdh_curve) curve = curve.ecdh_curve;
  var curve = normalize(curve);

  /* Our ECDH for deriving a shared secret */
  var ecdh = crypto.createECDH(curve.algorithm);
  ecdh.generateKeys();

  /* Request, instrument the public key */
  this.request = function request(object) {
    if (! object) object = {};
    object.ecdh_curve = curve.name;
    object.public_key = base64.encode(ecdh.getPublicKey());
    return object;
  }

  /* Respond, derive the shared secret */
  this.respond = function respond(request) {
    if (! request) throw new TypeError('Must respond to a request');
    if (! util.isString(request.ecdh_curve))
      throw new TypeError('ECDH curve missing or not a string');
    if (! util.isString(request.public_key))
      throw new TypeError('Public Key missing or not a string');

    var requested_curve = normalize(request.ecdh_curve);
    if (curve.name != requested_curve.name) throw new Error('ECDH curves mismatch');

    var public_key = base64.decode(request.public_key);
    var shared_secret = ecdh.computeSecret(public_key);

    return shared_secret;
  }
}

/* Our module exports */
exports = module.exports = {
  curves: Object.keys(curves),
  ECDH: ECDH
};

