'use strict';

/* ========================================================================== *
 * INTERACTION BETWEEN ECDH CURVES AND AES ALGORITHMS                         *
 * ========================================================================== *
 *                                                                            *
 * We derive our encryption secret passing around a couple of EC public keys  *
 * (Diffie-Hellman FTW), so here is a quick reminder of what curves actually  *
 * do work with which encryption algorithm.                                   *
 *                                                                            *
 * Note that we use AES (CBC a-la JWE or GCM) only, with three key sizes.     *
 *                                                                            *
 * +---------------+----------------+-------+-------+-------+-------+-------+ *
 * | Algorighm     | Key Size, Bits | P-192 | P-224 | P-256 | P-384 | P-521 | *
 * +---------------+----------------+-------+-------+-------+-------+-------+ *
 * | A128GCM       |       128      | Trunc | Trunc | Trunc | Trunc | Trunc | *
 * | A192GCM       |       192      | Exact | Trunc | Trunc | Trunc | Trunc | *
 * | A256GCM       |       256      |       |       | Exact | Trunc | Trunc | *
 * | A128CBC-HS256 |       256      |       |       | Exact | Trunc | Trunc | *
 * | A192CBC-HS384 |       384      |       |       |       | Exact | Trunc | *
 * | A256CBC-HS512 |       512      |       |       |       |       | Trunc | *
 * +---------------+----------------+-------+-------+-------+-------+-------+ *
 *                                                                            *
 * ========================================================================== */

var base64 = require('../util/base64');
var crypto = require('crypto');
var util = require('util');

/* ========================================================================== */

function key(k, len) {
  if (! util.isBuffer(k)) throw new Error('Key unavailable or not a buffer');
  if (k.length == len) return k; // unchanged if precise
  if (k.length > len) return k.slice(0, len);
  throw new TypeError("Key must be at least " + len + " bytes");
}

function vector(iv, len, create) {
  if (util.isBuffer(iv)) {
    if (iv.length == len) return iv;
  } else if (create) {
    return crypto.randomBytes(len);
  }

  throw new TypeError('Initialization vectory must be precisely ' + len + ' bytes');
}

/* ========================================================================== */
/* WRAPPER AROUND AES CBC ADDING AUTHENTICATION                               */
/* ========================================================================== */

function enc_cbc(alg, sha, len, k, p, a, iv) {
  k = key(k, len);
  iv = vector(iv, 16, true);

  var mac_key = k.slice(0, k.length / 2);
  var enc_key = k.slice(k.length / 2);;

  var cipher = crypto.createCipheriv(alg, enc_key, iv);
  cipher.write(p);
  cipher.end();
  var e = cipher.read();

  if (! a) a = new Buffer(0);
  var al = new Buffer(8).fill(0);
  al.writeUInt32BE(a.length * 8, 4);

  var t = crypto.createHmac(sha, mac_key)
                .update(a)
                .update(iv)
                .update(e)
                .update(al)
                .digest()
                .slice(0, k.length / 2);

  return({
    ciphertext: base64.encode(e),
    tag: base64.encode(t),
    iv: base64.encode(iv)
  });

}

function dec_cbc(alg, sha, len, k, e, t, iv, a) {
  k = key(k, len);
  iv = vector(iv, 16, false);

  var mac_key = k.slice(0, k.length / 2);
  var enc_key = k.slice(k.length / 2);;

  if (! a) a = new Buffer(0);
  var al = new Buffer(8).fill(0);
  al.writeUInt32BE(a.length * 8, 4);

  var tx = crypto.createHmac(sha, mac_key)
                .update(a)
                .update(iv)
                .update(e)
                .update(al)
                .digest()
                .slice(0, k.length / 2);

  if (Buffer.compare(t, tx) != 0) throw new Error("Authentication encryption failure");

  var cipher = crypto.createDecipheriv(alg, enc_key, iv);
  cipher.write(e);
  cipher.end();
  var d = cipher.read();

  return d;
}

/* ========================================================================== */
/* WRAPPER AROUND AES GCM                                                     */
/* ========================================================================== */

function enc_gcm(alg, sha, len, k, p, a, iv) {
  k = key(k, len);
  iv = vector(iv, 12, true);

  var cipher = crypto.createCipheriv(alg, k, iv);
  if (a != null) cipher.setAAD(a);

  cipher.write(p);
  cipher.end();

  var e = cipher.read();

  return({
    ciphertext: base64.encode(e),
    tag: base64.encode(cipher.getAuthTag()),
    iv: base64.encode(iv)
  });

}

function dec_gcm(alg, sha, len, k, e, t, iv, a) {
  k = key(k, len);
  iv = vector(iv, 12, false);

  var cipher = crypto.createDecipheriv(alg, k, iv);
  if (a != null) cipher.setAAD(a);
  cipher.setAuthTag(t);

  cipher.write(e);
  cipher.end();
  var d = cipher.read();

  return d;

}

/* ========================================================================== */
/* CIPHER WRAPPER                                                             */
/* ========================================================================== */

function Cipher(algorithm) {
  if (!(this instanceof Cipher)) return new Cipher(algorithm);

  if (!util.isString(algorithm)) throw new TypeError("Algorithm must be a string");
  algorithm = algorithm.toUpperCase();

  var enc, dec, alg, sha, len;
  switch (algorithm) {
    case 'A128CBC-HS256': enc = enc_cbc; dec = dec_cbc, alg = 'aes-128-cbc', sha = 'sha256'; len = 32; break;
    case 'A192CBC-HS384': enc = enc_cbc; dec = dec_cbc, alg = 'aes-192-cbc', sha = 'sha384'; len = 48; break;
    case 'A256CBC-HS512': enc = enc_cbc; dec = dec_cbc, alg = 'aes-256-cbc', sha = 'sha512'; len = 64; break;
    case 'A128GCM':       enc = enc_gcm; dec = dec_gcm, alg = 'aes-128-gcm',                 len = 16; break;
    case 'A192GCM':       enc = enc_gcm; dec = dec_gcm, alg = 'aes-192-gcm',                 len = 24; break;
    case 'A256GCM':       enc = enc_gcm; dec = dec_gcm, alg = 'aes-256-gcm',                 len = 32; break;
    default: throw new TypeError('Unsupported algorithm "' + algorithm + '"');
  }

  this.encrypt = function(encryption_key, plain_text, auth_data, initialization_vector) {
    if (! util.isBuffer(encryption_key)) throw new TypeError('Encryption key is not a buffer');
    if (! util.isBuffer(plain_text)) throw new TypeError('Data to encrypt is not a buffer');

    if (auth_data && (! util.isBuffer(auth_data))) {
      throw new TypeError("Authentication data is not a buffer");
    }

    if (initialization_vector && (! util.isBuffer(initialization_vector))) {
      throw new TypeError("Initialization Vector is not a buffer");
    }

    var encrypted_data = enc(alg, sha, len,
                             encryption_key,
                             plain_text,
                             auth_data,
                             initialization_vector);
    encrypted_data.enc = algorithm;
    return encrypted_data;
  }

  this.decrypt = function(encryption_key, encrypted_data, auth_data) {
    if (! util.isBuffer(encryption_key)) throw new TypeError('Encryption key is not a buffer');
    if (! util.isObject(encrypted_data)) throw new TypeError('Encrypted data is not a valid object');
    if (! util.isString(encrypted_data.ciphertext)) throw new TypeError('Invalid ciphertext');
    if (! util.isString(encrypted_data.tag)) throw new TypeError('Invalid authentication tag');
    if (! util.isString(encrypted_data.iv)) throw new TypeError('Invalid Initialization Vector');

    if (auth_data && (! util.isBuffer(auth_data))) {
      throw new TypeError("Authentication data is not a buffer");
    }

    return dec(alg, sha, len,
               encryption_key,
               base64.decode(encrypted_data.ciphertext),
               base64.decode(encrypted_data.tag),
               base64.decode(encrypted_data.iv),
               auth_data);
  }

}

exports = module.exports = Cipher;
