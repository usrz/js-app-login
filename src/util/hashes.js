'use strict';

const crypto = require('crypto');
const util = require('util');

// WebCrypto->OpenSSL names
var names = {
  "SHA-1" :  "sha1",
  "SHA-256": "sha256",
  "SHA-384": "sha384",
  "SHA-512": "sha512",
};

var bitLengths = {
  "SHA-1" :  160,
  "SHA-256": 256,
  "SHA-384": 384,
  "SHA-512": 512,
}

var byteLengths = {
  "SHA-1" :  20,
  "SHA-256": 32,
  "SHA-384": 48,
  "SHA-512": 64,
}

function normalize(name) {
  if (! util.isString(name)) throw new TypeError('Hash name must be a string');
  var normalized = name.trim().replace(/^sha-?/i, 'SHA-');
  if (! names[normalized]) throw new TypeError('Hash "' + name + '" unknown');
  return normalized;
}

function bits(name) {
  return bitLengths[normalize(name)];
}

function bytes(name) {
  return byteLengths[normalize(name)];
}

function algorithm(name) {
  return names[normalize(name)];
}

function createHash(name) {
  return crypto.createHash(names[normalize(name)]);
}

function createHmac(name, key) {
  return crypto.createHmac(names[normalize(name)], key);
}

exports = module.exports = {
  createHash: createHash,
  createHmac: createHmac,
  normalize: normalize,
  algorithm: algorithm,
  bytes: bytes,
  bits: bits
}
