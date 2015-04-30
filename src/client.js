'use strict';

const Promise = global.Promise || require('promise');
const request = require('request');
const base64 = require('./util/base64');
const ECKey = require('./eckey');
const e = require('./util/errors');
const util = require('util');
const url = require('url');

const CURVE = "P-256";

function Client(login_url, curve) {
  if (!(this instanceof Client)) return new Client(login_url, curve);

  if (! login_url) throw new TypeError('No login URL specified');
  if (! util.isString(login_url)) throw new TypeError('Login URL must be a string');

  // Normalize curve
  if (! curve) curve = CURVE;

  // Initial client data
  var self = this;
  var ecdhe_key = ECKey.createECKey(curve);
  var client_first = null;
  var server_first = null;
  var session_url = null;

  /* ======================================================================== *
   * Client First                                                             *
   * ======================================================================== */
  this.clientFirst = function clientFirst(subject) {

    return new Promise(function(resolve, reject) {
      if (! subject) throw new TypeError('No subject specified');
      if (! util.isString(subject)) throw new TypeError('Subject must be a string');

      client_first = base64.encode(new Buffer(JSON.stringify({
        public_key: ecdhe_key.toString('spki-urlsafe'),
        subject: subject
      }), 'utf8'));

      var message = {
        url: login_url,
        method: 'POST',
        json: true,
        body: { client_first: client_first }
      }

      request(message, function(err, res, body) {
        if (err) return reject(err);

        if (res.statusCode != 201) reject(e.fromStatus(res.statusCode));

        var location = res.headers.location;
        if (! location) throw new Error("Unable to determine session location");
        session_url = url.resolve(login_url, location);
        server_first = body.server_first; // TODO validate

        return resolve(body);
      });
    });
  }

  /* ======================================================================== *
   * Client Proof                                                             *
   * ======================================================================== */

  this.clientProof = function(subject) {
    return new Promise(function(resolve, reject) {

      var message = {
        url: session_url, // TODO validate
        method: 'POST',
        json: true,
        body: {
          client_first: client_first,
          server_first: server_first,
          client_final: 'foobarabaz'
        }
      }

      request(message, function(err, res, body) {
        if (err) return reject(err);

        //if (res.statusCode != 201) reject(e.fromStatus(res.statusCode));

        //var location = res.headers.location;
        //if (! location) throw new Error("Unable to determine session location");
        //data.session_url = url.resolve(data.login_url, location);

        return resolve(body);
      });

    });
  }
}


exports = module.exports = Client;
