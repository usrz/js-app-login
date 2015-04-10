'use strict';

var expect = require('chai').expect;
var scram = require('../src/scram');
var crypto = require('crypto');

describe('SCRAM', function() {

  var signing_key = crypto.randomBytes(32);

  it('should generate', function(done) {
    this.slow(300);

    var secret = new Buffer('password', 'utf8');
    var server = new scram.Server({signing_key: signing_key});
    var client = new scram.Client();

    var stored_credentials = null;

    server.generate(new Buffer(secret))

      .then(function(credentials) {
        console.log("CREDENTIALS", credentials);

        stored_credentials = credentials;

        return client.request();
      })

      .then(function(request) {
        console.log("REQUEST", request);
        return server.initiate(stored_credentials, request);
      })

      .then(function(session) {
        console.log("SESSION", session);
        return client.respond(new Buffer(secret), session);
      })

      .then(function(response) {
        console.log("RESPONSE", response);
        return server.validate(response, stored_credentials);
//        return client.respond(new Buffer(secret), session);
      })



      .then(function(success) {
        console.log('SUCCESS', success);
        done();
      }, function(failure) {
        console.log('FAILURE', failure);
        done(failure);
      });
  });
})

