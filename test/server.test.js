'use strict';

var request = require('request');
var express = require('express')();
var expect = require('chai').expect;
var server = require('../src/server.js');
var client = require('../src/client.js');

describe('Server Test', function() {

  var listener = null;
  var loginurl = null;

  before(function(done) {
    var sessionManager = require('../src/sessionManager')('foobarbaz');
    express.locals.sessionManager = sessionManager;

    express.use('/login', server);
    listener = express.listen(-1, '127.0.0.1', function(error) {
      if (error) done(error);
      var address = listener.address();
      loginurl = 'http://' + address.address + ':' + address.port + '/login';
      done();
    });
  });

  after(function(done) {
    if (listener) listener.close(done);
    else done(new Error("Nothing listening"));
  });

  it('should not respond to GET', function(done) {
    request({ url: loginurl, method: 'get', json: true }, function(err, res, body) {
      if (err) return done(err);
      else try {
        expect(res.statusCode).to.equal(405);
        expect(body.status).to.equal(405);
        expect(body.message).to.equal("Method Not Allowed");
        done();
      } catch (error) {
        done(error);
      }
    });
  });

  it('should respond to a client first', function(done) {
    var cl = client(loginurl);

    cl.clientFirst('test@example.org')
      .then(function(success) {
        return cl.clientProof();
      })
      .then(function(success) {
        done();
      })
      .catch(done);
  });

});
