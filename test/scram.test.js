'use strict';

var request = require('request');
var express = require('express')();
var expect = require('chai').expect;
var server = require('../src/server.js');
var client = require('../src/client.js');

/* Our "backend" for credentials */
var credentials = (function() {
  var stored = {};
  function fetch(subject) { return stored[subject] }
  function store(subject, c) { stored[subject] = c }
  return require('../src/credentials')(fetch, store, { fake_salt: 'shut up!' });
})();

/* Our shared TOTP */
var totp = require('../src/totp/Token')({label: 'Testing'});


describe('SCRAM Login', function() {

  var listener = null;
  var loginurl = null;

  before(function(done) {
    var sessionManager = require('../src/sessionManager')('foobarbaz');
    express.locals.sessionManager = sessionManager;
    express.locals.credentials = credentials;
    express.locals.totp = totp;

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

  it('should authenticate with password and TOTP', function(done) {
    credentials.set('test@example.org', 'password1').then(function() {

      var cl = client(loginurl);

      return cl.clientFirst('test@example.org')
        .then(function(require) {
          expect(require).to.equal('one-time-password');
          return cl.clientProof('password1', totp.compute());
        })
        .then(function(encryption_key) {
          expect(encryption_key).to.be.instanceof(Buffer);
          done();
        })

    })

    .catch(done);
  });

  it('should fail authentication with the wrong password', function(done) {
    credentials.set('test@example.org', 'password2').then(function() {

      var cl = client(loginurl);

      return cl.clientFirst('test@example.org')
        .then(function(require) {
          expect(require).to.equal('one-time-password');
          return cl.clientProof('not a valid password', totp.compute());
        })
        .then(function(encryption_key) {
          done(new Error('Returned encryption key for invalid password'))
        });

    }).catch(function(error) {
      try {
        expect(error).to.be.instanceof(Error);
        expect(error.message).to.equal('Authentication failed');
        done();
      } catch (error) {
        done(error);
      }
    });
  });

  it('should fail authentication with the wrong totp', function(done) {
    credentials.set('test@example.org', 'password3').then(function() {

      var cl = client(loginurl);

      return cl.clientFirst('test@example.org')
        .then(function(require) {
          expect(require).to.equal('one-time-password');
          return cl.clientProof('password3', '000000');
        })
        .then(function(encryption_key) {
          done(new Error('Returned encryption key for invalid totp'))
        });

    }).catch(function(error) {
      try {
        expect(error).to.be.instanceof(Error);
        expect(error.message).to.equal('Authentication failed');
        done();
      } catch (error) {
        done(error);
      }
    });
  });

  it('should fail authentication for an unknown user', function(done) {
    var cl = client(loginurl);

    return cl.clientFirst('unknown@example.org')
      .then(function(require) {
        expect(require).to.equal('one-time-password');
        return cl.clientProof('password', '000000');
      })
      .then(function(encryption_key) {
        done(new Error('Returned encryption key for invalid password'))
      })

      .catch(function(error) {
        try {
          expect(error).to.be.instanceof(Error);
          expect(error.message).to.equal('Authentication failed');
          done();
        } catch (error) {
          done(error);
        }
      });
  });

});
