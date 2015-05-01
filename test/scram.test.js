'use strict';

var request = require('request');
var express = require('express')();
var expect = require('chai').expect;
var server = require('../src/server.js');
var client = require('../src/client.js');

/* Our "backend" for credentials */
var credentials = {};
function fetch(subject) {
  return credentials[subject];
}
function store(subject, c) {
  credentials[subject] = c;
}
var credentialStore = require('../src/credentialStore')(fetch, store);



describe('SCRAM Login', function() {

  var listener = null;
  var loginurl = null;

  before(function(done) {
    var sessionManager = require('../src/sessionManager')('foobarbaz');
    var credentialStore = require('../src/credentialStore')(fetch, store);
    express.locals.sessionManager = sessionManager;
    express.locals.credentialStore = credentialStore;

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
    credentialStore.set('test@example.org', 'password').then(function(credentials) {

      var cl = client(loginurl);

      return cl.clientFirst('test@example.org')
        .then(function(require) {
          expect(require).to.equal('one-time-password');
          // TODO OTP!
          return cl.clientProof('password');
        })
        .then(function(encryption_key) {
          expect(encryption_key).to.be.instanceof(Buffer);
          done();
        })

    })

    .catch(done);
  });

  it('should fail authentication', function(done) {
    credentialStore.set('test@example.org', 'password').then(function(credentials) {

      var cl = client(loginurl);

      return cl.clientFirst('test@example.org')
        .then(function(require) {
          expect(require).to.equal('one-time-password');
          // TODO OTP!
          return cl.clientProof('not a valid password');
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

  it('should fail authentication for an unknown user', function(done) {
    var cl = client(loginurl);

    return cl.clientFirst('unknown@example.org')
      .then(function(require) {
        expect(require).to.equal('one-time-password');
        // TODO OTP!
        return cl.clientProof('password');
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
