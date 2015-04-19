'use strict';

var expect = require('chai').expect;
var base64 = require('../src/base64');
var scram = require('../src/scram');
var KDF = require('key-derivation');
var crypto = require('crypto');

describe('SCRAM', function() {

  var password = crypto.randomBytes(32);
  var credentials;

  it('should generate some credentials to store', function(done) {
    this.slow(100);

    var secret = new Buffer(password);
    var store = new scram.Store();

    store.generate(secret).then(function(storable) {
      //console.log("CREDENTIALS", storable, '\n');

      // Check the KDF
      expect(storable.kdf_spec).to.eql(KDF.defaultSpec);

      // Check the keys
      expect(base64.decode(storable.salt).length).to.equal(32);
      expect(base64.decode(storable.shared_key).length).to.equal(32);
      expect(base64.decode(storable.stored_key).length).to.equal(32);
      expect(base64.decode(storable.server_key).length).to.equal(32);

      // Check that we actually have reset the buffer
      expect(Buffer.compare(secret, password)).not.to.equal(0);

      // Remember our credentials
      credentials = storable;
      done();
    })

    .catch(function(err) { done(err) });

  });

  it('should not create a request without subject', function(done) {
    new scram.Client().request()
      .then(function(request) {
        done(request);
      })
      .catch(function(err) {
        expect(err.message).to.equal('Subject not specified or empty');
        done()
      });
  });

  it('should create a request with only a subject', function(done) {
    new scram.Client().request('test@example.org')
      .then(function(request) {
        expect(request).to.eql({
          subject: 'test@example.org'
        });
        done();
      })
      .catch(function(err) { done(err) });
  });

  it('should create a request with a subject and a single audience', function(done) {
    new scram.Client().request('test@example.org', 'audience-1')
      .then(function(request) {
        expect(request).to.eql({
          subject: 'test@example.org',
          audience: 'audience-1'
        });
        done();
      })
      .catch(function(err) { done(err) });
  });

  it('should create a request with a subject and two audiences as arguments', function(done) {
    new scram.Client().request('test@example.org', 'audience-1', 'audience-2')
      .then(function(request) {
        expect(request).to.eql({
          subject: 'test@example.org',
          audience: ['audience-1', 'audience-2']
        });
        done();
      })
      .catch(function(err) { done(err) });
  });

  it('should create a request with a subject and two audiences as an array', function(done) {
    new scram.Client().request('test@example.org', ['audience-1', 'audience-2'])
      .then(function(request) {
        expect(request).to.eql({
          subject: 'test@example.org',
          audience: ['audience-1', 'audience-2']
        });
        done();
      })
      .catch(function(err) { done(err) });
  });


  it('should successfully validate a session', function(done) {
    expect(credentials, "Credentials unavailable").to.exist;
    this.slow(100);

    // Server nonce, verifier for server and updater to check it changes
    var server_nonce = new Buffer(0);
    var client_nonce = new Buffer(0);
    var verifyNonce = function(promise) {
      return promise.then(function(message) {
        if (! message.server_nonce) throw new Error("No server nonce in message");
        var message_nonce = base64.decode(message.server_nonce);
        if (Buffer.compare(message_nonce, server_nonce) == 0) {
          return message;
        } else {
          throw new Error('Server nonce mismatch');
        }
      });
    }
    var updateNonce = function(promise) {
      return promise.then(function(message) {
        if (! message.server_nonce) throw new Error("No server nonce in message");
        var new_nonce = base64.decode(message.server_nonce);
        if (new_nonce.length < 32) throw new Error("New server nonce is too short");
        if (Buffer.compare(new_nonce, server_nonce) != 0) {
          server_nonce = new_nonce;
          return message;
        } else {
          throw new Error('Server nonce not updated');
        }
      });
    }

    function serverNonce(promise) {
      return promise.then(function(message) {

      });
    }




    // Server, client and (cloned) password
    var server = new scram.Server();
    var client = new scram.Client();
    var secret = new Buffer(password);

    // Start with a client simple request
    client.request('test@example.org', 'audience-1', 'audience-2')

      .then(function(request) {
        console.log("CLIENT REQUEST", request, '\n');

        expect(request).to.eql({
          subject: 'test@example.org',
          audience: 'audience-1',
        });

        // Let the server initiate a session from the request
        return updateNonce(server.initiate(credentials, request));
      })

      .then(function(session) {
        console.log("SERVER SESSION", session, '\n');

        // Session must be the same as credentials, minus signed key, plus nonces
        expect(session.server_key).not.to.exist; // <--- NEVER TRANSFER
        expect(session.hash).to.equal(credentials.hash);
        expect(session.salt).to.equal(credentials.salt);
        expect(session.kdf_spec).to.eql(credentials.kdf_spec);
        expect(session.shared_key).to.equal(credentials.shared_key);

        // Let the client respond
        return verifyNonce(client.respond(secret, session));
      })

      .then(function(response) {
        console.log("CLIENT RESPONSE", response, '\n');

        // Make sure that "client.respond()" wiped the password
        expect(Buffer.compare(secret, password)).not.to.equal(0);

        // We must have a proper server and client nonces, and client proof
        // TODO -> expect(base64.decode(response.client_nonce)).to.eql(client_nonce);
        expect(base64.decode(response.server_nonce)).to.eql(server_nonce);
        expect(response.client_proof).to.exist;

        return updateNonce(server.validate(credentials, response));
      })

      .then(function(validation) {
        console.log("SERVER VALIDATION", validation, '\n');

        // TODO -> expect(base64.decode(validation.client_nonce)).to.eql(client_nonce);
        expect(base64.decode(validation.server_nonce)).to.eql(server_nonce);
        expect(validation.server_proof).to.exist;

        return client.verify(validation);

      })

      .then(function(verification) {
        console.log("CLIENT VERIFICATION", verification, '\n');

        expect(verification).to.equal(true);

        done();
      })

      .catch(function(err) { done(err) });
  });

  it('should fail authenticating with the wrong password', function(done) {
    expect(credentials, "Credentials unavailable").to.exist;
    this.slow(100);

    var server = new scram.Server();
    var client = new scram.Client();

    // This is not the right password
    var secret = crypto.randomBytes(32);

    client.request("test@example.org")

      .then(function(request) {
        return server.initiate(credentials, request);
      })

      .then(function(session) {
        return client.respond(secret, session);
      })

      .then(function(response) {
        return server.validate(credentials, response);
      })

      .then(function(validation) {
        done(new Error("Unexpected validation: " + JSON.stringify(validation, null, 2)));
        return client.verify(validation);

      }, function(error) {
        expect(error.message).to.equal('Authentication failure');
        done();
      })

      .catch(function(err) { done(err) });
  });

})

