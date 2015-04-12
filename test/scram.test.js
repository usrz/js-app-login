'use strict';

var expect = require('chai').expect;
var base64 = require('../src/base64');
var scram = require('../src/scram');
var KDF = require('key-derivation');
var crypto = require('crypto');
var ursa = require('ursa');

describe('SCRAM', function() {

  var password;
  var store_key;
  var private_key;
  var public_key;
  var public_key2;
  var credentials;

  before(function() {
    var key     = ursa.generatePrivateKey(512);
    private_key = key.toPrivatePem().toString();
    public_key  = key.toPublicPem().toString();
    store_key   = crypto.randomBytes(32);
    password    = crypto.randomBytes(32);
  });

  it('should generate some credentials to store', function(done) {
    this.slow(100);

    var secret = new Buffer(password);
    var store = new scram.Store({store_key: store_key});

    store.generate(secret).then(function(storable) {

      // Check the KDF
      expect(storable.kdf_spec).to.eql(KDF.defaultSpec);

      // Check the keys
      expect(base64.decode(storable.salt).length).to.equal(32);
      expect(base64.decode(storable.shared_key).length).to.equal(32);
      expect(base64.decode(storable.stored_key).length).to.equal(32);
      expect(base64.decode(storable.signed_key).length).to.equal(32);

      // Check that we actually have reset the buffer
      expect(Buffer.compare(secret, password)).not.to.equal(0);

      // Remember our credentials
      //console.log("CREDENTIALS", storable, '\n');
      credentials = storable;
      done();
    })

    .catch(function(err) { done(err) });

  });

  it('should successfully validate a session', function(done) {
    expect(credentials, "Credentials unavailable").to.exist;
    this.slow(100);

    var server = new scram.Server({private_key: private_key});
    var client = new scram.Client({public_key: public_key, store_key: store_key});

    // Clone the password buffer
    var secret = new Buffer(password);

    // Things to validate along the way
    var client_nonce;
    var server_nonce;

    client.request()

      .then(function(request) {
        console.log("REQUEST", request, '\n');

        client_nonce = base64.decode(request.client_nonce);
        expect(client_nonce.length).to.equal(32);

        return server.initiate(credentials, request);
      })

      .then(function(session) {
        console.log("SESSION", session, '\n');

        // Session must be the same as credentials, minus signed key, plus nonces
        expect(session.signed_key).not.to.exist;

        expect(session.hash).to.equal(credentials.hash);
        expect(session.salt).to.equal(credentials.salt);
        expect(session.kdf_spec).to.eql(credentials.kdf_spec);
        expect(session.shared_key).to.equal(credentials.shared_key);

        server_nonce = base64.decode(session.server_nonce);
        expect(server_nonce.length).to.equal(32);

        expect(base64.decode(session.client_nonce)).to.eql(client_nonce);

        return client.respond(secret, session);
      })

      .then(function(response) {
        console.log("RESPONSE", response, '\n');

        // Make sure that "client.respond()" wiped the password
        expect(Buffer.compare(secret, password)).not.to.equal(0);

        // We must have a proper server and client nonces, and client proof
        expect(base64.decode(response.client_nonce)).to.eql(client_nonce);
        expect(base64.decode(response.server_nonce)).to.eql(server_nonce);
        expect(response.client_proof).to.exist;

        return server.validate(credentials, response);
      })

      .then(function(validation) {
        console.log("VALIDATION", validation, '\n');

        expect(validation.hash).to.equal(credentials.hash);
        expect(base64.decode(validation.client_nonce)).to.eql(client_nonce);
        expect(base64.decode(validation.server_nonce)).to.eql(server_nonce);
        expect(validation.server_proof).to.exist;

        return client.replace(validation, new Buffer('newpassword'));

      })

      .then(function(verification) {
        console.log("VERIFICATION", verification, '\n');
        var updated = server.update(credentials, verification);
        console.log('UPDATED', updated.toString());

        expect(updated.toString()).to.equal('newpassword');

        done();
      })

      .catch(function(err) { done(err) });
  });

  it('should fail authenticating with the wrong password', function(done) {
    expect(credentials, "Credentials unavailable").to.exist;
    this.slow(100);

    var server = new scram.Server({private_key: private_key});
    var client = new scram.Client();

    // This is not the right password
    var secret = crypto.randomBytes(32);

    client.request()

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

      }, function(error) {
        expect(error.message).to.equal('Authentication failure');
        done();
      })

      .catch(function(err) { done(err) });
  });

  it('should fail validating with the wrong public key', function(done) {
    expect(credentials, "Credentials unavailable").to.exist;
    this.slow(100);

    // Validate against the wrong public key
    var wrong_public_key = ursa.generatePrivateKey(512).toPublicPem().toString();

    var server = new scram.Server({private_key: private_key});
    var client = new scram.Client({public_key: wrong_public_key, store_key: store_key});

    // The password is correct!
    var secret = new Buffer(password);

    client.request()

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
        return client.verify(validation);
      })

      .then(function(verification) {
        done(new Error("Unexpected verification: " + JSON.stringify(verification, null, 2)));
      }, function(error) {
        expect(error).to.be.instanceof(Error);
        done();
      })

      .catch(function(err) { done(err) });
  });

})

