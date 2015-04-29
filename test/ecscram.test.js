var Credentials = require('../src/credentials');
var Client = require('../src/ecscram').Client;
var Server = require('../src/ecscram').Server;
var base64 = require('../src/base64');
var ECKey = require('../src/eckey');

var expect = require('chai').expect;
var fs = require('fs');

describe('EC Scram', function() {

  describe('Credentials', function() {
    it('should derive some credentials', function(done) {
      Credentials.deriveCredentials('password')
        .then(function(cred) {
          expect(cred.serverKey).to.be.a('string');
          expect(cred.storedKey).to.be.a('string');
          expect(cred.spec).to.be.a('object');
          expect(cred.spec.algorithm).to.equal('PBKDF2');
          expect(cred.spec.iterations).to.equal(10000);
          expect(cred.spec.derived_key_length).to.equal(32);
          expect(cred.spec.salt).to.be.a('string');
          done();
        })

        .catch(function(error) {
          done(error);
        });
    });

    it('should generate some credentials', function() {
      var cred = Credentials.generateCredentials('password');
      expect(cred.serverKey).to.equal('WmY2OGxFSkpISnhuWmhZU2dfU09yMTVVX3AtN1A5eS00bmJXaTFxc21hZw');
      expect(cred.storedKey).to.equal('c0RtcmRGMlZwYTlEaDhxckhtZlppR19MMk1Qc0JaQmwtNHB4OUxSMXkzRQ');
      expect(cred.spec).to.be.null;
    });
  });

  describe('Client First', function() {
    it('shoud create a simple "client_first" message', function() {
      var client = new Client();

      var message = client.clientFirst('test@example.org');

      expect(message.subject).to.equal('test@example.org');
      expect(message.public_key).to.be.a('string');

      var key = new ECKey(message.public_key, 'spki-urlsafe');

      expect(key.curve).to.equal('prime256v1');
      expect(key.toString('spki-urlsafe')).to.equal(message.public_key);
    });

    it('shoud create a "client_first" message with extra details', function() {
      var client = new Client("P-512");

      var message = client.clientFirst('test@example.org', { test: 123 });

      expect(message.subject).to.equal('test@example.org');
      expect(message.test).to.equal(123);
      expect(message.public_key).to.be.a('string');

      var key = new ECKey(message.public_key, 'spki-urlsafe');

      expect(key.curve).to.equal('prime256v1');
      expect(key.toString('spki-urlsafe')).to.equal(message.public_key);
    });
  });

  it('shoud negotiate a session', function() {
    var client = new Client();
    var server = new Server();

    var clientFirst = client.clientFirst('test@example.org');
    var serverFirst = server.serverFirst(clientFirst);
  });


});
