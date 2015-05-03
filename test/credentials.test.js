'use strict';

var Credentials = require('../src/credentials');

var expect = require('chai').expect;

describe('Credentials', function() {

  it('should create with defaults', function() {
    var store = new Credentials(function(){}, function(){});
    expect(store.scram_hash).to.equal('SHA-256');
    expect(store.pbkdf2_hash).to.equal('SHA-1');
    expect(store.salt_length).to.equal(20);
    expect(store.key_length).to.equal(20);
    expect(store.iterations).to.equal(100000);
  });

  it('should create with options', function() {
    var store = new Credentials(function(){}, function(){}, {
      fake_salt: 'shut up!',
      scram_hash: 'sha512',
      pbkdf2_hash: 'sha384',
      salt_length: 123,
      key_length: 321,
      iterations: 12345
    });
    expect(store.scram_hash).to.equal('SHA-512');
    expect(store.pbkdf2_hash).to.equal('SHA-384');
    expect(store.salt_length).to.equal(123);
    expect(store.key_length).to.equal(321);
    expect(store.iterations).to.equal(12345);
  });

  it('should not create with bogus parameters', function() {

    expect(function() { new Credentials(function(){}, function(){}, {
      scram_hash: 'bogus1',
    })}).to.throw('Hash "bogus1" unknown');

    expect(function() { new Credentials(function(){}, function(){}, {
      pbkdf2_hash: 'bogus2',
    })}).to.throw('Hash "bogus2" unknown');

    expect(function() { new Credentials(function(){}, function(){}, {
      salt_length: 19,
    })}).to.throw('Unwilling to truncate salts to 19 bytes (min=20)');

    expect(function() { new Credentials(function(){}, function(){}, {
      key_length: 19,
    })}).to.throw('Unwilling to truncate hashes to 19 bytes (min=20)');

    expect(function() { new Credentials(function(){}, function(){}, {
      iterations: 4999,
    })}).to.throw('Invalid iterations 4999 (min=5000)');

  });

  it('should store a password with defaults', function(done) {
    var saved = {};
    var store = new Credentials(function() {}, function(id, cred) {
      expect(id).to.equal('test@example.org');
      saved = cred;
    }, { fake_salt: 'shut up!' });

    store.set('test@example.org','password')
      .then(function(result) {
        //console.log('result', result);
        expect(result.kdf_spec).to.be.a('object');
        expect(result.kdf_spec.algorithm).to.equal('PBKDF2');
        expect(result.kdf_spec.hash).to.equal('SHA-1');
        expect(result.kdf_spec.iterations).to.equal(100000);
        expect(result.kdf_spec.derived_key_length).to.equal(20);
        expect(result.salt).to.be.a('string');
        expect(result.salt.length).to.equal(27);
        expect(result.hash).to.equal('SHA-256');
        expect(result.server_key).to.be.a('string');
        expect(result.stored_key).to.be.a('string');
        expect(result.server_key.length).to.equal(43);
        expect(result.stored_key.length).to.equal(43);
        expect(result).to.eql(saved);
        done();
      })

      .catch(done);
  });

  it('should store a password with custom parameters', function(done) {
    var saved = {};
    var store = new Credentials(function() {}, function(id, cred) {
      expect(id).to.equal('test@example.org');
      saved = cred;
    }, {
      fake_salt: 'shut up!',
      scram_hash: 'sha512',
      pbkdf2_hash: 'sha384',
      salt_length: 123,
      key_length: 321,
      iterations: 12345
    });

    store.set('test@example.org','password')
      .then(function(result) {
        //console.log('result', result);
        expect(result.kdf_spec).to.be.a('object');
        expect(result.kdf_spec.algorithm).to.equal('PBKDF2');
        expect(result.kdf_spec.hash).to.equal('SHA-384');
        expect(result.kdf_spec.iterations).to.equal(12345);
        expect(result.kdf_spec.derived_key_length).to.equal(321);
        expect(result.salt).to.be.a('string');
        expect(result.salt.length).to.equal(164);
        expect(result.hash).to.equal('SHA-512');
        expect(result.server_key).to.be.a('string');
        expect(result.stored_key).to.be.a('string');
        expect(result.server_key.length).to.equal(86);
        expect(result.stored_key.length).to.equal(86);
        expect(result).to.eql(saved);
        done();
      })

      .catch(done);
  });

  it('should return some valid credentials', function(done) {
    var store = new Credentials(function(id) {
      return id;
    }, function() {}, { fake_salt: 'shut up!' });

    store.get('this will be returned unchanged')
      .then(function(cred) {
        expect(cred).to.equal('this will be returned unchanged');
        done();
      })

      .catch(done);
  });

  it('should return nothing for an unknown user', function(done) {
    var store = new Credentials(function(id) {
      return null;
    }, function() {}, { fake_salt: 'shut up!' });

    store.get('this will be returned unchanged')
      .then(function(cred) {
        expect(cred).to.be.null;
        done();
      })

      .catch(done);
  });

  it('should generate some fake credentials', function() {
    var store = new Credentials(function() {}, function() {}, {
      fake_salt: '... a fake salt ...'
    });

    var result = store.fake('test@example.org');

    // console.log('result', result);
    expect(result.kdf_spec).to.be.a('object');
    expect(result.kdf_spec.algorithm).to.equal('PBKDF2');
    expect(result.kdf_spec.hash).to.equal('SHA-1');
    expect(result.kdf_spec.iterations).to.equal(100000);
    expect(result.kdf_spec.derived_key_length).to.equal(20);
    expect(result.salt).to.equal('eYcff6TYCnrD0oRTKNSGTOMy8dg');
    expect(result.hash).to.equal('SHA-256');
    expect(result.server_key).to.equal('');
    expect(result.stored_key).to.equal('');
    expect(result.fake).to.equal(true);
  });

  it('should should reject when fetch throws an error', function(done) {
    var store = new Credentials(function(id) {
      throw new Error('Thrown for ' + id);
    }, function() {}, { fake_salt: 'shut up!' });

    store.get('test@example.org')
      .then(function(token) {
        done(new Error('Should have thrown an error'));
      })
      .catch(function(error) {
        expect(error).to.be.instanceof(Error);
        expect(error.message).to.equal('Thrown for test@example.org');
        done();
      })
      .catch(done);
  });

  it('should should reject when store throws an error', function(done) {
    var store = new Credentials(function() {}, function(id) {
      throw new Error('Thrown for ' + id);
    }, { fake_salt: 'shut up!' });

    store.set('test@example.org', 'password')
      .then(function(token) {
        done(new Error('Should have thrown an error'));
      })
      .catch(function(error) {
        expect(error).to.be.instanceof(Error);
        expect(error.message).to.equal('Thrown for test@example.org');
        done();
      })
      .catch(done);
  });
});
