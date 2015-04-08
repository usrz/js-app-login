'use strict';

var expect = require('chai').expect;
var Scram = require('../src/scram');

describe('SCRAM', function() {

  it('should compute with a callback', function(done) {
    var scram = new Scram('SHA256');
    scram.generate(new Buffer(100), function(err, ok) {
      console.log('DONE', err, '\n', ok);
      done(err);
    });
  });

  it('should compute with a promise', function(done) {
    var scram = new Scram('SHA256');
    scram.promise(new Buffer(100)).then(function(result) {
      console.log('DONE', '\n', result);
      done();
    }, function(error) {
      done(error);
    });
  });
})

