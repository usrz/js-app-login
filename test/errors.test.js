'use strict';

var util = require('util');
var expect = require('chai').expect;
var HttpError = require('../src/util/HttpError');

function s(e) { return e.toString() };
function j(e) { return JSON.parse(JSON.stringify(e)) };

describe('HttpError', function() {

  it('should expose self', function() {
    expect(HttpError).to.equal(HttpError.HttpError);
  })

  it('should construct', function() {
    var e = HttpError();
    expect(e).to.be.instanceof(HttpError);
    expect(e.status).to.equal(500);
    expect(e.message).to.equal('Internal Server Error');
    expect(e.cause).to.equal(undefined);
    expect(s(e)).to.equal('HTTP 500: Internal Server Error');
    expect(j(e)).to.eql({message: 'Internal Server Error', status: 500});
  })

  it('should construct with a known (int) status', function() {
    var e = HttpError(404);
    expect(e).to.be.instanceof(HttpError);
    expect(e.status).to.equal(404);
    expect(e.message).to.equal('Not Found');
    expect(e.cause).to.equal(undefined);
    expect(s(e)).to.equal('HTTP 404: Not Found');
    expect(j(e)).to.eql({message: 'Not Found', status: 404});
  })

  it('should construct with a known (string) status', function() {
    var e = HttpError('410');
    expect(e).to.be.instanceof(HttpError);
    expect(e.status).to.equal(410);
    expect(e.message).to.equal('Gone');
    expect(e.cause).to.equal(undefined);
    expect(s(e)).to.equal('HTTP 410: Gone');
    expect(j(e)).to.eql({message: 'Gone', status: 410});
  })

  it('should construct with an unknown (int) status', function() {
    var e = HttpError(987);
    expect(e).to.be.instanceof(HttpError);
    expect(e.status).to.equal(987);
    expect(e.message).to.equal('Unknown Error');
    expect(e.cause).to.equal(undefined);
    expect(s(e)).to.equal('HTTP 987: Unknown Error');
    expect(j(e)).to.eql({message: 'Unknown Error', status: 987});
  })

  it('should construct with an unknown (string) status', function() {
    var e = HttpError('123');
    expect(e).to.be.instanceof(HttpError);
    expect(e.status).to.equal(123);
    expect(e.message).to.equal('Unknown Error');
    expect(e.cause).to.equal(undefined);
    expect(s(e)).to.equal('HTTP 123: Unknown Error');
    expect(j(e)).to.eql({message: 'Unknown Error', status: 123});
  })

  it('should construct with a status and a message', function() {
    var e = HttpError(412, 'NOT Precondition Failed');
    expect(e).to.be.instanceof(HttpError);
    expect(e.status).to.equal(412);
    expect(e.message).to.equal('NOT Precondition Failed');
    expect(e.cause).to.equal(undefined);
    expect(s(e)).to.equal('HTTP 412: NOT Precondition Failed');
    expect(j(e)).to.eql({message: 'NOT Precondition Failed', status: 412});
  })

  it('should construct with a message', function() {
    var e = HttpError('NOT Internal Server Error');
    expect(e).to.be.instanceof(HttpError);
    expect(e.status).to.equal(500);
    expect(e.message).to.equal('NOT Internal Server Error');
    expect(e.cause).to.equal(undefined);
    expect(s(e)).to.equal('HTTP 500: NOT Internal Server Error');
    expect(j(e)).to.eql({message: 'NOT Internal Server Error', status: 500});
  })

  it('should construct with a status, a message and a cause', function() {
    var c = new Error('There you go, a cause!');
    var e = HttpError(301, 'NOT Moved Permanently', c);
    expect(e).to.be.instanceof(HttpError);
    expect(e.status).to.equal(301);
    expect(e.message).to.equal('NOT Moved Permanently');
    expect(e.cause).to.equal(c);
    expect(s(e)).to.equal('HTTP 301: NOT Moved Permanently');
    expect(j(e)).to.eql({message: 'NOT Moved Permanently', status: 301});
  })

  it('should construct with a message and a cause', function() {
    var c = new Error('There you go, a cause!');
    var e = HttpError('NOT Another Internal Server Error', c);
    expect(e).to.be.instanceof(HttpError);
    expect(e.status).to.equal(500);
    expect(e.message).to.equal('NOT Another Internal Server Error');
    expect(e.cause).to.equal(c);
    expect(s(e)).to.equal('HTTP 500: NOT Another Internal Server Error');
    expect(j(e)).to.eql({message: 'NOT Another Internal Server Error', status: 500});
  })

  it('should construct with a cause', function() {
    var c = new Error('There you go, a cause!');
    var e = HttpError(c);
    expect(e).to.be.instanceof(HttpError);
    expect(e.status).to.equal(500);
    expect(e.message).to.equal('Internal Server Error');
    expect(e.cause).to.equal(c);
    expect(s(e)).to.equal('HTTP 500: Internal Server Error');
    expect(j(e)).to.eql({message: 'Internal Server Error', status: 500});
  })

  it('should construct with a status and a cause', function() {
    var c = new Error('There you go, a cause!');
    var e = HttpError(417, c);
    expect(e).to.be.instanceof(HttpError);
    expect(e.status).to.equal(417);
    expect(e.message).to.equal('Expectation Failed');
    expect(e.cause).to.equal(c);
    expect(s(e)).to.equal('HTTP 417: Expectation Failed');
    expect(j(e)).to.eql({message: 'Expectation Failed', status: 417});
  })

  describe('Stack Traces', function() {
    it('should expose the cause stack trace', function() {
      var c = new Error('There you go, a cause!');
      var e = HttpError(508, c);
      expect(e.stack.indexOf('HTTP 508: Loop Detected\n    at')).to.equal(0);
      expect(e.stack.indexOf('\n  Caused by Error: There you go, a cause!\n    at')).to.be.above(1);
    })

    it('should expose the cause even if it is not an error', function() {
      var e = HttpError(416, 'NOT Range Not Satisfiable', 'A string can be thrown');
      expect(e.stack.indexOf('HTTP 416: NOT Range Not Satisfiable\n    at')).to.equal(0);
      expect(e.stack.indexOf('\n  Caused by [string] A string can be thrown')).to.be.above(1);
    })
  })

  describe('Pre-packaged errors', function() {

    it('should construct with no parameters', function() {
      var e = HttpError.URITooLong();
      expect(e).to.be.instanceof(HttpError);
      expect(e.status).to.equal(414);
      expect(e.message).to.equal('URI Too Long');
      expect(e.cause).to.equal(undefined);
      expect(s(e)).to.equal('HTTP 414: URI Too Long');
      expect(j(e)).to.eql({message: 'URI Too Long', status: 414});
    })

    it('should construct with no parameters (camel case check)', function() {
      var e = HttpError.UriTooLong();
      expect(e).to.be.instanceof(HttpError);
      expect(e.status).to.equal(414);
      expect(e.message).to.equal('URI Too Long');
      expect(e.cause).to.equal(undefined);
      expect(s(e)).to.equal('HTTP 414: URI Too Long');
      expect(j(e)).to.eql({message: 'URI Too Long', status: 414});
    })

    it('should construct with a message', function() {
      var e = HttpError.TooManyRequests("NOT Too Many Requests");
      expect(e).to.be.instanceof(HttpError);
      expect(e.status).to.equal(429);
      expect(e.message).to.equal('NOT Too Many Requests');
      expect(e.cause).to.equal(undefined);
      expect(s(e)).to.equal('HTTP 429: NOT Too Many Requests');
      expect(j(e)).to.eql({message: 'NOT Too Many Requests', status: 429});
    })

    it('should construct with a message and a cause', function() {
      var c = new Error('There you go, a cause!');
      var e = HttpError.NotModified("NOT Not Modified", c);
      expect(e).to.be.instanceof(HttpError);
      expect(e.status).to.equal(304);
      expect(e.message).to.equal('NOT Not Modified');
      expect(e.cause).to.equal(c);
      expect(s(e)).to.equal('HTTP 304: NOT Not Modified');
      expect(j(e)).to.eql({message: 'NOT Not Modified', status: 304});
      expect(e.stack.indexOf('HTTP 304: NOT Not Modified\n    at')).to.equal(0);
      expect(e.stack.indexOf('\n  Caused by Error: There you go, a cause!\n    at')).to.be.above(1);
    })

    it('should construct with a cause', function() {
      var c = new Error('There you go, a cause!');
      var e = HttpError.Conflict(c);
      expect(e).to.be.instanceof(HttpError);
      expect(e.status).to.equal(409);
      expect(e.message).to.equal('Conflict');
      expect(e.cause).to.equal(c);
      expect(s(e)).to.equal('HTTP 409: Conflict');
      expect(j(e)).to.eql({message: 'Conflict', status: 409});
      expect(e.stack.indexOf('HTTP 409: Conflict\n    at')).to.equal(0);
      expect(e.stack.indexOf('\n  Caused by Error: There you go, a cause!\n    at')).to.be.above(1);
    })
  })
})
