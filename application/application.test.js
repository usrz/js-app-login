var request = require('request');
var express = require('express')();
var expect = require('chai').expect;
var login = require('../src/application.js');

describe('Express Error Handler', function() {

  var server = null;
  var url = null;

  before(function(done) {
    express.use('/login', login());
    server = express.listen(-1, '127.0.0.1', function(error) {
      if (error) done(error);
      var address = server.address();
      url = 'http://' + address.address + ':' + address.port + '/login';
      done();
    });
  });

  after(function(done) {
    if (server) server.close(done);
    else done();
  });

  it('should return a 405 (Method Not Allowed) on GET', function(done) {
    request({ url: url, method: 'head' }, function(error, response, body) {
      try {
        expect(response.statusCode).to.equal(405);
        expect(response.body.status).to.equal(405);
        expect(response.body.message).to.equal("Method Not Allowed");
        done();
      } catch (error) {
        done(error);
      }
    });
  });

  it('should return a 415 (Unsupported Media Type) on POST with wrong content type', function(done) {
    request.post({ url: url, body: 'bar', headers: { "Content-Type" : "text/plain"} }, function(error, response, body) {
      try {
        console.log("--->" + response.statusCode + "<---", JSON.stringify(response.body));
        expect(response.statusCode).to.equal(415);
        done();
      } catch (error) {
        done(error);
      }
    });
  });

  it('should establish a session', function(done) {
    request.post({ url: url, body: { foo: "bar" }, json: true }, function(error, response, body) {
      try {
        console.log("--->" + response.statusCode + "<---", JSON.stringify(response.body));
        expect(response.statusCode).to.equal(201);
        done();
      } catch (error) {
        done(error);
      }
    });
  });

    // request(url + '/test-1', function(error, response, body) {
    //   if (error) return done(error);
    //   try {
    //     expect(response.statusCode).to.equal(400);
    //     expect(response.statusMessage).to.equal('Bad Request');
    //     expect(response.headers['content-type']).to.equal('application/json; charset=utf-8');
    //     expect(JSON.parse(body)).to.eql({
    //       status: 400,
    //       message: 'Bad Request'
    //     });
    //     expect(logmessage).to.equal('GET /test-1 (400) - Bad Request');

    //     return done();
    //   } catch (error) {
    //     return done(error);
    //   }
    // });

    //done();

})
