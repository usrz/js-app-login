'use strict';

var expect = require('chai').expect;
var crypto = require('crypto');

var TokenManager = require('../src/tokens/TokenManager');

describe('Tokens', function() {

  var manager;
  before(function() {
    manager = new TokenManager(new Buffer('hello, world!'));
  });

  it('should encrypt and decrypt a secret', function() {
    var secret = crypto.randomBytes(64);
    var token = manager.create(1000, secret);

    var check = manager.validate(token);
    expect(check).to.be.instanceof(Buffer);
    expect(check).to.eql(secret);
  });

  it('should throw an error for a wrong secret', function() {
    var secret = crypto.randomBytes(64);
    var token1 = manager.create(1000, secret);

    var token2;
    if (token1.substr(60,1) == 'x') {
      token2 = token1.substr(0,60) + 'y' + token1.substr(61);
    } else {
      token2 = token1.substr(0,60) + 'x' + token1.substr(61);
    }

    expect(manager.validate(token1)).to.be.instanceof(Buffer);
    expect(function() {
        manager.validate(token2)
      }).to.throw('Unsupported state or unable to authenticate data');
  });

  it('should throw an error for a wrong authentication data', function() {
    var secret = crypto.randomBytes(64);
    var token = manager.create(1000, secret);

    expect(manager.validate(token)).to.be.instanceof(Buffer);
    expect(function() {
        manager.validate(token, new Buffer(1));
      }).to.throw('Unsupported state or unable to authenticate data');
  });

  it('should throw an error for a wrong authentication data (part deux)', function() {
    var secret = crypto.randomBytes(64);
    var extra = new Buffer('hi!', 'utf8');
    var token = manager.create(1000, secret, extra);

    expect(manager.validate(token, extra)).to.be.instanceof(Buffer);
    expect(function() {
        manager.validate(token);
      }).to.throw('Unsupported state or unable to authenticate data');
  });

  it('should never generate two equal tokens', function() {
    var secret = new Buffer('This will expire in 300 millis', 'utf8');

    // Overflow timeout, so we are always sure it will work
    var token1 = manager.create(Number.MAX_SAFE_INTEGER, secret);
    var token2 = manager.create(Number.MAX_SAFE_INTEGER, secret);

    var components1 = token1.split('.');
    var components2 = token2.split('.');
    expect(components1.length).to.equal(4);
    expect(components2.length).to.equal(4);

    // Timeout matches...
    expect(components1[0]).to.equal(components2[0]);

    // IV, encrypted data, and authentication tag do not...
    expect(components1[1]).to.not.equal(components2[1]);
    expect(components1[2]).to.not.equal(components2[2]);
    expect(components1[3]).to.not.equal(components2[3]);
  });

  it('should create a "forever" token', function() {
    var secret = new Buffer('This will expire in year 275760')
    var token = manager.create(Number.MAX_SAFE_INTEGER, secret);
    expect(token).to.match(/^AB6yCMLcAAA\./);
  })


  it('should decrypt a well known token', function() {//AB6yCMLcAAA.NDDv0ImE2m43ZOUd.CaWkRLUKGxYPN9hmyKgV9sCJooXlwL04gw.Ump1WTrsgLVfFMYEIqE5SA
    var secret = new Buffer('This will expire in year 275760')
    expect(manager.validate('AB6yCMLcAAA.oO3Rgimm9CpKrLNy.Mwndc4UvDDf6uY4r-q9f5p65sesP_ABuLJmwzQW5eg.j0J9O0t6stLXFzo12Q9KNA'))
      .to.eql(secret);
  })

  it('should return null decrypting an expired token', function() {
    expect(manager.validate('AAABTRTVbX0.YSuEbasiKH3R4yeY.D9A3xJlCJom6_WPUJc9ZvvkuFS7JpYVeRDVS0aWECgjkLCYrNwlO9GECIaat0HHnsUPncHDpwINsV6FT4TEsOA.YkHMO-U7Q-9sqOn_VHKIbg'))
      .to.be.null;
  });

  it('should honor timeouts', function(done) {
    this.slow(200);
    var secret = crypto.randomBytes(64);
    var token = manager.create(40, secret);

    setTimeout(function() {
      try {
        expect(manager.validate(token)).to.eql(secret);
      } catch (error) {
        done(error);
      }
    }, 20)

    setTimeout(function() {
      try {
        expect(manager.validate(token)).to.be.null;
        done();
      } catch (error) {
        done(error);
      }
    }, 60);


  })


})
