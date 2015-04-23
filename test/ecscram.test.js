var Client = require('../src/ecscram').Client;
var base64 = require('../src/base64');
var ECKey = require('../src/eckey');

var expect = require('chai').expect;
var fs = require('fs');

describe.only('EC Scram', function() {

  it('shoud create a "client_first" message', function() {
    var client = new Client();

    var client_first = client.clientFirst('test@example.org');
    expect(client_first.msg).to.be.a('string');
    expect(client_first.sig).to.be.a('string');

    var sig = base64.decode(client_first.sig);
    var buf = base64.decode(client_first.msg);
    var msg = JSON.parse(buf);

    expect(msg.ecdhe).to.be.a('string');
    expect(msg.ecdsa).to.be.a('string');

    expect(msg.nonce).to.be.a('string');
    expect(base64.decode(msg.nonce).length).to.equal(32);;

    expect(msg.subject).to.equal('test@example.org');
    expect(msg.service).to.be.undefined;

    expect(
      new ECKey(msg.ecdsa, 'spki')
        .createVerify('SHA256')
        .update(buf)
        .verify(sig)
      ).to.be.true;

    expect(
      new ECKey(msg.ecdhe, 'spki')
        .createVerify('SHA256')
        .update(buf)
        .verify(sig)
      ).to.be.false;

  });

  it('shoud create a "client_first" message with a service', function() {
    var client = new Client();

    var client_first = client.clientFirst('test@example.org', 'dc9ecd4a-d2a8-47e8-bf39-77d256b42ca5');
    expect(client_first.msg).to.be.a('string');
    expect(client_first.sig).to.be.a('string');

    var sig = base64.decode(client_first.sig);
    var buf = base64.decode(client_first.msg);
    var msg = JSON.parse(buf);

    expect(msg.ecdhe).to.be.a('string');
    expect(msg.ecdsa).to.be.a('string');

    expect(msg.nonce).to.be.a('string');
    expect(base64.decode(msg.nonce).length).to.equal(32);;

    expect(msg.subject).to.equal('test@example.org');
    expect(msg.service).to.equal('dc9ecd4a-d2a8-47e8-bf39-77d256b42ca5');

    expect(
      new ECKey(msg.ecdsa, 'spki')
        .createVerify('SHA256')
        .update(buf)
        .verify(sig)
      ).to.be.true;

    expect(
      new ECKey(msg.ecdhe, 'spki')
        .createVerify('SHA256')
        .update(buf)
        .verify(sig)
      ).to.be.false;

  });

});
