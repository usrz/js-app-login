var asn = require('asn1.js');

var PrivateKey = asn.define('PrivateKey', function() {
  this.seq().obj(
    this.key('version').int(),
    this.key('privateKey').octstr(),
    this.key('parameters').optional().explicit(0).objid({
        '1 3 132 0 35': 'secp521r1'
      }),
    this.key('publicKey').optional().explicit(1).bitstr()
  );
});

var PublicKey = asn.define('PublicKey', function() {
  this.seq().obj(
    this.key('AlgorithmIdentifier').seq().obj(
      this.key('publicKeyType').objid({
        '1 2 840 10045 2 1': 'EC'
      }),
      this.key('parameters').objid({
        '1 3 132 0 35': 'secp521r1'
      })
    ),
    this.key('publicKey').bitstr()
  );
});

console.log('MODELETD');

var crypto = require('crypto');
var ecdh = crypto.createECDH('secp521r1');
ecdh.generateKeys();

var buffer = PrivateKey.encode({
  version: 1,
  privateKey: ecdh.getPrivateKey(),
  parameters: 'secp521r1',
  publicKey: { data: ecdh.getPublicKey() },
}, 'der');
console.log(buffer.toString('base64'));


var buffer2 = PublicKey.encode({
  AlgorithmIdentifier: {
    publicKeyType: 'EC',
    parameters: 'secp521r1',
  },
  publicKey: { data: ecdh.getPublicKey() },
}, 'der');
console.log(buffer2.toString('base64'));
