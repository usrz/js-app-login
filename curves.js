var crypto = require('crypto');
var curves = [ 'prime192v1', 'secp224r1', 'prime256v1', 'secp384r1', 'secp521r1' ]

var hr = process.hrtime();
for (var i = 0; i < curves.length; i ++) {
  var curve = curves[i];
  var a = crypto.createECDH(curve);
  var b = crypto.createECDH(curve);

  a.generateKeys();
  b.generateKeys();

  var a_secret = a.computeSecret(b.getPublicKey());
  var b_secret = b.computeSecret(a.getPublicKey());

  console.log('curve', curve);
  console.log(a_secret.toString('hex'), a.getPublicKey().toString('hex'));
  console.log(b_secret.toString('hex'), b.getPublicKey().toString('hex'));
  console.log(a_secret.length, b_secret.length * 8);
}
console.log('time', process.hrtime(hr));
