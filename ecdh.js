var crypto = require('crypto');
var util = require('util');

function ECDH(privateKey, publicKey) {

}

// private
// --> PEM (BASE64 of PKCS8)
// --> PKCS8 (der)
// --> JWK (kty="EC", crv, d, x, y)
// public
// --> PEM (BASE64 of SPKI)
// --> SPKI (der)
// --> JWK (kty="EC", crv, x, y)
function readPrivateKey()
