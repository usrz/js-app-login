var InternalServerError = require('../errors').InternalServerError;
var BadRequest = require('../errors').BadRequest;
var base64 = require('../util/base64');
var ECKey = require('../eckey');
var util = require('util');

function Server() {
}

Server.prototype.serverFirst = function(clientFirst) {

  // Basic checks on client_first
  if (! util.isString(clientFirst.subject)) throw new BadRequest('No Subject in Client First');
  if (! clientFirst.public_key) throw new BadRequest('No ECDHE Public Key in Client First');

  // Parse the client ECDHE key
  var clientPublicKey;
  try {
    clientPublicKey = new ECKey(clientFirst.public_key, 'spki-urlsafe');
    if (clientPublicKey.isPrivateKey) throw new BadRequest('Received a ECDHE Private Key');
  } catch (error) {
    console.log('ERROR', error); // TODO
    throw new BadRequest('Unable to decode ECDHE Public Key');
  }

  // Create a server public key with the same curve as the client
  var serverPrivateKey = ECKey.createECKey(clientPublicKey.curve);

  // Calculate the nonce using private and public key
  var nonce = serverPrivateKey.computeSecret(clientPublicKey);

  console.log("NONCE IS", nonce);


}

exports = module.exports = Server;

