var InternalServerError = require('../errors').InternalServerError;
var BadRequest = require('../errors').BadRequest;
var base64 = require('../base64');
var ECKey = require('../eckey');
var util = require('util');

function Server() {
}

Server.prototype.serverFirst = function(message) {
  if (! message) throw new InternalServerError('No message');
  if (! util.isString(message.client_first)) throw new BadRequest('No Client First');

  // Parse the client_first
  var clientFirst;
  try {
    var buffer = base64.decode(message.client_first);
    clientFirst = JSON.parse(buffer.toString('utf8'));
  } catch (error) {
    console.log('ERROR', error); // TODO
    throw new BadRequest('Unable to decode Client First');
  }

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

