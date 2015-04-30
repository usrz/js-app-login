var express = require('express')();
var server = require('./src/server.js');

var sessionManager = require('./src/sessionManager')('foobarbaz');
express.locals.sessionManager = sessionManager;

express.use('/login', server);
listener = express.listen(8080, '127.0.0.1', function(error) {

  if (error) done(error);
  var address = listener.address();
  console.log('Running at http://' + address.address + ':' + address.port + '/login');
});
