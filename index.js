var express = require('express')();
var login = require('./src/application.js');

express.use('/login', login());
server = express.listen(8080, '127.0.0.1', function(error) {
  if (error) done(error);
  var address = server.address();
  console.log('Running at http://' + address.address + ':' + address.port + '/login');
});
