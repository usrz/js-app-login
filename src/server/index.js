'use strict';

var app = require('express')();
var parser = require('body-parser');
var typeis = require('type-is');
var e = require('../errors');

app.set('json spaces', 2);

app.on('mount', function(parent) {
  console.log('Login Server mounted under "' + app.mountpath + '"');
});

// Parse JSON or Form Data
app.use(parser.urlencoded({extended: false}));
app.use(parser.json());

// Accept only POST, and restrict content type to application/json
// and application/x-www-form-urlencoded only.
app.use(function(req, res, next) {
  if (req.method === 'POST') {
    if (typeis(req, [ 'application/x-www-form-urlencoded', 'application/json', ])) {
      return next();
    }
    throw new e.UnsupportedMediaType();
  }
  throw new e.MethodNotAllowed();
});

// Create a session
app.post('/', function(req, res, next) {
  console.log('BODY', req.body);
});



