'use strict';

var expect = require('chai').expect;
var base32 = require('../src/base32');
var base64 = require('../src/base64');

// Incredibly enough, "foobar" is in the RFC :-)
var testVectors = [
  [ "f"      , "MY"         , "Zg"       ],
  [ "fo"     , "MZXQ"       , "Zm8"      ],
  [ "foo"    , "MZXW6"      , "Zm9v"     ],
  [ "foob"   , "MZXW6YQ"    , "Zm9vYg"   ],
  [ "fooba"  , "MZXW6YTB"   , "Zm9vYmE"  ],
  [ "foobar" , "MZXW6YTBOI" , "Zm9vYmFy" ],
];


describe('BASE64', function() {

  for (var i = 0; i < testVectors.length; i++) (function(i) {
    var decoded = testVectors[i][0];
    var encoded = testVectors[i][2];

    it('should encode test vector ' + 1, function() {
      expect(base64.encode(decoded)).to.equal(encoded);
    });

    it('should decode test vector ' + 1, function() {
      expect(base64.decode(encoded).toString('utf8')).to.equal(decoded);
    });
  })(i);

  var buf = new Buffer('00108310518720928b30d38f41149351559761969b71d79f8218a39259a7a29aabb2dbafc31cb3d35db7e39ebbf3dfbf00108310518720928b30d38f41149351559761969b71d79f8218a39259a7a29aabb2dbafc31cb3d35db7e39ebbf3dfbf', 'hex');
  var b64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

  it('should encode a longer test', function() {
    expect(base64.encode(buf)).to.equal(b64);
  });

  it('should decode a longer test', function() {
    expect(base64.decode(b64)).to.eql(buf);
  });


});

describe('BASE32', function() {

  for (var i = 0; i < testVectors.length; i++) (function(i) {
    var decoded = testVectors[i][0];
    var encoded = testVectors[i][1];

    it('should encode test vector ' + 1, function() {
      expect(base32.encode(decoded)).to.equal(encoded);
    });

    it('should decode test vector ' + 1, function() {
      expect(base32.decode(encoded).toString('utf8')).to.equal(decoded);
    });

  })(i);
});

