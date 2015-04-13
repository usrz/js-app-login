'use strict';

var expect = require('chai').expect;
var Cipher = require('../src/scram/cipher');
var base64 = require('../src/base64');

describe('Cipher', function() {

  function buffer(size) {
    var b = new Buffer(size);
    for (var i = 0; i < size; i ++) b[i] = i;
    return b;
  }

  function convert(string) {
    return new Buffer(string.replace(/ /g, ''), 'hex');
  }

  describe('Authenticated AES + SHA2', function() {

    // 'A cipher system must not be required to be secret, and it must be able to fall into the hands of the enemy without inconvenience';
    var p = convert('41 20 63 69 70 68 65 72 20 73 79 73 74 65 6d 20'
                  + '6d 75 73 74 20 6e 6f 74 20 62 65 20 72 65 71 75'
                  + '69 72 65 64 20 74 6f 20 62 65 20 73 65 63 72 65'
                  + '74 2c 20 61 6e 64 20 69 74 20 6d 75 73 74 20 62'
                  + '65 20 61 62 6c 65 20 74 6f 20 66 61 6c 6c 20 69'
                  + '6e 74 6f 20 74 68 65 20 68 61 6e 64 73 20 6f 66'
                  + '20 74 68 65 20 65 6e 65 6d 79 20 77 69 74 68 6f'
                  + '75 74 20 69 6e 63 6f 6e 76 65 6e 69 65 6e 63 65');

    // 'The second principle of Auguste Kerckhoffs';
    var a = convert('54 68 65 20 73 65 63 6f 6e 64 20 70 72 69 6e 63'
                  + '69 70 6c 65 20 6f 66 20 41 75 67 75 73 74 65 20'
                  + '4b 65 72 63 6b 68 6f 66 66 73');

    var iv = convert('1a f3 8c 2d c2 b9 6f fd d8 66 94 09 23 41 bc 04');


    it('should validate the JWA (B.1) test vector for A128CBC-HS256', function() {
      var cipher = new Cipher('A128CBC-HS256');

      var k = buffer(32);
      var e = convert('c8 0e df a3 2d df 39 d5 ef 00 c0 b4 68 83 42 79'
                    + 'a2 e4 6a 1b 80 49 f7 92 f7 6b fe 54 b9 03 a9 c9'
                    + 'a9 4a c9 b4 7a d2 65 5c 5f 10 f9 ae f7 14 27 e2'
                    + 'fc 6f 9b 3f 39 9a 22 14 89 f1 63 62 c7 03 23 36'
                    + '09 d4 5a c6 98 64 e3 32 1c f8 29 35 ac 40 96 c8'
                    + '6e 13 33 14 c5 40 19 e8 ca 79 80 df a4 b9 cf 1b'
                    + '38 4c 48 6f 3a 54 c5 10 78 15 8e e5 d7 9d e5 9f'
                    + 'bd 34 d8 48 b3 d6 95 50 a6 76 46 34 44 27 ad e5'
                    + '4b 88 51 ff b5 98 f7 f8 00 74 b9 47 3c 82 e2 db');
      var t = convert('65 2c 3f a3 6b 0a 7c 5b 32 19 fa b3 a3 0b c1 c4');

      var result = cipher.encrypt(k, p, a, iv);

      expect(result).to.eql({
        enc: 'A128CBC-HS256',
        ciphertext: base64.encode(e),
        tag: base64.encode(t),
        iv: base64.encode(iv)
      });

      var d = cipher.decrypt(k, result, a);
      expect(Buffer.compare(d, p)).to.equal(0);
    });

    it('should validate the JWA (B.2) test vector for A192CBC-HS384', function() {
      var cipher = new Cipher('A192CBC-HS384');

      var k = buffer(48);
      var e = convert('ea 65 da 6b 59 e6 1e db 41 9b e6 2d 19 71 2a e5'
                    + 'd3 03 ee b5 00 52 d0 df d6 69 7f 77 22 4c 8e db'
                    + '00 0d 27 9b dc 14 c1 07 26 54 bd 30 94 42 30 c6'
                    + '57 be d4 ca 0c 9f 4a 84 66 f2 2b 22 6d 17 46 21'
                    + '4b f8 cf c2 40 0a dd 9f 51 26 e4 79 66 3f c9 0b'
                    + '3b ed 78 7a 2f 0f fc bf 39 04 be 2a 64 1d 5c 21'
                    + '05 bf e5 91 ba e2 3b 1d 74 49 e5 32 ee f6 0a 9a'
                    + 'c8 bb 6c 6b 01 d3 5d 49 78 7b cd 57 ef 48 49 27'
                    + 'f2 80 ad c9 1a c0 c4 e7 9c 7b 11 ef c6 00 54 e3');
      var t = convert('84 90 ac 0e 58 94 9b fe 51 87 5d 73 3f 93 ac 20'
                    + '75 16 80 39 cc c7 33 d7');

      var result = cipher.encrypt(k, p, a, iv);

      expect(result).to.eql({
        enc: 'A192CBC-HS384',
        ciphertext: base64.encode(e),
        tag: base64.encode(t),
        iv: base64.encode(iv)
      });

      var d = cipher.decrypt(k, result, a);
      expect(Buffer.compare(d, p)).to.equal(0);
    });

    it('should validate the JWA (B.3) test vector for A256CBC-HS512', function() {
      var cipher = new Cipher('A256CBC-HS512');

      var k = buffer(64);
      var e = convert('4a ff aa ad b7 8c 31 c5 da 4b 1b 59 0d 10 ff bd'
                    + '3d d8 d5 d3 02 42 35 26 91 2d a0 37 ec bc c7 bd'
                    + '82 2c 30 1d d6 7c 37 3b cc b5 84 ad 3e 92 79 c2'
                    + 'e6 d1 2a 13 74 b7 7f 07 75 53 df 82 94 10 44 6b'
                    + '36 eb d9 70 66 29 6a e6 42 7e a7 5c 2e 08 46 a1'
                    + '1a 09 cc f5 37 0d c8 0b fe cb ad 28 c7 3f 09 b3'
                    + 'a3 b7 5e 66 2a 25 94 41 0a e4 96 b2 e2 e6 60 9e'
                    + '31 e6 e0 2c c8 37 f0 53 d2 1f 37 ff 4f 51 95 0b'
                    + 'be 26 38 d0 9d d7 a4 93 09 30 80 6d 07 03 b1 f6');
      var t = convert('4d d3 b4 c0 88 a7 f4 5c 21 68 39 64 5b 20 12 bf'
                    + '2e 62 69 a8 c5 6a 81 6d bc 1b 26 77 61 95 5b c5');

      var result = cipher.encrypt(k, p, a, iv);

      expect(result).to.eql({
        enc: 'A256CBC-HS512',
        ciphertext: base64.encode(e),
        tag: base64.encode(t),
        iv: base64.encode(iv)
      });

      var d = cipher.decrypt(k, result, a);
      expect(Buffer.compare(d, p)).to.equal(0);
    });
  });

  describe('AES in Galois/Counter Mode', function() {

    it('should validate the JWE (A.1) test vector', function() {

      var ciphertext = new Buffer([229, 236, 166, 241, 53, 191, 115, 196, 174, 43, 73, 109, 39, 122,
                                   233, 96, 140, 206, 120, 52, 51, 237, 48, 11, 190, 219, 186, 80, 111,
                                   104, 50, 142, 47, 167, 59, 61, 181, 127, 196, 21, 40, 82, 242, 32,
                                   123, 143, 168, 226, 73, 216, 176, 144, 138, 247, 106, 60, 16, 205,
                                   160, 109, 64, 63, 192]);

      var authentication_tag = new Buffer([92, 80, 104, 49, 133, 25, 161, 215, 173, 101, 219, 211, 136, 91,
                                           210, 145]);

      var initialization_vector = new Buffer([227, 197, 117, 252, 2, 219, 233, 68, 180, 225, 77, 219]);

      var encrypted = {
        ciphertext: base64.encode(ciphertext),
        tag: base64.encode(authentication_tag),
        iv: base64.encode(initialization_vector)
      }

      /* -------------------------------------------------------------------- */

      var encryption_key = new Buffer([177, 161, 244, 128, 84, 143, 225, 115, 63, 180, 3, 255, 107, 154,
                                       212, 246, 138, 7, 110, 91, 112, 46, 34, 105, 47, 130, 203, 46, 122,
                                       234, 64, 252]);

      var authenticated_data = new Buffer([101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 83, 85, 48, 69,
                                           116, 84, 48, 70, 70, 85, 67, 73, 115, 73, 109, 86, 117, 89, 121, 73,
                                           54, 73, 107, 69, 121, 78, 84, 90, 72, 81, 48, 48, 105, 102, 81]);


      var result = new Cipher('A256GCM').decrypt(encryption_key, encrypted, authenticated_data);

      /* -------------------------------------------------------------------- */

      var plain_text = new Buffer([84, 104, 101, 32, 116, 114, 117, 101, 32, 115, 105, 103, 110, 32,
                                   111, 102, 32, 105, 110, 116, 101, 108, 108, 105, 103, 101, 110, 99,
                                   101, 32, 105, 115, 32, 110, 111, 116, 32, 107, 110, 111, 119, 108,
                                   101, 100, 103, 101, 32, 98, 117, 116, 32, 105, 109, 97, 103, 105,
                                   110, 97, 116, 105, 111, 110, 46]);

      expect(result.toString('utf8')).to.equal(plain_text.toString('utf8'));
    });

    it('should encrypt and decrypt in A128GCM with additional data', function() {
      var cipher = new Cipher('A128GCM');

      var key = buffer(16);
      var plain_text = new Buffer('A very simple message, to be encrypted and decrypted...', 'utf8');
      var auth_data = new Buffer('Additionally authenticating with some data', 'utf8');

      var result = cipher.encrypt(key, plain_text, auth_data);

      var decrypted = cipher.decrypt(key, result, auth_data);

      expect(decrypted.toString('utf8')).to.equal(plain_text.toString('utf8'));
    });

    it('should encrypt and decrypt in A192GCM with additional data', function() {
      var cipher = new Cipher('A192GCM');

      var key = buffer(24);
      var plain_text = new Buffer('A very simple message, to be encrypted and decrypted...', 'utf8');
      var auth_data = new Buffer('Additionally authenticating with some data', 'utf8');

      var result = cipher.encrypt(key, plain_text, auth_data);

      var decrypted = cipher.decrypt(key, result, auth_data);

      expect(decrypted.toString('utf8')).to.equal(plain_text.toString('utf8'));
    });

    it('should encrypt and decrypt in A256GCM with additional data', function() {
      var cipher = new Cipher('A256GCM');

      var key = buffer(32);
      var plain_text = new Buffer('A very simple message, to be encrypted and decrypted...', 'utf8');
      var auth_data = new Buffer('Additionally authenticating with some data', 'utf8');

      var result = cipher.encrypt(key, plain_text, auth_data);

      var decrypted = cipher.decrypt(key, result, auth_data);

      expect(decrypted.toString('utf8')).to.equal(plain_text.toString('utf8'));
    });

    it('should encrypt and decrypt in A128GCM without additional data', function() {
      var cipher = new Cipher('A128GCM');

      var key = buffer(16);
      var plain_text = new Buffer('A very simple message, to be encrypted and decrypted...', 'utf8');

      var result = cipher.encrypt(key, plain_text);

      var decrypted = cipher.decrypt(key, result);

      expect(decrypted.toString('utf8')).to.equal(plain_text.toString('utf8'));
    });

    it('should encrypt and decrypt in A192GCM without additional data', function() {
      var cipher = new Cipher('A192GCM');

      var key = buffer(24);
      var plain_text = new Buffer('A very simple message, to be encrypted and decrypted...', 'utf8');

      var result = cipher.encrypt(key, plain_text);

      var decrypted = cipher.decrypt(key, result);

      expect(decrypted.toString('utf8')).to.equal(plain_text.toString('utf8'));
    });

    it('should encrypt and decrypt in A256GCM without additional data', function() {
      var cipher = new Cipher('A256GCM');

      var key = buffer(32);
      var plain_text = new Buffer('A very simple message, to be encrypted and decrypted...', 'utf8');

      var result = cipher.encrypt(key, plain_text);

      var decrypted = cipher.decrypt(key, result);

      expect(decrypted.toString('utf8')).to.equal(plain_text.toString('utf8'));
    });

  });

});




