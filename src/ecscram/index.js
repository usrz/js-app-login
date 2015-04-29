'use strict';

/* ========================================================================== *
 * SCRAM (RFC-5802)                                                           *
 * -------------------------------------------------------------------------- *
 * SaltedPassword  := Hi(Normalize(password), salt, i)                        *
 *                                                                            *
 * ClientKey       := HMAC(SaltedPassword, "Client Key")                      *
 * StoredKey       := H(ClientKey)                                            *
 * ServerKey       := HMAC(SaltedPassword, "Server Key")                      *
 *                                                                            *
 * AuthMessage     := client-first-message-bare + "," +                       *
 *                    server-first-message + "," +                            *
 *                    client-final-message-without-proof                      *
 *                                                                            *
 * ClientSignature := HMAC(StoredKey, AuthMessage)                            *
 * ClientProof     := ClientKey XOR ClientSignature                           *
 *                                                                            *
 * ServerSignature := HMAC(ServerKey, AuthMessage)                            *
 * ========================================================================== *
 * SharedKey       := HMAC(StoredKey, OTP/APP|DEV SECRET)                     *
 * ClientSignature := HMAC(SharedKey, AuthMessage)                            *
 * ========================================================================== */

exports = module.exports = Object.freeze({
  Client: require('./Client'),
  Server: require('./Server')
});
