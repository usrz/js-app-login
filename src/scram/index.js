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
 *                                                                            *
 * -------------------------------------------------------------------------- *
 * In our extension:                                                          *
 *                                                                            *
 * - Replace "AuthMessage" definition with                                    *
 *    -> AuthMessage := subject + audience + server_nonce + client_nonce      *
 * - Replace SaltedPassword (PBKDF2 with i iterations) with                   *
 *    -> SaltedPassword := KDF(password, kdf_spec)                            *
 * - Replace "Client Key" (string) with                                       *
 *    -> SharedKey := RANDOM(digest_size_of(H))                               *
 * - Replace "Server Key" (string) with                                       *
 *    -> MasterKey := HMAC(ClientKey, SharedKey)                              *
 * - Rename ServerSignature with ServerProof                                  *
 *                                                                            *
 * Henceforth:                                                                *
 *                                                                            *
 * SaltedPassword  := KDF(Normalize(password), kdf_spec)                      *
 *                                                                            *
 * SharedKey       := RANDOM(digest_size_of(H))                               *
 * ClientKey       := HMAC(SaltedPassword, SharedKey)                         *
 * StoredKey       := H(ClientKey)                                            *
 *                                                                            *
 * MasterKey       := HMAC(ClientKey, SharedKey)                              *
 * ServerKey       := HMAC(SaltedPassword, MasterKey)                         *
 *                                                                            *
 * AuthMessage     := client-first-message-bare + "," +                       *
 *                    server-first-message + "," +                            *
 *                    client-final-message-without-proof                      *
 *                                                                            *
 * ClientSignature := HMAC(StoredKey, AuthMessage)                            *
 * ClientProof     := ClientKey XOR ClientSignature                           *
 *                                                                            *
 * ServerProof     := HMAC(ServerKey, AuthMessage)                            *
 *                                                                            *
 *                                                                            *
 *                                                                            *
 * ========================================================================== */

exports = module.exports = Object.freeze({
  Client: require('./Client'),
  Server: require('./Server'),
  Store:  require('./Store')
});
