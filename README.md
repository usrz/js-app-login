 This document describes a simple API for authenticating users over
_[HTTP](http://tools.ietf.org/html/rfc2616)_ and (strongly preferred)
_[HTTPs](http://tools.ietf.org/html/rfc2818)_ using _JSON_ to exchange messages.

This API was heavily inspired, and considers the various security implications
outlined by the [SCRAM](http://tools.ietf.org/html/rfc5802) _SASL_
specification.

This API follows the rationale of [SCRAM](http://tools.ietf.org/html/rfc5802)
and replaces the four binary messages described there with two pair of _HTTP_
request and response pairs.

This API also extends [SCRAM](http://tools.ietf.org/html/rfc5802) by
introducing the ability to use different key derivation functions, allowing
the extension of requests and responses exchanged between client and server,
support for time based or counter based one-time passwords as defined by
[RFC-6238](http://tools.ietf.org/html/rfc6238) (TOTP) and
[RFC-4226](http://tools.ietf.org/html/rfc4226) (HOTP).



Index
=====

1. [Terminology](#1-terminology)
2. [Core Definitions](#2-core-definitions)
3. [Request content types](#3-request-content-types)
4. [Hashing](#4-hashing)
   1. [Exchange hash algorithm](#4-1-exchange-hash-algorithm)
   2. [HMAC](#4-2-hmac)
5. [Key Derivation Functions](#5-key-derivation-functions)
   1. [Password Based Key Derivation Function 2](#5-1-password-based-key-derivation-function-2)
   2. [Colin Percival's SCrypt](#5-2-colin-percival-s-scrypt)
   3. [BCrypt](#5-3-bcrypt)
6. [Digital Signatures and Encryption](#6-digital-signatures-and-encryption)
7. [Server Configuration](#7-server-configuration)
8. [Password Storage](#8-password-storage)
9. [API Overview](#9-api-overview)
   1. [Session Creation](#9-1-session-creation)
   2. [Session Authentication](#9-2-session-authentication)
   3. [Server Proof Verification](#9-3-server-proof-verification)
   4. [Session URLs](#9-4-session-urls)
10. [One-Time Password Support](#10-one-time-password-support)
11. [Non-Standard Extensions](#11-non-standard-extensions)


1. Terminology
==============

The key words _MUST_, _MUST NOT_, _REQUIRED_, _SHALL_, _SHALL NOT_, _SHOULD_,
_SHOULD NOT_, _RECOMMENDED_, _MAY_, and _OPTIONAL_ in this document are to be
interpreted as described in [RFC-2119](http://tools.ietf.org/html/rfc2119).

For the purpose of this specification, the term _**JSON**_ always refers to the data
interchange format standardized by [RFC-4627](http://tools.ietf.org/html/rfc4627)
and [ECMA-404](http://www.ecma-international.org/publications/files/ECMA-ST/ECMA-404.pdf)
and described at [JSON.ORG](http://www.json.org/) and standardized

Also, the term _**BASE-64-URL**_ encoding always refers to the URL-safe
and filename-safe Base64 encoding described in
[RFC-4648, Section 5](http://tools.ietf.org/html/rfc4648#section-5), with the
(non URL-safe) `=` padding characters omitted, as permitted by the same RFC's
[Section 3.2](http://tools.ietf.org/html/rfc4648#section-3.2).

Finally, the term _**JWS**_ and _**JWE**_ always respectively refer to the
structures proposed in the
[JSON Web Signature](https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41)
and
[JSON Web Encryption](https://tools.ietf.org/html/draft-ietf-jose-json-web-encryption-40)
standard drafts.



2. Core Definitions
===================

This specification relies on few core definitions as follows:

* `version`: The version described by this specification is _number_ 1

* `user`: A user is identified by a _non-empty_ sequence of Unicode characters.
   Individual implementations of this specification are free to determine how
   each `user` can be mapped to a known entity to authenticate (for example,
   case normalization, [unicode normalization](http://unicode.org/reports/tr15/)
   or whitespace stripping).

* `password`: A password is a sequence of unicode characters.
   This specification dictates that its binary representation for hashing and
   key derivation is the _[non-normalized](http://unicode.org/reports/tr15/)_
   [UTF-8](http://tools.ietf.org/html/rfc2279) encoding of such sequence.


### Functions

* `CONCAT( param1, param2, ...)`: This defines the concatenation of the byte
   sequences represented by the various `param1`, `param2`, ..., in order.

* `XOR( param1, param2)`:  This defines the _exclusive OR operation_ of the two
   byte sequences represented by `param1` and `param2` which _MUST_ be of equal
   length.

* `HASH(data)`: See [section 4.1](#4-1-exchange-hash-algorithm)

* `HMAC(key, message)`: See [section 4.2](#4-2-hmac)

* `KDF(password, ...)`: See [section 5](#5-key-derivation-functions)



3. Request content types
========================

Server implementations _MUST_ accept both `application/json` and
`application/x-www-form-urlencoded` content types as its request.

As this specification does not define complex _JSON_ structures in its requests
(no objects nested within objects), it is defined that a document like:

```json
{
  "key1": 1,
  "key2": [ "value2A", "value2B" ],
  "key3": true
}
```

Can be represented in its [URL-encoded](http://tools.ietf.org/html/rfc3986)
format as:

```http
key1=1&key2=value2A&key2=value2B&key3=true
```

Or more formally:

* _strings_: should be encoded in [UTF-8](http://tools.ietf.org/html/rfc2279)]
  and then _URL-encoded_. For example `user@example.org` will be represented
  as `user%40example.org` while the Japanese name `山田太郎` will be represented
  as `%E5%B1%B1%E7%94%B0%E5%A4%AA%E9%83%8E`.

* _numbers_: should be represented precisely as in _JSON_. For example `1`,
  `-123.456` and `123e45` are all valid numbers

* _booleans_: should be identified as `true` or `false`.

* _arrays_: the same key should be transmitted multiple times, as in the
 example _JSON_ object above.

Additionally, while it might be possible to specify parameters encoded in
`application/x-www-form-urlencoded` in the query part of the request URLs,
this method _MUST NOT_ be supported, as request URLs are normally logged by
servers and proxies, and thus potentially disclosing sensitive information
inadvertently.



4. Hashing
==========

Throughout this document we will refer to _hashing algorithms_.

Hashing algorithms are identified their name, case insensitive, and this
specification recognizes the following names:

* `MD5`: from [RFC-1321](http://tools.ietf.org/html/rfc1321)
* `SHA1`: from [RFC-3174](http://tools.ietf.org/html/rfc3174)
* `SHA224`, `SHA256`, `SHA384` and `SHA512`: from [RFC-4634](http://tools.ietf.org/html/rfc4634)
* `SHA3-224`, `SHA3-256`, `SHA3-384`, `SHA3-512`: from **FIPS 202**.

Other [hashing functions](http://en.wikipedia.org/wiki/List_of_hash_functions)
_MAY_ be supported by clients and/or server but their identification is left
unspecified in this document.


4.1. Exchange hash algorithm
----------------------------

In the _[Session Creation](#9-1-session-creation)_ phase of the algorithm the
client and server negotiate a hashing algoritm to perform the steps necessary
in the _[Session Authentication](#9-2-session-authentication)_.

This specification requires that all client and server implementations _MUST_
support `SHA256` and `SHA512` as exchange hashes, while `MD5` and `SHA1`
_SHOULD NOT_ be used, due to their relative vulnerabilities which led to their
deprecation by NIST and other sources.

The `HASH(data)` function used throughout this document identifies the hashing
function associated with the algorithm negotiated between client and server
during the _[Session Creation](#9-1-session-creation)_ phase.


4.2. HMAC
---------

The `HMAC(key, message)` function used throughout the document is described by
[RFC-2104](http://tools.ietf.org/html/rfc2104) and its underlying _hashing
function_ is identified by the _exchange hash_ negotiated between client and
server during the _[Session Creation](#9-1-session-creation)_ phase and
described [above](#4-1-exchange-hash-algorithm).

The two parameters `key` and `message` respectively identify the `K` and `text`
variables outlined in [RFC-2104's section 2](http://tools.ietf.org/html/rfc2104#section-2)



5. Key Derivation Functions
===========================

[SCRAM](http://tools.ietf.org/html/rfc5802) forces the use of
[PBKDF2](http://tools.ietf.org/html/rfc2898#section-5.2), and while this
specification does not define the way in which credentials and passwords are
hashed, it defines the formal way in which some of the most used functions
should be represented.

The details of how a password was originally hashed by the server _MUST_ be
transmitted to the client in the _[Session Creation](#9-1-session-creation)_
phase.

We will identify this as a _KDF Specification_ and this document defines it to
be a JSON structure containing at least the key `function`, whose value (case
insensitive) uniquely identifies the Key Derivation Function to use and its
parameters.

Additionally, the `salt` key (optional, but always specified in the three
examples below) is defined to be some random data that was used as additional
input to the function when hashing the password.

The `KDF(password, salt)` function used throughout this document identifies
the key derivation function associated with the specification transmitted by
the server during the _[Session Creation](#9-1-session-creation)_ phase (this
assumes that all key derivation functions require a _salt_).


Depending on the _KDF Algorithm_ the _KDF Specification_ JSON _MAY_ include
additional keys, and this specification outlines three of such methods.


5.1. Password Based Key Derivation Function 2
---------------------------------------------

For [PBKDF2](http://tools.ietf.org/html/rfc2898#section-5.2) the formal
definition of its _KDF Specification_ is as follows:

* `function`: The string `PBKDF2` (case insensitive).
* `hash`: The hasing function used to derive the key, as one of the hashing
   algorithms described in [section 4](#4-hashing).
* `salt`: The random data that was used as additional input to the function
   when hashing the password, encoded in _BASE-64-URL_.
* `iterations`: The number of iterations emploeyed by the function.
* `derived_key_length`: The number of bytes of the derived key.

For example, the representation of the last test vector described in
[RFC-6070](http://tools.ietf.org/html/rfc6070) would be:

```json
"kdf_specification": {
  "function":           "PBKDF2",
  "hash":               "SHA1",
  "salt":               "c2EAbHQ",
  "iterations":         4096,
  "derived_key_kength": 16
}
```


5.2. Colin Percival's SCrypt
----------------------------

For [SCrypt](http://www.tarsnap.com/scrypt.html) the formal definition of its
_KDF Specification_ is as follows:

* `function`: The string `SCRYPT` (case insensitive).
* `hash`: The hasing function used to derive the key, as one of the hashing
   algorithms described in [section 4](#4-hashing).
* `salt`: The random data that was used as additional input to the function
   when hashing the password, encoded in _BASE-64-URL_.
* `cost`: The CPU and memory cost parameter `N`.
* `block_size`: The block size parameter `R`.
* `parallelization`: The parallelization parameter `P`.
* `derived_key_length`: The number of bytes of the derived key.


For example, the representation of the last test vector described in its
[specification](http://www.tarsnap.com/scrypt/scrypt.pdf) would be:

```json
"kdf_specification": {
  "function":           "SCRYPT",
  "hash":               "SHA256",
  "salt":               "U29kaXVtQ2hsb3JpZGU",
  "cost":               1048576,
  "block_size":         8,
  "parallelization":    1,
  "derived_key_length": 64
}
```


5.3. BCrypt
-----------

For [BCrypt](http://en.wikipedia.org/wiki/Bcrypt) the formal definition of its
_KDF Specification_ is as follows:

* `function`: The string `BCRYPT` (case insensitive).
* `hash`: (_optional_) The hasing function applied to the password _before_
   it is passed to the BCrypt function, as one of the hashing algorithms
   described in [section 4](#4-hashing). Defaults to no pre-hashing.
* `salt`: The random (128 bit long) data that was used as additional input
   to the function when hashing the password, encoded in _BASE-64-URL_.
* `cost`: A number representing _BCrypt_'s cost parameter.

The `hash` parameter in this particular case is optional, but widely used in
several implementations, as the [BCrypt](http://en.wikipedia.org/wiki/Bcrypt)
function limits its password input to either 56 or 72 bytes.

```JSON
"kdf_spec": {
  "function": "BCRYPT",
  "salt":     "st3dXjLkbOzhbPWFxDvf9g",
  "cost":     10
}
```


6. Digital Signatures and Encryption
====================================

The [SCRAM](http://tools.ietf.org/html/rfc5802) API relies on _channel binding_
for additional verification of the server (in other words the whole exchange
can be verified using the SSL exchange of the transport).

In _HTTPS_ this might be unrealistic as API requests might be proxied (think
for example of CDN deployments, load balancers, reverse proxies, ...) and the
server performing authentication _MIGHT_ not have access to the private key
securing the connection to the client.

This specification, therefore, relies on the proposed standard for
[JSON Web Signatures](https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41) and
[JSON Web Encryption](https://tools.ietf.org/html/draft-ietf-jose-json-web-encryption-40)
in order to validate (or encrypt) the exchange between server and clients.

Servers implementing this specification _SHOULD_ always sign the required
values using a proper `alg` from the _Json Web Algorithms_ specification under
[section 3.1](https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-40#section-3.1)
(for example `RS256`, or `ES256`), while clients _MAY_ use the `none` algorithm
to identify that they are not configured to sign the values exchanged (see
[Unsecured JWS](https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41#appendix-A.5)).

With regards to encryption, this specification does not describe a way how
encryption keys can be exchanged between server and clients. Such exchange is
out of the scope of this API.

The `typ` parameter in the scope of this specification shall always be the
string `json` or `application/json`, representing the nature of the payload
that will be signed.

// TODO

Finally, the `kid` parameter shall represent the _SHA1_ fingerprint of the
X.509 (DER) encoding of the _public key_ which can be used to verify the _JWS_.

The payload to be signed shall always be a _JSON_ object, and its _UTF-8_
encoding _MUST_ be used as the binary input for signature genration.



7. Server Configuration
=======================

It is assumed that the server providing authentication is configured with the
following data:

* `exchange_hash`: The hashing algorithm that clients should use when
   authenticating, as outlined in [section 4.1](#4-1-exchange-hash-algorithm).

* `shared_key`: A sequence of bytes used by the clients to authenticate
   themselves; this document recommends a random sequence of at least the same
   number of bytes as produced by the `exchange_hash` function.
   The [SCRAM](http://tools.ietf.org/html/rfc5802) specification defines this
   to be the hard-coded constant `Client Key`.

* `signing_key`: A sequence of bytes used by the clients to validate responses
   from the server; this document recommends a random sequence of at least the
   same number of bytes as produced by the `exchange_hash` function.
   The [SCRAM](http://tools.ietf.org/html/rfc5802) specification defines this
   to be the hard-coded constant `Server Key`.

* `private_key` and `public_key`: A keypair used to sign the response by the
   server, as outlined in [section 6](#6-digital-signatures-and-encryption)

Please note that `exchange_hash`, `shared_key` are actually transmitted by the
server to the client by this API.

The `signing_key` is never transmitted by the API, but _SHOULD_ be configured in
clients to perform [server proof verification](#9-3-server-proof-verification).

In the same way, the `public_key` used to validate signatures _SHOULD_ also be
configured into clients. The server only transmits its _SHA1_ fingerprint, as
outlined in [section 6](#6-digital-signatures-and-encryption).

The `private_key` should never be exposed beyond the realms of the server.



8. Password Storage
===================

In order to protect the integrity of the original plain-text passwords the
server _MUST_ only store cryptographically secure values derived from it.

In addition to this, as the result of the _Key Derivation Function_ over
the plain-text password could be used as a _password equivalent_ in the
[SCRAM](http://tools.ietf.org/html/rfc5802) negotiation, the server _SHOULD
NOT_ store this value directly, but rather only keep values derived from it.

Assuming that the server is configured to use specific hashing and key
derivation functions, and has generated a random `salt` value, it should
proceed as follows:

```makefile
salted_password := KDF  ( password, salt )
client_key      := HMAC ( salted_password, shared_key )

stored_key      := HASH ( client_key )
server_key      := HMAC ( salted_password, signing_key )
```

The server can then simply store the `stored_key`, which will be sufficient for
authentication of clients, and the `server_key` that will be used to proove to
clients its knowledge of the original password.



9. API Overview
===============

The first _HTTP_ request and response pair (later called _Session Creation_)
is the equivalent of the `client-first` and `server-first` message exchange in
[SCRAM](http://tools.ietf.org/html/rfc5802).

The second _HTTP_ request and respons pair (later called _Session
Authentication_) is the equivalent of the `client-final` and `server-final`
message exchange in [SCRAM](http://tools.ietf.org/html/rfc5802).


9.1. Session Creation
---------------------

During this first interaction, client informs the server of the desire to
perform an authentication operation sending a _POST_ to a well-known _URL_
transmitting the following:

* `version`: Always `1`, the version number of this specification.
* `request`: A _JWS_ or _JWE_ structure enclosing and signing or encrypting
   a _JSON_ object containing:
  * `user`: A unique identifier for the user to be authenticated
     as outlined in [section 2](#2-core-definitions).
  * `client_nonce`: A random sequence of at least 32 bytes generated by the
     client that will be used to derive a key protecting the exchange,
     encoded in _BASE-64-URL_.
  * `x-...`: _(optional)_ Any extra information the client needs to transfer
     to the server in order to perform authentication, as described in
     [section 11](#11-non-standard-extensions)

The response from the server _MUST_ be either one of:

* `201 Created`: A session was created by the server and the client shall
   continue attempting authentication using the URL specified in the
   `Location` header of the response This is known as the _Session URL_.
* `400 Bad Request`: A required parameter was not specified or was not valid.
* `401 Unauthorized`: The server failed to verify the signature of the _JWS_
   or decrypt the _JWA_ `request` token.
* `405 Method Not Allowed`: If the _HTTP_ method was not `POST`.
* `503 Service Unavailable`: The server is rejecting the session creation
   operation, for example when rate limiting is in place. A `Retry-After`
   header _CAN_ be included in the response to inform the client of such
   time restrictions.

The body of a successful `201 Created` response includes the following:

* `version`: Always `1`, the version number of this specification.
* `response`: A _JWS_ or _JWE_ structure enclosing and signing or encrypting
   a _JSON_ object containing:
  * `exchange_hash`: The hashing function to be used outlined in
     [section 4.1](#4-1-exchange-hash-algorithm).
  * `kdf_specification`: The specification for a _one-way_ function that hashes
     a password as typed by an end user (a _Key Derivation Function_) as
     outlined in [section 5](#5-key-derivation-functions).
  * `server_nonce`: A random sequence of at least the same number of bytes
     produced by the `exchange_hash` function (or 32 bytes, whichever is
     greater) generated by the server that will be used to derive a key
     protecting the exchange, encoded in _BASE-64-URL_.
  * `shared_key`: The key used by the server to protect the stored information,
     outlined in [section 7](#7-server-configuration) encoded in _BASE-64-URL_.
  * `require_otp`: _(optional)_ A boolean value (defaults to `false`) indicating
     that the server requires the additional validation of a _one time password_
     as detailed in [section 10](#10-one-time-password-support). If `false` or
     not present, no such requirement exists.
  * `x-...`: _(optional)_ Any extra information the server needs to transfer
     to the client in order to perform authentication, as described in
     [section 11](#11-non-standard-extensions)

The server _SHOULD_ issue a `400 Bad Request` response only in the following
scenarios:

* The `version` was not specified, or was not `1`.
* The `request` token was not a valid _JWS_ or _JWE_.
* The `user` was not specified, or was an empty string.
* The `client_nonce` was not specified, or was not properly encoded in
  _BASE-64-URL_, or it was less than 32 bytes.

In order not to disclose potentially sensitive information, the server _SHOULD_
respond with a `201 Created` response (with placeholder or invalid data) if
the `user` was not recognized by the server.


### Session Creation Example

A client _Session Creation_ request will look like:

```http
POST /login HTTP/1.1
Content-Type: application/json; charset=UTF-8

{
  "version": 1,
  "request": "...(the JWS/JWE structure for session creation request)..."
}
```

The content enclosed and signed by/encrypted in the `request` _JWS_/_JWE_:

```json
{
  "user": "...(the user identifier)...",
  "client_nonce": "...(at least 32 bytes encoded in BASE-64-URL)...",
  "x-...": "...(any additional information to be transmitted to the server)..."
}
```

A valid response from the server:

```http
HTTP/1.1 201 Created
Location: /login/sessions/...(the unique identifier of the session)...
Content-Type: application/json; charset=UTF-8

{
  "version": 1,
  "response": "...(the JWS/JWE structure for session creation response)..."
}
```

The content enclosed and signed by/encrypted in the `response` _JWS_/_JWE_:

```json
{
  "exchange_hash": "...(the hash to use for validation)...",
  "kdf_specification": {
    "function": "...(the kdf function used to hash the password)...",
    "salt":     "...(the salt used to hash the password, if needed)...",
    "...":      "...(any other parameter to drive key derivation)..."
  },
  "server_nonce": "...(at least N bytes encoded in BASE-64-URL)...",
  "shared_key": "...(the shared_key known by the server,  encoded in BASE-64-URL)...",
  "x-...": "...(any additional information to be transmitted to the client)..."
}
```



9.2. Session Authentication
---------------------------

Once a session is initialized, and the client has retrieved the required `hash`,
`server_nonce`, `kdf_specification`, and obtained a `password` from the user,
the client should compute the following values:

```makefile
# The "user" and "client_nonce" were transmitted during session creation
# The "server_nonce" was included in the server's reply to session creation
auth_message := CONCAT ( user, client_nonce, server_nonce )

# The resulting hashed password, applying a key derivation function
salted_password := KDF ( password, salt )

# The client key (and derived stored key) the server will use to authenticate
client_key         := HMAC ( salted_password, shared_key )
derived_stored_key := HASH ( client_key )

# Per-session masking of the derived stored key
client_signature := HMAC ( derived_stored_key, auth_message )
client_proof     := XOR  ( client_key, client_signature )
```

The `client_proof` is the value that will need to be transmitted to the server,
and to do so the client will prepare a _JSON_ object containing:

* `version`: Always `1`, the version number of this specification.
* `request`: A _JWS_ or _JWE_ structure enclosing and signing or encrypting
   a _JSON_ object containing:
  * `user`: The same identifier specified in the _Session Creation_ phase.
  * `client_nonce`: The same value specified in the _Session Creation_ phase.
  * `server_nonce`: The same `server_nonce` value as received from the server
     in the _Session Creation_ phase.
  * `client_proof`: The proof derived by the client from the original (or
     salted) password encoded in _BASE-64-URL_.
  * `client_otp_proof`: _(optional)_ The proof derived from a _one time
     password_, as outlined in [section 10](#10-one-time-password-support)
  * `x-...`: _(optional)_ Any extra information the client needs to transfer
     to the server in order to perform authentication, as described in
     [section 11](#11-non-standard-extensions), including all the extra keys
     that were specified in the _Session Creation_ phase.

The server _SHOULD_ be validating the appropriateness of the _Session URL_
at which the request was received (see [section 9.4](#9-4-session-urls) below),
and the correctness of the `request` _JWS_ or _JWE_ structure specified by the
client.

After retrieving the `stored_key` from its underlying passwords storage as
outlined in [section 8](#8-password-storage), it should compute the following
in order to authenticate the session:

```http
# The "user" and "client_nonce" were received during session creation
# The "server_nonce" was included in the server's reply to session creation
auth_message := CONCAT ( user_id, client_nonce, server_nonce )

# The "stored_key" is known by the server
server_signature := HMAC ( stored_key, auth_message )

# The "client_proof" was received from the client in session authentication
derived_client_key := XOR ( client_proof, server_signature )

# The derived stored key to match for authentication
derived_stored_key := HASH ( derived_client_key )
```

If the calculated `derived_stored_key` matches exactly the `stored_key` known
by the server, we can guarantee that the client derived correctly (or was aware
of the) `salted_password` associated with the user.

If the authentication is successful, the server _MAY_ need to compute the a
`server_proof` which _COULD_ be required by the client in order to trust
that the server had (at one point) access to the same salted password the
client calculated. It therefore retrieves the `server_key` outlined in
[section 8](#8-password-storage) and calculates:

```
server_proof := HMAC ( server_key, auth_message )
```

At this point, the server prepares a response, which can be one of:

* `200 Ok`: The session was authenticated by the server.
* `400 Bad Request`: A required parameter was not specified or was not valid.
* `401 Unauthorized`: If the session could not be authenticated, either because
   of an invalid _JWS_ signature/_JWE_ encryptopm, or invalid `client_proof`,
   or because the _Session URL_ was unknown to (or could not be verified by)
   the server.

The body of a succesful `200 Ok` response will be a _JSON_ including:

* `version`: Always `1`, the version number of this specification.
* `response`: A _JWS_ or _JWE_ structure enclosing and signing or encrypting
   a _JSON_ object containing:
  * `server_proof`: _(optional)_ The calculated proof informing the client that
     the server had (at one point) access to the salted password
  * `server_otp_proof`: _(optional)_ The calculated proof informing the client
     that the server can generate the same one-time password as the client.
  * `x-...`: _(optional)_ Any extra information the server needs to transfer
     to the client, as described in [section 11](#11-non-standard-extensions).

The server only needs to transmit the `server_proof` and `server_otp_proof` if
it knows the client _requires_ them (for example, after validating the request's
_JWS_ signature).

The server _SHOULD_ issue a `400 Bad Request` response only in the following
scenarios:

* The `version` was not specified, or was not 1.
* The `request` token was not a valid _JWS_ or _JWE_.
* The `user` key was not specified, or its value was an empty string.
* One of the required `client_nonce`, `server_nonce`, or `client_proof`
  parameters was not specified, or was not properly encoded in BASE-64.

A `404 Not Found` _SHOULD NOT_ be used as a response for invalid sessions, as
such a response _MAY_ be used to potentially harvest sensitive information from
the server.



### Session Authentication Example

A client _Session Authentication_ request will look like:

```http
POST /login/session/...(the unique identifier of the session)... HTTP/1.1
Content-Type: application/json; charset=UTF-8

{
  "version": 1,
  "request": "...(the JWS/JWE structure for session authentication request)..."
}
```

The content enclosed and signed by/encrypted in the `request` _JWS_/_JWE_:

```json
{
  "user": "...(the user identifier from session creation)...",
  "client_nonce": "...(the client nonce from session creation)...",
  "server_nonce": "...(the the same nonce received from the server)...",
  "client_proof": "...(the proof calculated by the client in _BASE-64-URL_)...",
  "client_otp_proof": "...(the optional client one time password proof)...",
  "x-...": "...(any additional information to be transmitted to the server)..."
}
```

A valid response from the server:

```http
HTTP/1.1 200 Ok
Content-Type: application/json; charset=UTF-8

{
  "version": 1,
  "response": "...(the JWS/JWE structure for session authentication response)..."
}
```

The content enclosed and signed by/encrypted in the `response` _JWS_/_JWE_:

```json
{
  "server_proof": "...(the proof calculated by the server in BASE-64-URL)...",
  "server_otp_proof": "...(the one time password proof calculated by the server)...",
  "x-...": "...(any additional information to be transmitted to the client)..."
}
```


9.3. Server Proof Verification
------------------------------

Clients willing to do so _MAY_ be able to verify the authenticity of the
`server_proof` transmitted by the server.

This step requires the client's knowledge of the `signing_key`, which is not
transmitted by this API but should be exchanged via a different channel.

The client can generate a `derived_server_proof` using said `signing_key` and
the `salted_password` calculated in [section 9.2](#9-2-session-authentication):

```
derived_server_key   := HMAC ( salted_password, signing_key )
devived_server_proof := HMAC ( derived_server_key, auth_message )
```

If the `derived_server_proof` matches the `server_proof` received
from the server the client can be sure that at one point the server had access
to the calculated `salted_password` and `signing_key`.



9.4. Session URLs
-----------------

Please note that in order to improve security, the _Session URL_ returned by
the server _SHOULD NOT_ be predictable (in other words, they should not be
derived from a timestamp or a sequential counter).

_Session URLa_ _SHOULD_ also be valid only for a restricted amount of time,
after which they _MUST_ be considered invalid.

Server implementations _MAY_ choose to return session URLs containing a
verifiable fingerprint of the exchange, as all the keys transmitted by the
client during this phase, and the returned `server_nonce` will be retransmitted
verbatim again during the _Session Authentication_ phase.

If servers choose to use such an approach, they should be also employing a way
to timeout sessions after a pre-determined amount of time and blacklist
sessions at once after a successful (or failed) authentcation is performed
against them.

For example:

```
session_secret     := ... a secret known only to the server...
session_expiration := ... a timestamp when the session expores...

# The "user", "client_nonce" and "server_nonce" will be returned by the client,
# while "session_expiration" will be encoded in the session URL below
session_id        := CONCAT ( user, client_nonce, server_nonce, session_expiration )
session_signature := HMAC ( session_secret, session_id )

# Combine the values to return a URL
session_url := CONCAT ( "/login/session/", session_expiration, ".", BASE-64-URL(session_signature) )
```

The server could _trivially_ verify the validity of such a _Session URL_ and
would only need to blacklist the `session_signature` value (for example in
a cache) until its expiration.





10. One-Time Password Support
=============================

When a server requires the additional verification of a _one time password_,
specifying a `true` (boolean) value for the `require_otp` key of the _Session
Creation_ response, the client should obtain such value.

This specification defines the `otp_password` as the UTF-8 encoding of the
string produced by the [TOTP](http://tools.ietf.org/html/rfc6238) or
[HOTP](http://tools.ietf.org/html/rfc4226) algorithms (henceforth, a sequence
of numbers of a pre-agreed length, derived from a shared secret).

Before sending its _Session Authentication_ packet, the client computes the
following values:

```
# The client key (and derived stored key) the server will use to authenticate
client_otp_key        := HMAC ( otp_password, shared_key )

# Per-session masking of the derived stored key
client_otp_signature  := HMAC ( client_otp_key, auth_message )
client_otp_proof      := XOR  ( client_otp_key, client_otp_signature )
```

It therefore performs the same computation for the `client_proof`, simply
replacing the `salted_password` with the `otp_password`.

The `client_otp_proof`, encoded in _BASE-64-URL_ is then added to the
_JSON_ enclosed in the `request` _JWS_ or _JWE_ as previously described in
[section 9.2](9-2-session-authentication).

The server then determines the original value of the one-time password
using the same mechanism and secret used by the end user in order to generate
one (or multiple) possible values.

Multiple values _MAY_ be generated by the server in order to accomodate for
time drift (in case of [TOTP](http://tools.ietf.org/html/rfc6238)) or
counter drift (in case of [HOTP](http://tools.ietf.org/html/rfc4226)).

For each of those values (`otp_password` below) it then computes the following:

```
# Performed for each otp password, the shared key is the same used for passwords
server_otp_key         := HMAC ( otp_password, shared_key )

server_otp_signature   := HMAC ( server_otp_key, auth_message )

derived_client_otp_key := XOR ( client_otp_proof, server_otp_signature )
```

If one of the computed `derived_client_otp_key` matches the `server_otp_key`
then the server can be sure that the client had access to the original
`otp_password`.

With regards to the `server_otp_proof`, once the server has found the correct
`server_otp_value` from the multiple ones it _MAY_ have generated, the proof
is calculated as follows:

```
signed_otp_key   := HMAC ( otp_password, signing_key )
server_otp_proof := HMAC ( signed_otp_key, auth_message )
```

Any client configured with the `signing_key` as outlined previously in
[section 9.3](9-3-server-proof-verification) can apply the same calculation
and validate that the `server_otp_proof` received from the server matches.



11. Non-Standard Extensions
===========================

As outlined above outlining the [session creation](#9-1-session-creation) phase
and the [session authentication](#9-2-session-authentication) one, request and
response entities _MAY_ include additional `x-...` prefixed keys.

While this specification does not determine what kind of information may be
exchanged in those values, it permits their presentce as _non-standard
extensions_.

Client and server implementations are free to exchange any additional piece
of information as long as the _JSON_ keys identifying them in the `request`
and `response` entities are prefixed by `x-...`.
