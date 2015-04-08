Express Error Log
=================

A very simple logger for [Express](http://expressjs.com/) 4.x, based on
the [`errorlog`](https://www.npmjs.com/package/errorlog) NPM module.

* [Install and use](#install-and-use)
* [Logging and responses](#logging-and-responses)
  * [Numbers](#numbers)
  * [Strings](#strings)
  * [Objects](#objects)
  * [Errors](#errors)
* [Request IDs](#request-ids)
* [Configuration](#configuration)
* [License (MIT)](#license-mit-)



Install and use
---------------

Install as usual with _NPM_:

```bash
npm install --save express-errorlog
```

Then configure as the last route of your Express app:

```javascript
var errorlog = require('express-errorlog');
app.use(errorlog);
```



Logging and responses
---------------------

In order to trigger log entries, simply use Express' own `next(...)` function,
passing one of the the following types of parameter:

#### Numbers

```javascript
app.get('/test', function(req, res, next) {
  next(400); // Simply interrupt with a 400 Bad Request
});
```

The number will be interpreted as the status code of the response. If the number
is less than zero or greater than 599, the response status will be normalized to
a _500 Internal Server Error_.

The response sent back to the client will contain the following:

```json
HTTP/1.1 400 Bad Request
Content-Type: application/json

{
  "status": 400,
  "message": "Bad Request"
}
```

And the log will written with

```text
2015-03-30T16:45:01.661Z - GET /test (400) - Bad Request
```

#### Strings

```javascript
app.get('/test', function(req, res, next) {
  next("Something is wrong"); // Interrupt with a message
});
```

The number will be interpreted as the status message for the response, while the
status will be defaulted to a _500 Internal Server Error_.

The response sent back to the client will contain the following:

```json
HTTP/1.1 500 Internal Server Error
Content-Type: application/json

{
  "status": 500,
  "message": "Something is wrong"
}
```

And the log will written with

```text
2015-03-30T16:45:01.661Z - GET /test (500) - Something is wrong
```

#### Objects

```javascript
app.get('/test', function(req, res, next) {
  var error = new Error('Invalid access for user');
  error.user = 'pier@usrz.com';
  error.token = 'c568019d-3c80-4685-8982-ed455a2c0cd1';

  next({
    status: 403,
    message: 'You have no access, my friend',
    error: error,
    details: {
      example: "... some extra token for the response ..."
    },
  });
});
```

Objects can also be passed directly to the `next(...)` call, having the
following keys:

* `status`: A _number_ representing the status code of the response.
* `message`: The message to transmit to the client.
* `error`: An `Error` that will be logged, but not transmitted to the client.
* `details`: Anything that will be serialized to JSON and sent back alongside
   the response.

In the example above, the response will be:

```json
HTTP/1.1 403 Forbidden
Content-Type: application/json

{
  "status": 403,
  "message": "You have no access, my friend",
  "details": {
    "example": "... some extra token for the response ..."
  }
}
```

And the log will contain something along the following:

```text
2015-03-30T16:45:01.718Z - GET /test (403) - You have no access, my friend
  >>> {"example":"... some extra token for the response ..."}
  >>> {"user":"pier@usrz.com","token":"c568019d-3c80-4685-8982-ed455a2c0cd1"}
  Error: Invalid access for user
    at Error (native)
    at ... stacktrace continues ...
```

In other words, `details` and `error` will be logged  and the `Error`'s stack
trace will be dumped in full. At the same time, note that there is no trace of
the `error` in the response sent back to the client.

#### Errors

```javascript
app.get('/test', function(req, res, next) {
  // Create and instrument an error
  var error = new Error('Something is amiss');
  error.status = 410;
  error.details = {
    example: "... some extra token for the response ..."
  };
  // Equivalent to `next(error);`
  throw error;
});
```

Whether thrown or passed to `next(...)`, exceptions will produce a _500 Internal
Server Error_ unless they expose a `status` property directly and their message
will be sent alongside the response, as:

```json
HTTP/1.1 410 Gone
Content-Type: application/json

{
  "status": 410,
  "message": "Something is amiss",
  "details": {
    "example": "... some extra token for the response ..."
  }
}
```

The log will contain the full details and stack trace of the error:

```text
2015-03-30T16:45:01.718Z - GET /test (410) - Something is amiss
  >>> {"example":"... some extra token for the response ..."}
  Error: Something is amiss
    at Error (native)
    at ... stacktrace continues ...
```



Request IDs
-----------

If the Express' `request` contains the special `id` value (as for example when
using [`express-request-id`](https://www.npmjs.com/package/express-request-id))
said `id` will also be reported, for example:

```text
2015-03-30T16:45:01.661Z - d7c32387-3feb-452b-8df1-2d8338b3ea22 - GET /test (500) - Something is wrong
```



Configuration
-------------

Configure accepts basically the same options as
[`errorlog`](https://www.npmjs.com/package/errorlog):

```javascript
var errorlog = require('express-errorlog');
app.use(errorlog({
  logger: function/stream,
  render: true/false
}));
```

* `logger` may be one of the following:
  * a `Writable` _stream_ to which error messages will be written to (actually
    an object offering a `write(...)` function will do).
  * a simple `function` that will be invoked once with each message to log.
  * if unspecified this will default to `process.stderr`.
* `category`: a category name that will be inserted in the message to log.
* `render`: A _boolean_, if `true` the response will be sent to the client
  using Express' own `render(...)` function (extra for `express-errorlog`).

As with [`errorlog`](https://www.npmjs.com/package/errorlog), use a package
like [`logrotate-stream`](https://www.npmjs.com/package/logrotate-stream) if
log rotation is necessary in your environment.



License (MIT)
-------------

Copyright (c) 2015 USRZ.com and Pier Paolo Fumagalli

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

