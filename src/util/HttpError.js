'use strict';

const util = require('util');

/* ========================================================================== *
 * Known HTTP Status codes.                                                   *
 * ========================================================================== */

var httpCodes = {
  "100": "Continue",
  "101": "Switching Protocols",
  "102": "Processing",
  "200": "OK",
  "201": "Created",
  "202": "Accepted",
  "203": "Non Authoritative Information",
  "204": "No Content",
  "205": "Reset Content",
  "206": "Partial Content",
  "207": "Multi Status",
  "208": "Already Reported",
  "226": "IM Used",
  "300": "Multiple Choices",
  "301": "Moved Permanently",
  "302": "Found",
  "303": "See Other",
  "304": "Not Modified",
  "305": "Use Proxy",
  "307": "Temporary Redirect",
  "308": "Permanent Redirect",
  "400": "Bad Request",
  "401": "Unauthorized",
  "402": "Payment Required",
  "403": "Forbidden",
  "404": "Not Found",
  "405": "Method Not Allowed",
  "406": "Not Acceptable",
  "407": "Proxy Authentication Required",
  "408": "Request Timeout",
  "409": "Conflict",
  "410": "Gone",
  "411": "Length Required",
  "412": "Precondition Failed",
  "413": "Payload Too Large",
  "414": "URI Too Long",
  "415": "Unsupported Media Type",
  "416": "Range Not Satisfiable",
  "417": "Expectation Failed",
  "422": "Unprocessable Entity",
  "423": "Locked",
  "424": "Failed Dependency",
  "425": "Unordered Collection",
  "426": "Upgrade Required",
  "428": "Precondition Required",
  "429": "Too Many Requests",
  "431": "Request Header Fields Too Large",
  "451": "Unavailable For Legal Reasons",
  "500": "Internal Server Error",
  "501": "Not Implemented",
  "502": "Bad Gateway",
  "503": "Service Unavailable",
  "504": "Gateway Timeout",
  "505": "HTTP Version Not Supported",
  "506": "Variant Also Negotiates",
  "507": "Insufficient Storage",
  "508": "Loop Detected",
  "509": "Bandwidth Limit Exceeded",
  "510": "Not Extended",
  "511": "Network Authentication Required"
}

/* ========================================================================== *
 * Our basic "HttpError" class                                                *
 * ========================================================================== */

function mergeStack(error, cause) {
  if (! cause) return;
  var stack = error.stack || error.toString();
  if (util.isError(cause)) {
    stack += '\n  Caused by ' + (cause.stack || cause.toString());
  } else {
    stack += '\n  Caused by [' + typeof(cause) + '] ' + cause.toString();
  }
  Object.defineProperty(error, 'stack', {
    enumerable: false,
    configurable: true, // leave configurable
    value: stack
  });
}

function HttpError(status, message, cause) {
  if (!(this instanceof HttpError)) return new HttpError(status, message, cause);

  var _status;
  var _message;
  var _cause;
  var pos = 0;

  /* Process the status */
  if (httpCodes[arguments[pos]]) {
    _status = parseInt(arguments[pos]);
    _message = httpCodes[_status];
    pos ++;

  } else if (util.isNumber(arguments[pos])) {
    _status = parseInt(arguments[pos]);
    _message = "Unknown Error";
    pos ++;

  } else if (/^\d\d\d$/.test(arguments[pos])) {
    _status = parseInt(arguments[pos]);
    _message = "Unknown Error";
    pos ++;
  }

  /* Process the message (any non error) */
  if (arguments[pos] && (!util.isError(arguments[pos]))) {
    _message = arguments[pos];
    pos ++;
  }

  /* Process the cause */
  if (arguments[pos]) {
    _cause = arguments[pos];
    pos ++;
  }

  /* Remember the status, message and cause (if any) */
  if (_status) Object.defineProperties(this, {
    'status': {
      enumerable: false,
      configurable: false,
      value: _status
    },
    'name': {
      enumerable: false,
      configurable: false,
      value: 'HTTP ' + _status,
    }
  });

  if (_message) Object.defineProperty(this, 'message', {
    enumerable: false,
    configurable: false,
    value: _message
  });

  if (_cause) Object.defineProperty(this, 'cause', {
    enumerable: false,
    configurable: false,
    value: _cause
  });

  /* Build up our properties */
  Error.call(this, message);
  Error.captureStackTrace(this, HttpError);

  /* Instrument the caller's stack */
  mergeStack(this, _cause);

};

HttpError.prototype = Object.create(Error.prototype);
HttpError.prototype.constructor = HttpError;
HttpError.prototype.message = 'Internal Server Error';
HttpError.prototype.status = 500;
HttpError.prototype.name = 'HTTP 500';

HttpError.prototype.toJSON = function() {
  return {
    message: this.message,
    status: this.status
  };
}

/* ========================================================================== *
 * Subclass "HttpError" for each known status code                            *
 * ========================================================================== */

/* Create an HTTP error */
function makeHttpError(code, name, defaultMessage) {

  function StatusError(message, cause) {
    if (!(this instanceof StatusError)) return new StatusError(message, cause);

    /* In case we were called with only a cause */
    if (util.isError(message) && (cause == null)) {
      cause = message;
      message = null;
    }

    /* Remember the message (if any) */
    if (message) Object.defineProperty(this, 'message', {
      enumerable: false,
      configurable: false,
      value: message
    });

    /* Remember the cause (if any) */
    if (cause) Object.defineProperty(this, 'cause', {
      enumerable: false,
      configurable: false,
      value: cause
    });

    /* Build up our properties */
    HttpError.call(code, this, message, cause);
    Error.captureStackTrace(this, StatusError);

    /* Instrument the caller's stack (again) */
    mergeStack(this, this.cause);
  }

  StatusError.prototype = Object.create(HttpError.prototype);
  StatusError.prototype.constructor = StatusError;
  StatusError.prototype.message = defaultMessage;
  StatusError.prototype.status = parseInt(code);
  StatusError.prototype.name = 'HTTP ' + code;

  StatusError.prototype.toJSON = function() {
    return {
      message: this.message,
      status: this.status
    };
  }

  return StatusError;
}

/* CamelCase a set of strings */
function toCamelCase(string) {
  var array = new Array();
  string.split(/\s+/g).forEach(function (s) {
    array.push(s.charAt(0).toUpperCase() + s.substring(1).toLowerCase());
  });
  return array.join('');
}

/* ========================================================================== *
 * Oue exports                                                                *
 * ========================================================================== */

/* Expose self as a class */
HttpError.HttpError = HttpError;

/* Create a new HttpError for each code/message */
for (var code in httpCodes) {
  var defaultMessage = httpCodes[code];
  var name = defaultMessage.replace(/\s/g, '');

  var httpError = makeHttpError(code, name, defaultMessage);
  var camelCased = toCamelCase(defaultMessage);
  if (camelCased != name) HttpError[camelCased] = httpError;
  HttpError[name] = httpError;
}

/* Export the base class */
exports = module.exports = HttpError;

