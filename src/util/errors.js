/* Exports, a new object */
exports = module.exports = {};

/* HTTP Status codes */
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

/* HTTP Status errors */
var httpErrors = {}

/* Create an HTTP error */
function makeHttpError(code, name, defaultMessage) {

  function HttpError(message) {
    if (!(this instanceof HttpError)) return new HttpError(message);

    if (message) Object.defineProperty(this, 'message', {
      enumerable: false,
      configurable: false,
      value: message
    });

    Error.call(this, message);
    Error.captureStackTrace(this, HttpError);
  }

  HttpError.prototype = Object.create(Error.prototype);
  HttpError.prototype.constructor = HttpError;
  HttpError.prototype.message = defaultMessage;
  HttpError.prototype.status = parseInt(code);
  HttpError.prototype.name = 'HTTP ' + code;

  HttpError.prototype.toJSON = function() {
    return {
      message: this.message,
      status: this.status
    };
  }

  return HttpError;
}

/* CamelCase a set of strings */
function toCamelCase(string) {
  var array = new Array();
  string.split(/\s+/g).forEach(function (s) {
    array.push(s.charAt(0).toUpperCase() + s.substring(1).toLowerCase());
  });
  return array.join('');
}

/* Create a new HttpError for each code/message */
for (var code in httpCodes) {
  var defaultMessage = httpCodes[code];
  var name = defaultMessage.replace(/\s/g, '');

  var httpError = makeHttpError(code, name, defaultMessage);
  httpErrors[code] = httpError;

  var camelCased = toCamelCase(defaultMessage);
  if (camelCased != name) exports[camelCased] = httpError;
  exports[name] = httpError;
}

exports.fromStatus = function(status) {
  if (httpErrors[status]) return httpErrors[status]();
  return makeHttpError(status, 'UnknownError', 'Unknown Error')();
}
