'use strict';

/**
 * Module dependencies.
 */

var InvalidArgumentError = require('../errors/invalid-argument-error');
var url = require('url');
var debug = require('debug')('oauth2-server: code-response-type');
/**
 * Constructor.
 */

function CodeResponseType(code) {
  if (!code) {
    throw new InvalidArgumentError('Missing parameter: `code`');
  }

  this.code = code;
}

/**
 * Build redirect uri.
 */

CodeResponseType.prototype.buildRedirectUri = function(redirectUri) {
  debug("======CodeResponseType: buildRedirectUri======")
  if (!redirectUri) {
    throw new InvalidArgumentError('Missing parameter: `redirectUri`');
  }

  var uri = url.parse(redirectUri, true);
<<<<<<< HEAD
  // REVISAR
=======

>>>>>>> 32555286286bd121f0622e932a513c040e5b6886
  uri.query.code = this.code;
  uri.search = null;

  return uri;
};

/**
 * Export constructor.
 */

module.exports = CodeResponseType;
