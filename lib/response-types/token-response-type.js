'use strict';

/**
 * Module dependencies.
 */

var InvalidArgumentError = require('../errors/invalid-argument-error');
var url = require('url');

/**
 * Constructor.
 */

function TokenResponseType(token) {
	if (!token) {
    throw new InvalidArgumentError('Missing parameter: `token`');
  }
  
  this.token = token;
}

/**
 * Build redirect uri.
 */

TokenResponseType.prototype.buildRedirectUri = function(redirectUri) {
  if (!redirectUri) {
    throw new InvalidArgumentError('Missing parameter: `redirectUri`');
  }

  var uri = url.parse(redirectUri, true);
  uri.query.token_type = "Bearer" 
  uri.query.expires_in = this.token.client.accessTokenLifetime
  uri.query.token = this.token.accessToken;

  uri.search = null;

  return uri;
};

/**
 * Export constructor.
 */

module.exports = TokenResponseType;
