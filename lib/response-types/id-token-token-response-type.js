'use strict';

/**
 * Module dependencies.
 */

var InvalidArgumentError = require('../errors/invalid-argument-error');
var url = require('url');
var debug = require('debug')('oauth2-server: id-token-token-response-type');

/**
 * Constructor.
 */

function IDTokenTokenResponseType(id_token, token) {
	if (!id_token) {
    throw new InvalidArgumentError('Missing parameter: `id_token`');
  }
  if (!token) {
    throw new InvalidArgumentError('Missing parameter: `token`');
  }

  this.id_token = id_token;
  this.token = token;
}

/**
 * Build redirect uri.
 */

IDTokenTokenResponseType.prototype.buildRedirectUri = function(redirectUri) {
  debug("======IDTokenTokenResponseType: buildRedirectUri======")
  if (!redirectUri) {
    throw new InvalidArgumentError('Missing parameter: `redirectUri`');
  }

  var uri = url.parse(redirectUri, true);
  uri.query.token_type = "Bearer";
  if (this.token.accessTokenExpiresAt) {
    uri.query.expires_in = this.token.accessTokenExpiresAt.toString();
  }
  uri.query.id_token = this.id_token;
  uri.query.access_token = this.token.accessToken;

  uri.search = null;

  return uri;
};

/**
 * Export constructor.
 */

module.exports = IDTokenTokenResponseType;
