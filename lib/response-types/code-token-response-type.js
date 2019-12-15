'use strict';

/**
 * Module dependencies.
 */

var InvalidArgumentError = require('../errors/invalid-argument-error');
var url = require('url');
var debug = require('debug')('oauth2-server: code-token-response-type');
/**
 * Constructor.
 */

function CodeTokenResponseType(code, token) {
  if (!code) {
    throw new InvalidArgumentError('Missing parameter: `code`');
  }
  if (!token) {
    throw new InvalidArgumentError('Missing parameter: `token`');
  }

  this.code = code;
  this.token = token;
}

/**
 * Build redirect uri.
 */

CodeTokenResponseType.prototype.buildRedirectUri = function(redirectUri) {
  debug("======CodeTokenResponseType: buildRedirectUri======")
  if (!redirectUri) {
    throw new InvalidArgumentError('Missing parameter: `redirectUri`');
  }

  var uri = url.parse(redirectUri, true);
  //  QUEDA POR HACER!!!!!***********
  uri.query.token_type = "Bearer";
  if (this.token.accessTokenExpiresAt) {
    uri.query.expires_in = this.token.accessTokenExpiresAt.toString();
  }
  uri.query.access_token = this.token.accessToken;
  uri.query.code = this.code;
  uri.search = null;

  return uri;
};

/**
 * Export constructor.
 */

module.exports = CodeTokenResponseType;
