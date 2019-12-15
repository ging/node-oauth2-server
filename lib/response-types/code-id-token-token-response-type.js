'use strict';

/**
 * Module dependencies.
 */

var InvalidArgumentError = require('../errors/invalid-argument-error');
var url = require('url');
var debug = require('debug')('oauth2-server: code-id-token-token-response-type');
/**
 * Constructor.
 */

function CodeIDTokenTokenResponseType(code, id_token, token) {
  if (!code) {
    throw new InvalidArgumentError('Missing parameter: `code`');
  }
  if (!id_token) {
    throw new InvalidArgumentError('Missing parameter: `id_token`');
  }
  if (!token) {
    throw new InvalidArgumentError('Missing parameter: `token`');
  }

  this.code = code;
  this.id_token = id_token;
  this.token = token;
}

/**
 * Build redirect uri.
 */

CodeIDTokenTokenResponseType.prototype.buildRedirectUri = function(redirectUri) {
  debug("======CodeIDTokenTokenResponseType: buildRedirectUri======")
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
  
  uri.query.code = this.code;
  uri.search = null;

  return uri;
};

/**
 * Export constructor.
 */

module.exports = CodeIDTokenTokenResponseType;
