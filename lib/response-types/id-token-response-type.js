'use strict';

/**
 * Module dependencies.
 */

var InvalidArgumentError = require('../errors/invalid-argument-error');
var url = require('url');
var debug = require('debug')('oauth2-server: id-token-response-type');
/**
 * Constructor.
 */

function IdTokenResponseType(id_token) {
  if (!id_token) {
    throw new InvalidArgumentError('Missing parameter: `id_token`');
  }

  this.id_token = id_token;
}

/**
 * Build redirect uri.
 */

IdTokenResponseType.prototype.buildRedirectUri = function(redirectUri) {
  debug("======IdTokenResponseType: buildRedirectUri======")
  if (!redirectUri) {
    throw new InvalidArgumentError('Missing parameter: `redirectUri`');
  }

  var uri = url.parse(redirectUri, true);

  uri.query.id_token = this.id_token;
  uri.search = null;

  return uri;
};

/**
 * Export constructor.
 */

module.exports = IdTokenResponseType;
