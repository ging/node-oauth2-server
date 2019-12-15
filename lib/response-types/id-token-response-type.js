'use strict';

/**
 * Module dependencies.
 */

var InvalidArgumentError = require('../errors/invalid-argument-error');
var url = require('url');
var debug = require('debug')('oauth2-server: id-token-response-type');
<<<<<<< HEAD

=======
>>>>>>> 32555286286bd121f0622e932a513c040e5b6886
/**
 * Constructor.
 */

<<<<<<< HEAD
function IDTokenResponseType(id_token) {
	if (!id_token) {
=======
function IdTokenResponseType(id_token) {
  if (!id_token) {
>>>>>>> 32555286286bd121f0622e932a513c040e5b6886
    throw new InvalidArgumentError('Missing parameter: `id_token`');
  }

  this.id_token = id_token;
}

/**
 * Build redirect uri.
 */

<<<<<<< HEAD
IDTokenResponseType.prototype.buildRedirectUri = function(redirectUri) {
  debug("======IDTokenResponseType: buildRedirectUri======")
=======
IdTokenResponseType.prototype.buildRedirectUri = function(redirectUri) {
  debug("======IdTokenResponseType: buildRedirectUri======")
>>>>>>> 32555286286bd121f0622e932a513c040e5b6886
  if (!redirectUri) {
    throw new InvalidArgumentError('Missing parameter: `redirectUri`');
  }

  var uri = url.parse(redirectUri, true);

  uri.query.id_token = this.id_token;
<<<<<<< HEAD

=======
>>>>>>> 32555286286bd121f0622e932a513c040e5b6886
  uri.search = null;

  return uri;
};

/**
 * Export constructor.
 */

<<<<<<< HEAD
module.exports = IDTokenResponseType;
=======
module.exports = IdTokenResponseType;
>>>>>>> 32555286286bd121f0622e932a513c040e5b6886
