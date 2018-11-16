'use strict';

/**
 * Module dependencies.
 */

var AbstractGrantType = require('./abstract-grant-type');
var InvalidArgumentError = require('../errors/invalid-argument-error');
var InvalidGrantError = require('../errors/invalid-grant-error');
var InvalidRequestError = require('../errors/invalid-request-error');
var Promise = require('bluebird');
var promisify = require('promisify-any').use(Promise);
var ServerError = require('../errors/server-error');
var is = require('../validator/is');
var util = require('util');
var debug = require('debug')('oauth2-server: implicit-grant-type');

/**
 * Constructor.
 */

function ImplicitGrantType(options) {
  options = options || {};

  if (!options.model) {
    throw new InvalidArgumentError('Missing parameter: `model`');
  }

  if (!options.model.saveToken) {
    throw new InvalidArgumentError('Invalid argument: model does not implement `saveToken()`');
  }

  AbstractGrantType.call(this, options);
}

/**
 * Inherit prototype.
 */

util.inherits(ImplicitGrantType, AbstractGrantType);

/**
 * Handle authorization code grant.
 *
 * @see https://tools.ietf.org/html/rfc6749#section-4.1.3
 */

ImplicitGrantType.prototype.handle = function(request, client, user, scope) {
  debug("======ImplicitGrantType: handle======")

  if (!request) {
    throw new InvalidArgumentError('Missing parameter: `request`');
  }

  if (!client) {
    throw new InvalidArgumentError('Missing parameter: `client`');
  }

  if (!user) {
    throw new InvalidArgumentError('Missing parameter: `user`');
  }

  return Promise.bind(this)
    .then(function() {
      return this.validateRedirectUri(request, client);
    })
    .then(function() {
      return this.saveToken(user, client, scope);
    });
};

/**
 * Validate the redirect URI.
 *
 * "The authorization server MUST ensure that the redirect_uri parameter is
 * present if the redirect_uri parameter was included in the initial
 * authorization request as described in Section 4.1.1, and if included
 * ensure that their values are identical."
 *
 * @see https://tools.ietf.org/html/rfc6749#section-4.1.3
 */

 ImplicitGrantType.prototype.validateRedirectUri = function(request, client) {
  debug("======ImplicitGrantType: validateRedirectUri======")
   if (!client.redirectUri) {
     return;
   }

   var redirectUri = request.body.redirect_uri || request.query.redirect_uri;

   if (!is.uri(redirectUri)) {
     throw new InvalidRequestError('Invalid request: `redirect_uri` is not a valid URI');
   }

   if (redirectUri !== client.redirectUri) {
     throw new InvalidRequestError('Invalid request: `redirect_uri` is invalid');
   }
 };


/**
 * Save token.
 */

ImplicitGrantType.prototype.saveToken = function(user, client, scope) {
  debug("======ImplicitGrantType: saveToken======")

  var fns = [
    this.validateScope(user, client, scope),
    this.generateAccessToken(client, user, scope),
    this.getAccessTokenExpiresAt()
  ];

  return Promise.all(fns)
    .bind(this)
    .spread(function(scope, accessToken, accessTokenExpiresAt) {
      var token = {
        accessToken: accessToken,
        accessTokenExpiresAt: accessTokenExpiresAt,
        scope: scope
      };

      return promisify(this.model.saveToken, 3).call(this.model, token, client, user);
    });
};

/**
 * Export constructor.
 */

module.exports = ImplicitGrantType;
