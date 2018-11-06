'use strict';

/**
 * Module dependencies.
 */

var InvalidArgumentError = require('../errors/invalid-argument-error');
var InvalidClientError = require('../errors/invalid-client-error');
var InvalidRequestError = require('../errors/invalid-request-error');
var UnauthorizedClientError = require('../errors/unauthorized-client-error');
var UnsupportedGrantTypeError = require('../errors/unsupported-grant-type-error');
var UnauthorizedRequestError = require('../errors/unauthorized-request-error');
var UnsupportedTokenType = require('../errors/unsupported-token-type-error');
var OAuthError = require('../errors/oauth-error');
var Promise = require('bluebird');
var promisify = require('promisify-any').use(Promise);
var Request = require('../request');
var Response = require('../response');
var ServerError = require('../errors/server-error');
var debug = require('debug')('oauth2-server: revoke-handler');
var auth = require('basic-auth');


/**
 * Constructor.
 */

function RevokeHandler(options) {
  debug("=====RevokeHandler=====")
  options = options || {};

  if (!options.model) {
    throw new InvalidArgumentError('Missing parameter: `model`');
  }

  if (!options.model.revokeToken) {
    throw new InvalidArgumentError('Invalid argument: model does not implement `revokeToken()`');
  }

  if (!options.model.getClient) {
    throw new InvalidArgumentError('Invalid argument: model does not implement `getClient()`');
  }

  this.tokenTypesHints = options.tokenTypesHints
}

/**
 * Authenticate Handler.
 */

RevokeHandler.prototype.handle = function(request, response) {
  debug("=====handle=====")
  if (!(request instanceof Request)) {
    throw new InvalidArgumentError('Invalid argument: `request` must be an instance of Request');
  }

  if (!(response instanceof Response)) {
    throw new InvalidArgumentError('Invalid argument: `response` must be an instance of Response');
  }

  let tokenTypeHint;

  return Promise.bind(this)
    .then(function() {
      return this.getClient(request, response);
    })
    .then(function(client) {
      return this.getTokenTypeHintFromRequestBody(request);
    })
    .then(function(type) {
      tokenTypeHint = type
      return this.getTokenFromRequest(request);
    })
    .then(function(token) {
      return this.revokeToken(token, tokenTypeHint);
    })
    .tap(function(token) {
      return this.updateResponse(response, token);
    })
    .catch(function(e) {
      // Include the "WWW-Authenticate" response header field if the client
      // lacks any authentication information.
      //
      // @see https://tools.ietf.org/html/rfc6750#section-3.1
      if (e instanceof UnauthorizedRequestError) {
        response.set('WWW-Authenticate', 'Bearer realm="Service"');
      }

      if (!(e instanceof OAuthError)) {
        throw new ServerError(e);
      }

      throw e;
    });
};

/**
 * Get the client from the model.
 */

RevokeHandler.prototype.getClient = function(request, response) {
  debug("=====getClient=====")
  var credentials = this.getClientCredentials(request);
  var grantType = request.body.grant_type;

  if (!credentials.clientId) {
    throw new InvalidRequestError('Missing parameter: `client_id`');
  }

  if (!request.query.response_type) {
    if(this.isClientAuthenticationRequired(grantType) && !credentials.clientSecret) {
      throw new InvalidRequestError('Missing parameter: `client_secret`');
    }
  }   

  if (!is.vschar(credentials.clientId)) {
    throw new InvalidRequestError('Invalid parameter: `client_id`');
  }
  if (!request.query.response_type) {
    if (credentials.clientSecret && !is.vschar(credentials.clientSecret)) {
      throw new InvalidRequestError('Invalid parameter: `client_secret`');
    }  
  }
  

  return promisify(this.model.getClient, 2).call(this.model, credentials.clientId, credentials.clientSecret)
    .then(function(client) {
      if (!client) {
        throw new InvalidClientError('Invalid client: client is invalid');
      }

      if (!client.grants) {
        throw new ServerError('Server error: missing client `grants`');
      }

      if (!(client.grants instanceof Array)) {
        throw new ServerError('Server error: `grants` must be an array');
      }

      return client;
    })
    .catch(function(e) {
      // Include the "WWW-Authenticate" response header field if the client
      // attempted to authenticate via the "Authorization" request header.
      //
      // @see https://tools.ietf.org/html/rfc6749#section-5.2.
      if ((e instanceof InvalidClientError) && request.get('authorization')) {
        response.set('WWW-Authenticate', 'Basic realm="Service"');

        throw new InvalidClientError(e, { code: 401 });
      }

      throw e;
    });
};

/**
 * Get client credentials.
 *
 * The client credentials may be sent using the HTTP Basic authentication scheme or, alternatively,
 * the `client_id` and `client_secret` can be embedded in the body.
 *
 * @see https://tools.ietf.org/html/rfc6749#section-2.3.1
 */

RevokeHandler.prototype.getClientCredentials = function(request) {
  debug("=====getClientCredentials=====")
  var credentials = auth(request);
  var grantType = request.body.grant_type;

  if (credentials) {
    return { clientId: credentials.name, clientSecret: credentials.pass };
  }

  if (request.body.client_id && request.body.client_secret) {
    return { clientId: request.body.client_id, clientSecret: request.body.client_secret };
  }

  if (!this.isClientAuthenticationRequired(grantType)) {
    if(request.body.client_id) {
      return { clientId: request.body.client_id };
    }
  }

  throw new InvalidClientError('Invalid client: cannot retrieve client credentials');
};

/**
 * Get the token from the header or body, depending on the request.
 *
 * "Clients MUST NOT use more than one method to transmit the token in each request."
 *
 * @see https://tools.ietf.org/html/rfc6750#section-2
 */

RevokeHandler.prototype.getTokenFromRequest = function(request) {
  debug("=====getTokenFromRequest=====")

  var bodyToken = request.body.access_token;

  if (bodyToken) {
    return this.getTokenFromRequestBody(request);
  }

  throw new UnauthorizedRequestError('Unauthorized request: no authentication given');
};

/**
 * Get the token from the request body.
 *
 * "The HTTP request method is one for which the request-body has defined semantics.
 * In particular, this means that the "GET" method MUST NOT be used."
 *
 * @see http://tools.ietf.org/html/rfc6750#section-2.2
 */

RevokeHandler.prototype.getTokenFromRequestBody = function(request) {
  debug("=====getTokenFromRequestBody=====")
  if (request.method === 'GET') {
    throw new InvalidRequestError('Invalid request: token may not be passed in the body when using the GET verb');
  }

  if (!request.is('application/x-www-form-urlencoded')) {
    throw new InvalidRequestError('Invalid request: content must be application/x-www-form-urlencoded');
  }

  return request.body.access_token;
};


/**
 * Get the token type hint from the request body.
 *
 * "The HTTP request method is one for which the request-body has defined semantics.
 * In particular, this means that the "GET" method MUST NOT be used."
 *
 * @see http://tools.ietf.org/html/rfc6750#section-2.2
 */

RevokeHandler.prototype.getTokenTypeHintFromRequestBody = function(request) {
  debug("=====getTokenTypeHintFromRequestBody=====")

  var bodyTokenTypeHint = request.body.token_type_hint;

  if (tokenTypeHint) {
    if (!this.tokenTypesHints.includes(bodyTokenTypeHint)) {
      throw new UnsupportedTokenType('Unauthorized request: invalid token type');
    }
  }

  return bodyTokenTypeHint;
};

/**
 * Revoke access token from the model.
 */

RevokeHandler.prototype.revokeToken = function(token, type) {
  debug("=====revokeToken=====")
  return promisify(this.model.revokeToken, 2).call(this.model, token, type)
    .then(function(revoked) {
      if (!accessToken) {
        throw new InvalidTokenError('Invalid token: access token is invalid');
      }

      if (accessToken.user) {
        return accessToken;
      } else {
        if (accessToken.oauth_client.grant_type.includes('client_credentials')) { 
          return accessToken;
        }
        throw new ServerError('Server error: `revokeToken()` did not return a `user` object');
      }
    });
};

/**
 * Update response.
 */

RevokeHandler.prototype.updateResponse = function(response, accessToken) {
  debug("=====updateResponse=====")
  if (this.scope && this.addAcceptedScopesHeader) {
    response.set('X-Accepted-OAuth-Scopes', this.scope);
  }

  if (this.scope && this.addAuthorizedScopesHeader) {
    response.set('X-OAuth-Scopes', accessToken.scope);
  }
};

/**
 * Given a grant type, check if client authentication is required
 */
RevokeHandler.prototype.isClientAuthenticationRequired = function(grantType) {
  debug("=====isClientAuthenticationRequired =====")
  if (Object.keys(this.requireClientAuthentication).length > 0) {
    return (typeof this.requireClientAuthentication[grantType] !== 'undefined') ? this.requireClientAuthentication[grantType] : true;
  } else {
    return true;
  }
};

/**
 * Export constructor.
 */

module.exports = RevokeHandler;
