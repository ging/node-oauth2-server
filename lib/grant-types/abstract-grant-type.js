'use strict';

/**
 * Module dependencies.
 */
const jsonwebtoken = require('jsonwebtoken');
var InvalidArgumentError = require('../errors/invalid-argument-error');
var InvalidScopeError = require('../errors/invalid-scope-error');
var Promise = require('bluebird');
var promisify = require('promisify-any').use(Promise);
var is = require('../validator/is');
var tokenUtil = require('../utils/token-util');
var debug = require('debug')('oauth2-server: abstract-grant-type');
const crypto = require('crypto');


/**
 * Constructor.
 */

function AbstractGrantType(options) {
  options = options || {};

  if (!options.accessTokenLifetime) {
    throw new InvalidArgumentError('Missing parameter: `accessTokenLifetime`');
  }

  if (!options.model) {
    throw new InvalidArgumentError('Missing parameter: `model`');
  }

  this.accessTokenLifetime = options.accessTokenLifetime;
  this.model = options.model;
  this.refreshTokenLifetime = options.refreshTokenLifetime;
  this.alwaysIssueNewRefreshToken = options.alwaysIssueNewRefreshToken;
  this.atHash = "";
  this.cHash = "";
}

/**
 * Generate access token.
 */

AbstractGrantType.prototype.generateAccessToken = function(client, user, scope) {
  debug("======AbstractGrantType: generateAccessToken======")
  if (this.model.generateAccessToken) {
    return promisify(this.model.generateAccessToken, 3).call(this.model, client, user, scope)
      .then(function(accessToken) {
        //return accessToken || tokenUtil.generateRandomToken();
        if(accessToken){
          //athash
          this.atHash=crypto.createHmac('sha256',client.jwt_secret).update(accessToken).digest('hex');
          return accessToken;
        }else{
          //athash
          var at = tokenUtil.generateRandomToken();
          this.atHash=crypto.createHmac('sha256',client.jwt_secret).update(at).digest('hex');
          return at;
        }
      });
  }

  var at2 = crypto.randomBytes(40).toString("hex");
    debug("AT2"+at2)
    const hash = crypto.createHmac('sha256', client.jwt_secret);
    hash.update(at2.toString());
    this.atHash=hash.digest('hex');
    debug("ACCESS TOKEN HASH"+this.atHash);
    return at2;


};

AbstractGrantType.prototype.generateIDToken = function(user, client, request, code) {
  debug("======AbstractGrantType: generateIDToken======")
  const id_token = JSON.parse(
    JSON.stringify(
      require('../templates/openid_id_token_response.json')
    )
  );
  debug("ID_TOKEN:")
  id_token.iss = "FIWARE-IDM";
  debug(id_token.iss)
  id_token.sub = user.id;
  debug(id_token.sub)
  id_token.aud = client.id;
  debug(id_token.aud)
  id_token.exp = 60*60*24;
  id_token.iat = 60*60*60;
  id_token.email = user.email;
  //debug(Object.values(request));
  //(Object.values(client));
  if((request.query.response_type == 'id_token token') || (request.query.response_type == 'code id_token token')){
    id_token.at_hash =this.atHash;
    debug("AT HASH******"+ this.atHash)
  }

  if((request.query.response_type == 'code id_token') || (request.query.response_type == 'code id_token token')){
    const hash = crypto.createHmac('sha256', client.jwt_secret);
    debug("CODE"+code)
    hash.update(code.toString());
    this.cHash=hash.digest('hex');
    id_token.c_hash =this.cHash;
    debug("C HASH******"+ this.cHash)
  }


  const options = {};

  debug("***JWT_SECRET***"+client.jwt_secret)
  var idToken = jsonwebtoken.sign(
    id_token,
    client.jwt_secret,
    options
  );
  debug("****ID_TOKEN:***" + idToken)
  return idToken;
}

/*AbstractGrantType.prototype.generateIDToken = function (client, user){
  debug("======AbstractGrantType: generateIDToken======")
  //if (this.model.generateIDToken) {
    return promisify(this.model.generateIDToken, 2).call(this.model, client, user)
      .then(function(idToken) {
        return idToken;
      });
  //}
  //return "ERROR GENERANDO ID_TOKEN";
}*/

/**
 * Generate refresh token.
 */

AbstractGrantType.prototype.generateRefreshToken = function(client, user, scope) {
  debug("======AbstractGrantType: generateRefreshToken======")
  if (this.model.generateRefreshToken) {
    return promisify(this.model.generateRefreshToken, 3).call(this.model, client, user, scope)
      .then(function(refreshToken) {
        return refreshToken || tokenUtil.generateRandomToken();
      });
  }

  return tokenUtil.generateRandomToken();
};

/**
 * Get access token expiration date.
 */

AbstractGrantType.prototype.getAccessTokenExpiresAt = function() {
  debug("======AbstractGrantType: getAccessTokenExpiresAt======")
  var expires = new Date();

  expires.setSeconds(expires.getSeconds() + this.accessTokenLifetime);

  return expires;
};

/**
 * Get refresh token expiration date.
 */

AbstractGrantType.prototype.getRefreshTokenExpiresAt = function() {
  debug("======AbstractGrantType: getRefreshTokenExpiresAt======")
  var expires = new Date();

  expires.setSeconds(expires.getSeconds() + this.refreshTokenLifetime);

  return expires;
};

/**
 * Get scope from the request body.
 */

AbstractGrantType.prototype.getScope = function(request) {
  debug("======AbstractGrantType: getScope======")
  if (!is.nqschar(request.body.scope)) {
    throw new InvalidArgumentError('Invalid parameter: `scope`');
  }
debug("SCOPEEEEEEEEEEE"+request.body.scope);
  return request.body.scope;
};

/**
 * Validate requested scope.
 */
AbstractGrantType.prototype.validateScope = function(user, client, scope) {
  debug("======AbstractGrantType: validateScope======")
  debug("SCOPEEEEEEEEEEE"+scope);
  //Creo que esto con openidconnect no seria necesario porque la request al token endpoint no necesita scope???
  if (this.model.validateScope) {
    return promisify(this.model.validateScope, 3).call(this.model, user, client, scope)
      .then(function (scope) {
        if (!scope) {
          throw new InvalidScopeError('Invalid scope: Requested scope is invalid');
        }
        debug("SCOPEEEEEEEEEEE"+scope);
        return scope;
      });
  } else {
    return scope;
  }
};

/**
 * Export constructor.
 */

module.exports = AbstractGrantType;
