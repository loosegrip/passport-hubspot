var OAuth2Strategy = require('passport-oauth2').Strategy
  , util = require('util');


function Strategy(options, verify) {

    options = options || {};
    options.authorizationURL = options.authorizationURL || 'https://app.hubspot.com/oauth/authorize';
    options.tokenURL = options.tokenURL || 'https://api.hubapi.com/oauth/v1/token';
    options.scope = options.scope || ['contacts', 'content', 'reports', 'social', 'automation', 'timeline'];

    OAuth2Strategy.call(this, options, verify);

    this.name = 'hubspot';
    this._skipUserProfile = false;
    this._oauth2._useAuthorizationHeaderForGET = true;
    this._scope = options.scope
}

util.inherits(Strategy, OAuth2Strategy);


/**
 * Retrieve user profile from HubSpot.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `provider`         always set to `hubspot`
 *   - `id`
 *   - `username`
 *   - `displayName`
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */

Strategy.prototype.userProfile = function (accessToken, done) {
  this._oauth2.get(`https://api.hubapi.com/oauth/v1/access-tokens/${accessToken}`,
    accessToken,
    (err, body, res) => {
      if (err) {
        return done(new InternalOAuthError('failed to fetch user profile', err));
      }

      try {
        const json = JSON.parse(body);
        const profile = Object.assign(json, {
          provider: 'hubspot'
        });
        return done(null, profile);
      } catch (e) {
        return done(e);
      }
    });
};

module.exports = Strategy;