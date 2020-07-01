const axios = require('axios');
const R = require('ramda');
const _ = require('lodash');

const APPROLE_LOGIN_URL = '/v1/auth/approle/login';
const IS_TOKEN_ALIVE_URL = '/v1/auth/token/lookup-self';
const SECRET_URL = '/v1/secret';

const HEADER_TOKEN = 'X-Vault-Token';

class Vault {
  /**
   * Vault Constructor
   *
   * @param {object} {host, token, roleId, secretId}
   */
  constructor({ host, token, roleId, secretId }) {
    this.host = host;
    this.roleId = roleId;
    this.secretId = secretId;
    this.usrToken = token;
    this.session = {};

    this.validateConfig();

    this.axios = axios.create({
      baseURL: `https://${this.host}`,
    });

    this.axios.interceptors.request.use(async (config) => {
      // eslint-disable-next-line
      console.log(`[Vault Request] - ${config.url}`);

      const hasToken = config.headers[HEADER_TOKEN];
      if (!hasToken) {
        // user force to use an token
        if (this.usrToken) {
          // eslint-disable-next-line
          config.headers[HEADER_TOKEN] = this.usrToken;
          // fetch the token!
          // TODO In that case the user provides an role_id and secret_id
          // skip infinite loop because when it calls authenticate will enter
          // again for this interceptor
        } else if (config.url !== APPROLE_LOGIN_URL) {
          await this.authenticate();
          // eslint-disable-next-line
          config.headers[HEADER_TOKEN] = this.getSessionToken();
        }
      }

      return config;
    });
  }

  /**
   * Validate Vault config
   *
   * @param {object} config vault config host and auth
   */
  validateConfig() {
    if (!this.host) {
      throw new Error('VAULT_HOST_IS_MISSING');
    }

    if (!this.usrToken) {
      if (!this.roleId || !this.secretId) {
        throw new Error('VAULT_AUTH_IS_MISSING: roleId, secretId or token');
      }
    }
  }

  /**
   * Get Vault Token from Session.
   *
   * @returns {string} token
   */
  getSessionToken() {
    return _.get(this.session, 'auth.client_token');
  }

  /**
   * useRequestInterceptor
   *
   * @param {function} funDef function to intercpt the request
   */
  useRequestInterceptor(funDef) {
    this.axios.interceptors.request.use(funDef);
  }

  /**
   * Use http headers vault token
   *
   * @param {string} token to use with axios
   */
  useToken(token) {
    if (_.isEmpty(token)) throw new Error('para "token" is required.');
    this.axios.defaults.headers.common[HEADER_TOKEN] = token;
  }

  /**
   * Is Token Alive or launch exception
   *
   * @static
   * @returns {number} token time to live
   */
  isTokenAlive() {
    return this.axios
      .get(IS_TOKEN_ALIVE_URL)
      .then(R.pathOr({}, ['data']))
      .then((data) => {
        const ttl = _.get(data, 'data.ttl', 0);

        if (ttl > 0) {
          return ttl;
        }

        throw new Error('Vault session expired. renew token...');
      });
  }

  /**
   * FetchSecret
   *
   * @param {string} secretPath /path to secret /some/misecretkey
   * @returns {promise} vault result
   */
  fetchSecret(secretPath) {
    let secret = secretPath;

    if (_.isEmpty(secret)) throw new Error('param "secretPath" is required');
    if (!secret.startsWith('/')) {
      secret = `/${secret}`;
    }

    return this.axios
      .get(`${SECRET_URL}${secret}`)
      .then(R.pathOr({}, ['data']));
  }

  /**
   * Create Secret
   *
   * @param {string} secretPath key secret path
   * @param {object} data object to store
   * @returns {promise} vault created object
   */
  createSecret(secretPath, data) {
    let secret = secretPath;

    if (_.isEmpty(secretPath))
      throw new Error('param "secretPath" is required');
    if (_.isEmpty(data)) throw new Error('param "data" is required');

    if (!secret.startsWith('/')) {
      secret = `/${secret}`;
    }

    return this.axios.post(`${SECRET_URL}${secret}`, data);
  }

  /**
   * Delete Secret
   *
   * @param {string} secretPath key secret path
   * @returns {promise} vault created object
   */
  deleteSecret(secretPath) {
    let secret = secretPath;

    if (_.isEmpty(secretPath)) {
      throw new Error('param "secretPath" is required');
    }

    if (!secret.startsWith('/')) {
      secret = `/data/${secret}`;
    }

    return this.axios.delete(`${SECRET_URL}${secret}`);
  }

  /**
   * Refresh token alias function
   *
   */
  refreshToken() {
    this.authenticate();
  }

  /**
   * Authenticate before perform any vault action
   *
   * @returns {object} vault auth object
   */
  authenticate() {
    if (!this.roleId) throw new Error('field "roleId" is required');
    if (!this.secretId) throw new Error('field "secretId" is required');

    return this.axios
      .post(APPROLE_LOGIN_URL, {
        role_id: this.roleId,
        secret_id: this.secretId,
      })
      .then(R.pathOr({}, ['data']))
      .then((data) => {
        const cliToken = _.get(data, 'auth.client_token');
        this.useToken(cliToken);
        this.session = data;
      });
  }
}

module.exports = Vault;
