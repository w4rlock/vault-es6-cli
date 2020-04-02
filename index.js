const axios = require('axios');
const R = require('ramda');
const _ = require('lodash');

const APPROLE_LOGIN_URL = '/v1/auth/approle/login';
const IS_TOKEN_ALIVE_URL = '/v1/auth/token/lookup-self';
const SECRET_URL = '/v1/secret';

class Vault {
  /**
   * Vault Constructor
   *
   * @param {string} host vault host id
   * @param {string} roleId vault role id
   * @param {string} secretId vault secret id
   * @param {boolean} debugRequest=false log request stdout
   */
  constructor(host, roleId, secretId, debugRequest = false) {
    this.host = host;
    this.roleId = roleId;
    this.secretId = secretId;
    this.session = {};
    this.axios = axios.create({
      baseURL: `https://${this.host}`,
    });

    if (debugRequest) {
      axios.interceptors.request.use((request) => {
        console.log('Starting Request...');
        console.log(JSON.stringify(request));

        return request;
      });
    }
  }

  /**
   * Use http headers vault token
   *
   * @param {string} token to use with axios
   */
  useToken(token) {
    if (_.isEmpty(token)) throw new Error('token is required.');
    this.axios.defaults.headers.common['X-Vault-Token'] = token;
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
   */
  fetchSecret(secretPath) {
    let secret = secretPath;

    if (!secret) throw new Error('secretPath is required');
    if (!secret.startsWith('/')) {
      secret = `/${secret}`;
    }

    return this.axios
      .get(`${SECRET_URL}${secret}`)
      .then(R.pathOr({}, ['data']));
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
