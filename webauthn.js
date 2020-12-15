/**
 * webauthn.js module to perform cbor encoded webauthn registration
 *  and login rituals using axios.
 *
 * Licensed as-is, without warranty, under the GNU LGPL2.1
 * Copyright &copy; 2020 Chris Volny
**/

import axios from 'axios';
import cbor, {
  encodeAsync,
  decodeAll,
} from 'cbor';
import { Buffer } from 'buffer';


/**
 * cborRequestInterceptor
 *
 * perform CBOR encoding and set responseType to arraybuffer
 *  on outbound requests with content-type application/cbor.
**/
export const cborRequestInterceptor = async function (request) {
  if (request.headers['content-type'] === 'application/cbor') {
    request.data = await encodeAsync(request.data);
    request.responseType = "arraybuffer"
    return request;
  }
  return request;
};

/**
 * cborResponseInterceptor
 *
 * perform CBOR decoding on inbound responses with
 *  content-type application/cbor.
**/
export const cborResponseInterceptor = async function (response) {
  if (response.headers['content-type'] === 'application/cbor') {
    const [data] = await decodeAll(Buffer.from(response.data));
    response.data = data;
    return response;
  }
  return response;
};


/**
 * axios_cbor object
 *
 * Axios instance used for XSRF aware, POST, application/cbor requests.
**/
export const axios_cbor = axios.create();
axios_cbor.defaults.xsrfHeaderName = "X-CSRFToken";
axios_cbor.defaults.xsrfCookieName = "csrftoken";
axios_cbor.defaults.withCredentials = true;
axios_cbor.defaults.headers['content-type'] = 'application/cbor';
axios_cbor.defaults.method = 'POST';
axios_cbor.interceptors.request.use(cborRequestInterceptor);
axios_cbor.interceptors.response.use(cborResponseInterceptor);


/**
 * error codes passed as 2nd argument of failure_callback().
**/
export const WEBAUTHN_REGISTER_FAIL_BEGIN    = 1;
export const WEBAUTHN_REGISTER_FAIL_COMPLETE = 2;
export const WEBAUTHN_LOGIN_FAIL_BEGIN       = 3;
export const WEBAUTHN_LOGIN_FAIL_COMPLETE    = 4;


/**
 * webauthn_login
 *
 * Login ritual wrapper for webauthn().
 *  Required arguments:
 *   - payload object, Ex: {username: foo}
 *   - success_callback, Ex: {this.setState({login: true})}
 *  Optional arguments:
 *   - failure_callback, default: callback to log results to console
 *   - beginurl, default: /api/auth/login/begin/
 *   - completeurl, default: /api/auth/login/
 *   - axcbor, default: axios_cbor
**/
export const webauthn_login = (payload,
                success_callback,
                failure_callback = (error, code) =>
                    console.log("webauthn-login failed:", code, error),
                beginurl = '/api/auth/login/begin/',
                completeurl = '/api/auth/login/',
                ax = axios_cbor) => {

    const credentials_callback = (opts) => navigator.credentials.get(opts);
    const complete_payload_callback = (payload, assertion) => {
        return {
            ...payload,
            "credentialId":      new Uint8Array(assertion.rawId),
            "authenticatorData": new Uint8Array(assertion.response.authenticatorData),
            "clientDataJSON":    new Uint8Array(assertion.response.clientDataJSON),
            "signature":         new Uint8Array(assertion.response.signature),
        };
    };

    return webauthn_internal(payload, success_callback, failure_callback, credentials_callback,
                    complete_payload_callback, beginurl, completeurl,
                    WEBAUTHN_LOGIN_FAIL_BEGIN, WEBAUTHN_LOGIN_FAIL_COMPLETE, ax);
};

/**
 * webauthn_register
 *
 * Register ritual wrapper for webauthn().
 *  Required arguments:
 *   - payload object, Ex: {username: foo}
 *   - success_callback, Ex: {this.setState({registered: true})}
 *  Optional arguments:
 *   - failure_callback, default: callback to log results to console
 *   - beginurl, default: /api/auth/register/begin/
 *   - completeurl, default: /api/auth/register/
 *   - axcbor, default: axios_cbor
**/
export const webauthn_register = (payload,
                success_callback,
                failure_callback = (error, code) =>
                    console.log("webauthn-register failed.", code, error),
                beginurl = '/api/auth/register/begin/',
                completeurl = '/api/auth/register/',
                ax = axios_cbor) => {

    const credentials_callback = (opts) => navigator.credentials.create(opts);
    const complete_payload_callback = (payload, attestation) => {
        return {
            ...payload,
            "attestationObject": new Uint8Array(attestation.response.attestationObject),
            "clientDataJSON":    new Uint8Array(attestation.response.clientDataJSON),
        };
    };

    return webauthn_internal(payload, success_callback, failure_callback, credentials_callback,
                    complete_payload_callback, beginurl, completeurl,
                    WEBAUTHN_REGISTER_FAIL_BEGIN, WEBAUTHN_REGISTER_FAIL_COMPLETE,
                    ax);
};

/**
 * webauthn
 *
 * Generalized webauthn exchange.
 *  Required arguments:
 *   - payload object, Ex: {username: foo}
 *   - success_callback, Ex: {this.setState({registered: true})}
 *   - failure_callback, Ex: callback to log results to console
 *   - credentials_callback, Ex: {(opts) => navigator.credentials.get(opts)}
 *   - beginurl, Ex: /api/auth/register/begin/
 *   - completeurl, Ex: /api/auth/register/
 *   - begin_failure_code, Ex: WEBAUTHN_REGISTER_FAIL_BEGIN
 *   - complete_failure_code, Ex: WEBAUTHN_REGISTER_FAIL_COMPLETE
 *   - ax, default: axios_cbor
**/
export const webauthn_internal = (payload, success_callback, failure_callback,
                credentials_callback, complete_context_callback, beginurl,
                completeurl, begin_failure_code, complete_failure_code, ax) => {
    console.log('webauthn:', {'begin': beginurl, 'complete': completeurl});
    ax.post(beginurl, payload)
      .then(res => res.data)
      .catch(error => failure_callback(error, begin_failure_code))
      .then(opts => credentials_callback(opts))
      .then(auth => {
        ax.post(completeurl, complete_context_callback(payload, auth))
          .then(res => success_callback(res))
          .catch(error => failure_callback(error, complete_failure_code));
      });

};
