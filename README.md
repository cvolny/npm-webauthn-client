# npm-webauthn-client
Webauthn client leveraging Axios and CBOR encoding.

I have request/response interceptors set on an axios instance inside of webauthn.js such that
  CBOR encoding/decoding is performed for you. I also configured the axios xsrf settings for
  the Django web framework default configuration.

## Example Usage:
```
import {
  webauthn_login,
  webauthn_register,
} from "webauthn-client";

...

login_passwordless = (username) => {
    const success = (res) => this.setState({authenticated: true});
    const failure = (res, code) => console.log('webauthn login failed', code, res);
    webauthn_login({username: username}, success, failure);
};

login_2fa = (username, password) => {
    const success = (res) => this.setState({authenticated: true});
    const failure = (res, code) => console.log('webauthn login failed', code, res);
    webauthn_login({username: username, password: password}, success, failure);
};

register = () => {
    const success = (res) => console.log('registered!');
    const failure = (res, code) => console.log('webauthn registration failed', code, res);
    webauthn_login({}, success, failure);
};
```

## Notes:

Really any map can be passed for authentication payload (username, password, token, etc).
