# React and Django Sample Application
### Table of Contents

  - [Introduction](#introduction)
    - [Login Redirect](#1-login-redirect)
    - [Custom Login Form](#2-custom-login-form)
  - [Prerequisites](#prerequisites)
  - [Quick Start](#quick-start)
  - [Front End](#front-end-react)
    - [Login Redirect](#login-redirect)
    - [Custom Login Form](#custom-login-form)
  - [Back End](#back-end-django)
    - [Routes](#routes)
    - [Handle the Redirect](#handle-the-redirect)
    - [Code Exchange](#code-exchange)
    - [Validation](#validation)
  - [Set User Session](#set-user-session)
  - [Logout](#logout)
  - [Conclusion](#conclusion)
  - [Support](#support)
  - [License](#license)
  
## Introduction

This tutorial will demonstrate how to use OAuth 2.0 and OpenID Connect to add authentication to a [React](https://facebook.github.io/react/) and [Django](https://www.djangoproject.com/) application.

### 1. Login Redirect

Users are redirected to your Okta organization for authentication.

<img src="https://raw.githubusercontent.com/jmelberg-okta/doc-assets/master/samples/redirect.png" width="300" >

After authenticating into your Okta organization, an authorization code is returned in a callback URL. This authorization code is then exchanged for an `id_token`.

### 2. Custom Login Form

The Okta Sign-In Widget is fully customizable via CSS and JavaScript. You can change how the widget [looks with CSS](http://developer.okta.com/code/javascript/okta_sign-in_widget#customizing-style-with-css) and [configured with JavaScript](http://developer.okta.com/code/javascript/okta_sign-in_widget#customizing-widget-features-and-text-labels-with-javascript).

<img src="https://raw.githubusercontent.com/jmelberg-okta/doc-assets/master/samples/custom.png" width="300">

This custom-branded login experience uses the [Okta Sign-In Widget](http://developer.okta.com/code/javascript/okta_sign-in_widget) to perform authentication, returning an authorization code to be exchanged for an `id_token`.

## Prerequisites

Ensure [Node.js](https://nodejs.org/en/) is installed and updated to the most recent version

```
$ node -v
```
Download the sample application from GitHub

```
$ git clone git@github.com:okta/samples-python-django.git
```
Create an isolated virtual environment
Install [virtualenv](http://docs.python-guide.org/en/latest/dev/virtualenvs/) via pip:
```
[samples-python-django]$ pip install virtualenv
```
Create the virtual environment:
```
[samples-python-django]$ virtualenv venv
```
Activate the virtual environment:
```
[samples-python-django]$ source venv/bin/activate
```
When you are finished working inside of the virtual environment, you can deactivate it:
```
(venv)[samples-python-django]$ deactivate
```

Update frontend to React
Switch the frontend from `samples-js-angular-1` to `samples-js-react` inside of `tools/copy-static`:
``` javascript
// index.js

const frontend = 'samples-js-react';
```

Install required dependencies inside of `samples-python-django`
```
(venv)[samples-python-django]$ npm install
(venv)[samples-python-django]$ npm install @okta/samples-js-react
(venv)[samples-python-django]$ pip3 install -r requirements.txt
```

## Quick Start

Start the back-end for your sample application with `npm start` or `python3 lib/manage.py runserver 3000`. This will start the app server on [http://localhost:3000](http://localhost:3000).

By default, this application uses a mock authorization server which responds to API requests similar to a production environment. This grants us access to multiple users without the need to set up another application. To use it, run the mock server on [http://127.0.0.1:7777](http://127.0.0.1:7777) by entering the following in a second terminal window:
```
[terminal2:samples-python-django]$ npm run mock-okta
```

To use your [Okta Developer](http://developer.okta.com/) organization, follow the [app integration instructions for OAuth 2.0 and OpenID Connect Single Page Applications](https://gist.github.com/jmelberg-okta/cabe7ee5784997c37465724deb00fa04). Then, replace the `oidc` object with the appropriate fields. For example:
```javascript
// .samples.config.json

{
  "oidc": {
    "oktaUrl": "https://example.oktapreview.com",
    "clientId": "hereIsMyClientId",
    "clientSecret": "hereIsMyClientSecret",
    "redirectUri": "http://localhost:3000/authorization-code/callback"
  }
}
```

## Front-end (React)

When you run `npm install`, a copy of the [React](https://github.com/okta/samples-js-react) front-end application is copied into the `dist/` directory. More information about the controllers and views are available in the [React project repository](https://github.com/okta/samples-js-react/blob/master/README.md).

### Login Redirect

With React, we include the event trigger `onClick` to begin the login process. When the link is clicked, it calls the `login` function defined in `LoginRedirect.js`. Let’s take a look at how the `OktaAuth` object is created.

```javascript
// LoginRedirect.js

class LoginRedirect extends React.Component {

  constructor(props) {
    super(props);
    this.login = this.login.bind(this);
    const config = this.props.route.config;
    this.authClient = new OktaAuth({
      url: config.oktaUrl,
      clientId: config.clientId,
      redirectUri: config.redirectUri,
      scopes: ['openid', 'email', 'profile'],
    });
  }

  login(e) {
    e.stopPropagation();
    e.preventDefault();
    this.authClient.token.getWithRedirect({ responseType: 'code' });
  }
```

There are a number of different ways to construct the login redirect URL.

1. Build the URL manually
2. Use an OpenID Connect / OAuth 2.0 middleware library
3. Use [AuthJS](http://developer.okta.com/code/javascript/okta_auth_sdk)

We use AuthJS to create the URL and perform the redirect. An `OktaAuth` object is instantiated with the configuration in `.samples.config.json`. When the `login()` function is called from the view, it calls the [`/authorize`](http://developer.okta.com/docs/api/resources/oauth2.html#authentication-request) endpoint to start the [Authorization Code Flow](https://tools.ietf.org/html/rfc6749#section-1.3.1).
 

You can read more about the `OktaAuth` configuration options here: [OpenID Connect with Okta AuthJS SDK](http://developer.okta.com/code/javascript/okta_auth_sdk#social-authentication-and-openid-connect).

**Important:** When the authorization code is exchanged for an `accessToken` and/or `idToken`, the tokens *MUST* be [validated](#validation).

### Custom Login Form

To render the [Okta Sign-In Widget](http://developer.okta.com/code/javascript/okta_sign-in_widget), include a container element on the page for the widget to attach to. In this sample, we add a `<div>` with an `id` of `sign-in-container`:

```html
<!-- index.mustache -->
<div id="sign-in-container">...</div>
```
Next, we can configure and render the [Okta Sign-In Widget](https://github.com/okta/okta-signin-widget#configuration).

``` javascript
// LoginCustom.js
 
class LoginCustom extends React.Component {

  componentDidMount() {
    const config = this.props.route.config;
    const signIn = new SignIn({
      baseUrl: config.oktaUrl,
      clientId: config.clientId,
      redirectUri: config.redirectUri,
      authParams: {
        responseType: 'code',
        scopes: ['openid', 'email', 'profile'],
      },
      i18n: {
        en: {
          'primaryauth.title': 'Use john/Asdf1234 for the mock Okta server',
        },
      },
    });
    signIn.renderEl({ el: '#sign-in-container' }, () => {});
  }
```
To perform the [Authorization Code Flow](https://tools.ietf.org/html/rfc6749#section-1.3.1), we set the `responseType` to `code`. This returns an `accessToken` and/or `idToken` through the [`/token`](http://developer.okta.com/docs/api/resources/oauth2.html#token-request) OpenID Connect endpoint. 

**Note:** Additional configuration for the `SignIn` object is available at [OpenID Connect, OAuth 2.0, and Social Auth with Okta](https://github.com/okta/okta-signin-widget#configuration).

## Back-end (Django)

To complete the [Authorization Code Flow](https://tools.ietf.org/html/rfc6749#section-1.3.1), your back-end server performs the following tasks:
  - Handle the [Authorization Code code exchange](https://tools.ietf.org/html/rfc6749#section-1.3.1) callback
  - [Validate](http://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation) the `idToken`
  - Set `user` session in the app
  - Log the user out

### Routes

To render the React templates, we define the following Django controllers:
  - `authorization-code/login-redirect/` renders the [login redirect](#login-redirect) flow
  - `authorization-code/login-custom/` renders the [custom login](#custom-login-form) flow
  - `authorization-code/callback/` handles the redirect from Okta
  - `authorization-code/profile/` renders the logged in state, displaying profile information
  - `authorization-code/logout/` closes the `user` session

### Handle the Redirect

After successful authentication, an authorization code is returned to the redirectUri:
```
http://127.0.0.1:7777/callback?code=authorizationCodeWillGoHere&state=OAuth2StateWillGoHere
```

Two cookies are created after authentication: `okta-oauth-nonce` and `okta-auth-state`. You **[MUST](https://www.ietf.org/rfc/rfc2119.txt)** verify the returned `state` value in the URL matches the `state` value created.

For example:
```python
# views.py

if ('okta-oauth-state' in request.COOKIES and 'okta-oauth-nonce' in request.COOKIES):
    # Current AuthJS Cookie Setters
    state = request.COOKIES['okta-oauth-state']
    nonce = request.COOKIES['okta-oauth-nonce']
else:
    return HttpResponse('Error setting and/or retrieving cookies', status=401)
```

### Code Exchange

Next, we must exchange an authorization code for an `idToken` and/or `accessToken`. You can choose the best [token authentication method](http://developer.okta.com/docs/api/resources/oauth2.html#token-request) for your application. For this sample, we use the default token authentication method `client_secret_basic`:

```python
# openid.py

def call_token_endpoint(url, code, config):
    """ Call /token endpoint
        Returns accessToken, idToken, or both
    """
    auth = HTTPBasicAuth(config['clientId'], config['clientSecret'])
    header = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json',
        'Connection': 'close'
    }

    params = 'grant_type=authorization_code&code={}&redirect_uri={}'.format(
        urllib.parse.quote_plus(code),
        urllib.parse.quote_plus(config['redirectUri'])
    )

    url_encoded = '{}{}'.format(url, params)

    # Send token request
    r = requests.post(url_encoded, auth=auth, headers=header)

    return r.json()

```
A successful response returns an `idToken` which looks similar to:
```
eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIwMHVpZDRCeFh3Nkk2VFY0bTBnMyIsImVtYWlsIjoid2VibWFzd
GVyQGNsb3VkaXR1ZGUubmV0IiwiZW1haWxfdmVyaWZpZWQiOnRydWUsInZlciI6MSwiaXNzIjoiaHR0cD
ovL3JhaW4ub2t0YTEuY29tOjE4MDIiLCJsb2dpbiI6ImFkbWluaXN0cmF0b3IxQGNsb3VkaXR1ZGUu
bmV0IiwiYXVkIjoidUFhdW5vZldrYURKeHVrQ0ZlQngiLCJpYXQiOjE0NDk2MjQwMjYsImV4cCI6MTQ0O
TYyNzYyNiwiYW1yIjpbInB3ZCJdLCJqdGkiOiI0ZUFXSk9DTUIzU1g4WGV3RGZWUiIsImF1dGhfdGltZSI
6MTQ0OTYyNDAyNiwiYXRfaGFzaCI6ImNwcUtmZFFBNWVIODkxRmY1b0pyX1EifQ.Btw6bUbZhRa89
DsBb8KmL9rfhku--_mbNC2pgC8yu8obJnwO12nFBepui9KzbpJhGM91PqJwi_AylE6rp-
ehamfnUAO4JL14PkemF45Pn3u_6KKwxJnxcWxLvMuuisnvIs7NScKpOAab6ayZU0VL8W6XAijQmnYTt
MWQfSuaaR8rYOaWHrffh3OypvDdrQuYacbkT0csxdrayXfBG3UF5-
ZAlhfch1fhFT3yZFdWwzkSDc0BGygfiFyNhCezfyT454wbciSZgrA9ROeHkfPCaX7KCFO8GgQEkGRoQ
ntFBNjluFhNLJIUkEFovEDlfuB4tv_M8BM75celdy3jkpOurg

```

### Validation

After receiving the `idToken`, we must first [validate](http://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation) the token to prove its integrity. First, we check if the token is a JWT. This can be performed easily as OpenID Connect [JWTs](https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-32#section-3) have a set format.

We use a [JSON Object Signing and Encryption (JOSE)](https://github.com/mpdavis/python-jose) library to decode and validate the token. Choose the best library that fits your development needs.


We verify the `id_token` using the following steps:

1. [Verify the signature](#verify-signature)
2. [Verify the *iss* (issuer), *aud* (audience), and *exp* (expiry) time](#verify-fields)
3. [Verify the *iat* (issued at) time](#verify-issued-time)
4. [Verify the *nonce*](#verify-nonce)

Learn more about validating tokens in [OpenID Connect Resources](http://developer.okta.com/docs/api/resources/oidc.html#validating-id-tokens).

#### Verify signature

An `id_token` should contain a [public key id](https://tools.ietf.org/html/rfc7517#section-4.5) (`kid`). To verify the signature, we use the [Discovery Document](http://developer.okta.com/docs/api/resources/oidc.html#openid-connect-discovery-document) to find the `jwks_uri`, which will return a list of public keys. It is safe to cache or persist these keys for performance, but Okta rotates them periodically. We strongly recommend dynamically retrieving keys if the `id_token`'s `kid` has not been cached. For example: If the `kid` has been cached, you can use it to validate the signature. If not, make a request to the OAuth 2.0 [`/keys`](http://developer.okta.com/docs/api/resources/oidc.html#get-keys) endpoint. 

```python
# tokens.py

def fetch_jwk_for(id_token=None):
    if id_token is None:
        raise NameError('id_token is required')

    # This will be pulled from the OpenID connect Discovery Document
    jwks_uri = 'http://127.0.0.1:7777/oauth2/v1/keys'

    unverified_header = jws.get_unverified_header(id_token)
    key_id = None

    if 'kid' in unverified_header:
        key_id = unverified_header['kid']
    else:
        raise ValueError('The id_token header must contain a "kid"')

    if key_id in settings.PUBLIC_KEY_CACHE:
        # If we've already cached this JWK, return it
        return settings.PUBLIC_KEY_CACHE[key_id]

    # If it's not in the cache, get the latest JWKS from /oauth2/v1/keys
    r = requests.get(jwks_uri)
    jwks = r.json()

    for key in jwks['keys']:
        jwk_id = key['kid']
        settings.PUBLIC_KEY_CACHE[jwk_id] = key

    if key_id in settings.PUBLIC_KEY_CACHE:
        return settings.PUBLIC_KEY_CACHE[key_id]
    else:
        raise RuntimeError('Unable to fetch public key from jwks_uri')
```

#### Verify fields

Using the `jwt.decode()` method, we pass in a dictionary containing the `issuer`, `audience`, and `clock_skew` to verify that:

  - The `issuer` is identical to the host where authorization was performed
  - The `clientId` stored in our configuration matches the `aud` claim
  - If the token expiration time has passed, the token must be revoked

```python
# tokens.py

# A clock skew of five minutes is considered to account for
# differences in server times
clock_skew = 300

jwks_with_public_key = fetch_jwk_for(tokens['id_token'])

jwt_kwargs = {
    'algorithms': jwks_with_public_key['alg'],
    'options': {
        'verify_at_hash': False,
        # Used for leeway on the 'exp' claim
        'leeway': clock_skew
    },
    'issuer': okta_config.oidc['oktaUrl'],
    'audience': okta_config.oidc['clientId']
}

claims = jwt.decode(
    tokens['id_token'],
    jwks_with_public_key,
    **jwt_kwargs)
```

#### Verify issued time

The `iat` value indicates what time the token was "issued at". We verify that this claim is valid by checking that the token was not issued in the future, with some leeway for clock skew.

```python
# tokens.py

# Validate 'iat' claim
plus_time_now_with_clock_skew = (datetime.utcnow() +
                                 timedelta(seconds=clock_skew))
plus_acceptable_iat = calendar.timegm(
    (plus_time_now_with_clock_skew).timetuple())

if 'iat' in claims and claims['iat'] > plus_acceptable_iat:
    return 'invalid iat claim', 401
```

#### Verify nonce

To mitigate replay attacks, verify that the `nonce` value in the `id_token` matches the `nonce` stored in the cookie `okta-oauth-nonce`.

```python
# tokens.py
if nonce != claims['nonce']:
    return 'invalid nonce', 401
```

### Set user session

If the `idToken` passes validation, we can then set the `user` session in our application. In a production environment, you look up the `user` in a user store, and set the session for that user. In this sample, we simplify this process by setting the session as a new `user` object and store the email address in a session object using [Django authentication](https://docs.djangoproject.com/en/1.10/topics/auth/).

```python
# views.py

def validate_user(claims):
    # Create user for django session

    user = authenticate(
        username=claims['email'],
        password=claims['sub']
    )

    if user is None:
        # Create user
        new_user = User.objects.create_user(
            claims['email'],
            claims['email'],
            claims['sub']
        )

        user = authenticate(
            username=claims['email'],
            password=claims['sub']
        )

    # Update user profile
    if not hasattr(user, 'profile'):
        profile = Profile()
        profile.user = user
        profile.save()

    return user
```

### Logout

To clear the user session, we use Django's built-in `logout` method to ensure the user's session has ended. The Okta session is terminated in our client-side code.

```python
# views.py

def logout_controller(request):
    # Log user out

    # Clear existing user
    user = User.objects.get(username=request.user).delete()
    logout(request)

    return redirect('/')
```

## Conclusion

You have now successfully authenticated with Okta! Now what? With a user's `idToken`, you have basic claims into the user's identity. You can extend the set of claims by modifying the `response_type` and `scopes` to retrieve custom information about the user. This includes `locale`, `address`, `phone_number`, `groups`, and [more](http://developer.okta.com/docs/api/resources/oidc.html#scopes). 


## Support 

Have a question or see a bug? Email developers@okta.com. For feature requests, feel free to open an issue on this repo. If you find a security vulnerability, please follow our [Vulnerability Reporting Process](https://www.okta.com/vulnerability-reporting-policy/).

## License

Copyright 2017 Okta, Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

