import requests
import base64
import json
from urllib import parse


def call_token_endpoint(url, code, config):
    """ Call /token endpoint

        Returns accessToken, idToken, or both
    """
    encoded_sting = '{}:{}'.format(config['clientId'],config['clientSecret']).encode('utf-8')
    authorization_header = base64.b64encode(encoded_sting)

    header = {
        'Authorization': 'Basic: ' + authorization_header.decode("utf-8", "ignore"),
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': None,
        'Connection': 'close'
    }

    params = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': config['redirectUri']
    }
    url_encoded = url + parse.urlencode(params)
    
    # Send token request
    r = requests.post(url_encoded, headers=header)
    response = r.json()
    
    # Return object
    result = {}
    if 'error' not in response:
        if 'access_token' in response:
            result['access_token'] = response['access_token']
        if 'id_token' in response:
            result['id_token'] = response['id_token']
    
    return result if len(result.keys()) > 0 else None