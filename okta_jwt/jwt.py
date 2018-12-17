import os
import json
import requests
from jose import jwk, jwt
from requests.auth import HTTPBasicAuth
from jose.utils import base64url_decode
from okta_jwt.utils import verify_exp, verify_aud, check_presence_of, verify_iat, verify_iss, verify_cid



# Generates Okta Access Token
def generate_token():
    """For generating a token, you need to add the
    following ENV variables in your ~/.bash_profile
    1) OKTA_CLIENT_IDS (multiple Client IDs can be passed)
    2) OKTA_CLIENT_SECRET
    3) OKTA_URL
    4) OKTA_ISSUER
    """
    try:
        client_id     = os.environ['OKTA_CLIENT_IDS']
        client_secret = os.environ['OKTA_CLIENT_SECRET']
        oidc_url      = os.environ['OKTA_URL']
        issuer        = os.environ['OKTA_ISSUER']
    except Exception as e:
        raise Exception("Failed to load Okta ENV Variables : " + str(e))

    auth = HTTPBasicAuth(client_id, client_secret)

    headers = {
        'Accept':       'application/json',
        'Content-Type': 'application/x-www-form-urlencoded'
    }

    """ scope and grant_type are gonna be constant,
    Replace username & password with your credentials
    """
    payload = {
        "username":   "test@example.org",
        "password":   "Password123",
        "scope":      "openid",
        "grant_type": "password"
    }

    url = "{}/v1/token".format(issuer)

    try:
        response = requests.post(url, data=payload, headers=headers, auth=auth)

        # Consider any status other than 2xx an error
        if not response.status_code // 100 == 2:
            return "Error: Unexpected response {}".format(response)

        return_value = response.json()

        if 'access_token' not in return_value:
            return "no access_token in response from /token endpoint", 401

        print("[Okta::Jwt] Generating Okta Token")
        access_token = return_value['access_token']

        return access_token
    except requests.exceptions.RequestException as e:
        # A serious problem happened, like an SSLError or InvalidURL
        raise "Error: {}".format(str(e))


# Verifies Claims
def verify_claims(payload, issuer, audience, cid_list):
    """ Validates Issuer, Client IDs, Audience
    Issued At time and Expiration in the Payload
    """
    print("[Okta::Jwt] Verifying Claims")

    verify_iss(payload, issuer)
    verify_cid(payload, cid_list)
    verify_aud(payload, audience)
    verify_exp(payload)
    verify_iat(payload)


# Validates Token
def validate_token(access_token):
    try:
        client_ids = os.environ['OKTA_CLIENT_IDS']
        oidc_url   = os.environ['OKTA_URL']
        issuer     = os.environ['OKTA_ISSUER']
        audience   = os.environ['OKTA_AUDIENCE']
    except Exception as e:
        raise Exception("Failed to load Okta ENV Variables : " + str(e))

    # Client ID's list
    cid_list = []

    if not isinstance(client_ids, list):
        cid_list.append(client_ids)
    else:
        cid_list = client_ids

    check_presence_of(access_token, issuer, audience, cid_list)

    # Decoding Header & Payload from token
    header  = jwt.get_unverified_header(access_token)
    payload = jwt.get_unverified_claims(access_token)

    # Verifying Claims
    verify_claims(payload, issuer, audience, cid_list)

    # Verifying Signature
    key = jwk.construct(fetch_jwk_for(header, payload))
    message, encoded_sig = access_token.rsplit('.', 1)
    decoded_sig = base64url_decode(encoded_sig.encode('utf-8'))

    print("[Okta::Jwt] Validating the Access Token")
    print()

    valid = key.verify(message.encode(), decoded_sig)

    # If the token is valid, it returns the payload 
    if valid == True:
        print('Valid Token')
        return payload
    else:
        raise Exception('Invalid Token')


# Extract public key from metadata's jwks_uri using kid
def fetch_jwk_for(header, payload):
    # Extracting kid from the Header
    if 'kid' in header:
        kid = header['kid']
    else:
        raise ValueError('The Token header must contain a "kid" value')

    # if kid in key_cache:
    #     return key_cache[kid]

    print("[Okta::Jwt] Fetching public key: kid => " + str(kid))

    # Fetching jwk
    url = fetch_metadata_for(payload)['jwks_uri']
    jwks_response = requests.get(url)

    #############
    # for key in jwks_response.json()['keys'][0]:
    #     jwk_id = key['kid']
    #     key_cache[jwk_id] = key

    # if key_id in key_cache:
    #     return key_cache[key_id]
    # else:
    #     raise RuntimeError("Unable to fetch public key from jwks_uri")
    ###########

    jwk = list(filter(lambda x: x['kid'] == kid, jwks_response.json()['keys']))[0]
    return jwk

    # cache and return the key
    # to implement


def fetch_metadata_for(payload):
    print("[Okta::Jwt] Fetching MetaData")

    # Extracting auth_server_id & client_id from the Payload
    auth_server_id = payload['iss'].split('/')[-1]
    client_id      = str(payload['cid']) or str(payload['aud'])
    issuer         = os.environ['OKTA_ISSUER']

    # Preparing URL to get the metadata
    url = "{}/.well-known/oauth-authorization-server?client_id={}".format(issuer, client_id)

    try:
        metadata_response = requests.get(url)

        # Consider any status other than 2xx an error
        if not metadata_response.status_code // 100 == 2:
            return "Error: Unexpected response {}".format(metadata_response)

        json_obj = metadata_response.json()
        return json_obj

    except requests.exceptions.RequestException as e:
        # A serious problem happened, like an SSLError or InvalidURL
        raise "Error: {}".format(str(e))
