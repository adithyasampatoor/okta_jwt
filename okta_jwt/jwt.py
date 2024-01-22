import requests
from jose import jwk, jwt
from requests.auth import HTTPBasicAuth
from jose.utils import base64url_decode
from okta_jwt.utils import verify_exp, verify_aud, check_presence_of, verify_iat, verify_iss, verify_cid

JWKS_CACHE = {}

# Generates Okta Access Token
def generate_token(issuer, client_id, client_secret, username, password, scope='openid', grant_type='password'):
    """For generating a token, you need to pass in the Issuer,
    Client ID, Client Secret, Username and Password
    """
    auth = HTTPBasicAuth(client_id, client_secret)

    headers = {
        'Accept':       'application/json',
        'Content-Type': 'application/x-www-form-urlencoded'
    }

    # Configurable payload parameters
    payload = {
        "username":   username,
        "password":   password,
        "scope":      scope,
        "grant_type": grant_type
    }

    url = "{}/v1/token".format(issuer)

    try:
        response = requests.post(url, data=payload, headers=headers, auth=auth)

        # Consider any status other than 2xx an error
        if not response.status_code // 100 == 2:
            raise Exception(response.text, response.status_code)

        return_value = response.json()

        if 'access_token' not in return_value:
            raise Exception("no access_token in response from /token endpoint", 401)

        access_token = return_value['access_token']

        return access_token
    except requests.exceptions.RequestException as e:
        # A serious problem happened, like an SSLError or InvalidURL
        raise Exception("Error: {}".format(str(e)))


# Verifies Claims
def verify_claims(payload, issuer, audience, cid_list):
    """ Validates Issuer, Client IDs, Audience
    Issued At time and Expiration in the Payload
    """
    verify_iss(payload, issuer)
    verify_cid(payload, cid_list)
    verify_aud(payload, audience)
    verify_exp(payload)
    verify_iat(payload)


# Validates Token
def validate_token(access_token, issuer, audience, client_ids):
    # Client ID's list
    cid_list = []

    # Convert client_ids to a list if it's a string
    cid_list = client_ids.split(',') if isinstance(client_ids, str) else client_ids

    check_presence_of(access_token, issuer, audience, cid_list)

    # Decoding Header & Payload from token
    header  = jwt.get_unverified_header(access_token)
    payload = jwt.get_unverified_claims(access_token)

    # Verifying Claims
    verify_claims(payload, issuer, audience, cid_list)

    # Verifying Signature
    jwks_key = fetch_jwk_for(header, payload)
    key      = jwk.construct(jwks_key)
    message, encoded_sig = access_token.rsplit('.', 1)
    decoded_sig = base64url_decode(encoded_sig.encode('utf-8'))

    # If the token is valid, it returns the payload 
    if key.verify(message.encode(), decoded_sig):
        return payload
    else:
        raise Exception('Invalid Token Signature')


# Extract public key from metadata's jwks_uri using kid
def fetch_jwk_for(header, payload):
    # Extracting kid from the Header

    kid = header.get('kid')
    if not kid:
        raise ValueError('Token header is missing "kid" value')

    global JWKS_CACHE

    # If there is a matching kid, it wont fetch for kid from the server again
    if JWKS_CACHE and kid in JWKS_CACHE:
        return JWKS_CACHE[kid]

    # Fetching jwk
    url = fetch_metadata_for(payload)['jwks_uri']

    try:
        # Making an HTTP GET request to the JWKS URI
        jwks_response = requests.get(url)
        jwks_response.raise_for_status()  # Raises HTTPError for bad responses

        # Extracting the JWK with a matching kid
        jwks = [key for key in jwks_response.json().get('keys', []) if key.get('kid') == kid]
        if not jwks:
            raise Exception(f"Error: Could not find jwk for kid: {kid}")

        jwk = jwks[0]

        # Adding JWK to the Cache
        jwks_cache[kid] = jwk

        return jwk
    except requests.exceptions.RequestException as e:
        # Handling HTTP request errors
        raise Exception(f"HTTP request error: {str(e)}")


def fetch_metadata_for(payload):
    # Extracting client_id and issuer from the Payload
    client_id = payload['cid']
    issuer    = payload['iss']

    # Preparing URL to get the metadata
    url = "{}/.well-known/oauth-authorization-server?client_id={}".format(issuer, client_id)

    try:
        metadata_response = requests.get(url)

        # Consider any status other than 2xx an error
        if not metadata_response.status_code // 100 == 2:
            raise Exception(metadata_response.text, metadata_response.status_code)

        json_obj = metadata_response.json()
        return json_obj

    except requests.exceptions.RequestException as e:
        # A serious problem happened, like an SSLError or InvalidURL
        raise Exception("Error: {}".format(str(e)))
