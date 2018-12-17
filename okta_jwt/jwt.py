import json
import requests
from jose import jwk, jwt
from jose.utils import base64url_decode
from utils import verify_exp, verify_aud, check_presence_of, verify_iat, verify_iss, verify_cid


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
def validate_token(access_token, issuer, audience, client_ids):
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
    jwks_response = requests.get(url=url)

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

    # Preparing URL to get the metadata
    url = "{}/{}/.well-known/oauth-authorization-server?client_id={}".format(oidc_url, auth_server_id, client_id)

    try:
        metadata_response = requests.get(url=url)

        # Consider any status other than 2xx an error
        if not metadata_response.status_code // 100 == 2:
            return "Error: Unexpected response {}".format(metadata_response)

        json_obj = metadata_response.json()
        return json_obj

    except requests.exceptions.RequestException as e:
        # A serious problem happened, like an SSLError or InvalidURL
        return "Error: {}".format(str(e))
