import calendar
from calendar import timegm
from datetime import datetime, timedelta
from six import string_types
from exceptions import ExpiredSignatureError
from exceptions import JWTClaimsError


def check_presence_of(access_token, issuer, audience, client_ids):
    if not access_token:
        raise ValueError('Access Token is required')

    if not issuer:
        raise ValueError('Issuer is required')

    if not audience:
        raise ValueError('Audience is required')

    if '' in client_ids:
        raise ValueError('Client ID is required')


def verify_iss(payload, issuer):
    if payload['iss'] != issuer:
        raise JWTClaimsError('Invalid Issuer')


def verify_cid(payload, cid_list):
    if not payload['cid'] in cid_list:
        raise JWTClaimsError('Invalid Client')


def verify_exp(payload, leeway=0):
    """Validates that the 'exp' claim is valid.
    The "exp" (expiration time) claim identifies the expiration time on
    or after which the JWT MUST NOT be accepted for processing.  The
    processing of the "exp" claim requires that the current date/time
    MUST be before the expiration date/time listed in the "exp" claim.
    Implementers MAY provide for some small leeway, usually no more than
    a few minutes, to account for clock skew.
    Args:
        payload (dict): The payload dictionary to validate.
        leeway (int): The number of seconds of skew that is allowed.
    """
    if 'exp' not in payload:
        return

    try:
        exp = int(payload['exp'])
    except ValueError:
        raise JWTClaimsError('Expiration Time payload (exp) must be an integer.')

    now = timegm(datetime.utcnow().utctimetuple())

    if exp < (now - leeway):
        raise ExpiredSignatureError('Token is expired.')


def verify_aud(payload, audience=None):
    """Validates that the 'aud' claim is valid.
    The "aud" (audience) claim identifies the recipients that the JWT is
    intended for. Each principal intended to process the JWT MUST
    identify itself with a value in the audience claim.  If the principal
    processing the claim does not identify itself with a value in the
    "aud" claim when this claim is present, then the JWT MUST be
    rejected.  In the general case, the "aud" value is an array of case-
    sensitive strings, each containing a StringOrURI value.
    """
    if 'aud' not in payload:
        return

    audience_claims = payload['aud']

    if isinstance(audience_claims, string_types):
        audience_claims = [audience_claims]
    if not isinstance(audience_claims, list):
        raise JWTClaimsError('Invalid claim format in token')
    if any(not isinstance(c, string_types) for c in audience_claims):
        raise JWTClaimsError('Invalid claim format in token')
    if audience not in audience_claims:
        raise JWTClaimsError('Invalid Audience')


def verify_iat(payload, leeway=300):
    """The iat value indicates what time the token was "issued at". 
    We verify that this claim is valid by checking that the token was 
    not issued in the future, with some leeway for clock skew.
    """
    time_now_with_leeway = datetime.utcnow() + timedelta(seconds=leeway)
    acceptable_iat = calendar.timegm((time_now_with_leeway).timetuple())

    if 'iat' in payload and payload['iat'] > acceptable_iat:
        raise JWTClaimsError('Invalid Issued At(iat) Time')
