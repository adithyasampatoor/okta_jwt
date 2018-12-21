import unittest
import jose.jwt as jwt
import jose.jwk as jwk
from mock import patch
from ddt import ddt, data, unpack
from tests.mocks import MockHTTPResponse
from okta_jwt.jwt import generate_token, validate_token
from okta_jwt.exceptions import ExpiredSignatureError
from datetime import datetime
from calendar import timegm


def get_now_formatted(offset_s=0):
    utcnow = datetime.utcnow()
    return timegm(utcnow.timetuple()) + offset_s


@ddt
class TestJWT(unittest.TestCase):
    priv_pem = open('tests/private.pem', 'r').read()
    pub_pem = open('tests/public.pem', 'r').read()

    @unpack
    @data(
        (MockHTTPResponse(401, 'Authentication failed.'),
         True, 'Authentication failed.', 401),
        (MockHTTPResponse(),
         True, 'no access_token in response from /token endpoint', 401),
        (MockHTTPResponse(json={'access_token': 'access_token'}),
         False, '', None)
    )
    @patch('okta_jwt.jwt.requests.post')
    def test_generate_token(self, mockresponse, should_raise, error, code, mockpost):
        mockpost.return_value = mockresponse
        if should_raise:
            with self.assertRaises(Exception) as ctx:
                generate_token('iss', 'cid', 'csecret', 'username', 'password')
            self.assertEqual(error, ctx.exception.args[0])
            self.assertEqual(code, ctx.exception.args[1])
        else:
            token = generate_token(
                'iss', 'cid', 'csecret', 'username', 'password')
            self.assertEqual(token, 'access_token')

    @unpack
    @data(
        ({}, {'aud': 'aud', 'cid': 'cid', 'iss': 'iss'}, False, None),
        ({}, {'aud': 'aud', 'cid': 'cid', 'iss': 'iss',
              'iat': get_now_formatted(), 'exp': get_now_formatted(10)}, False, None),
        ({}, {'aud': 'aud', 'cid': 'cid', 'iss': 'iss',
              'iat': get_now_formatted(-10), 'exp': get_now_formatted(-1)}, True, ExpiredSignatureError),
    )
    @patch('okta_jwt.jwt.fetch_jwk_for')
    @patch('okta_jwt.jwt.jwk')
    def test_validate_token(self, header, claims, should_raise, error, mockjwk, _):
        mockjwk.construct.return_value = jwk.construct(
            self.pub_pem, algorithm=jwk.ALGORITHMS.RS256)
        access_token = jwt.encode(
            claims, self.priv_pem, jwt.ALGORITHMS.RS256, header)
        if should_raise:
            with self.assertRaises(error) as ctx:
                validate_token(
                    access_token, claims['iss'], claims['aud'], claims['cid'])
            self.assertEqual(error, type(ctx.exception))
        else:
            res = validate_token(
                access_token, claims['iss'], claims['aud'], claims['cid'])
            self.assertEqual(res, claims)
