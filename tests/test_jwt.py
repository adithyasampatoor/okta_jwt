import unittest
import jose.jwt as jwt
import jose.jwk as jwk
from mock import patch
from datetime import datetime
from calendar import timegm
from ddt import ddt, data, unpack
from tests.mocks import MockHTTPResponse
from requests.exceptions import RequestException
from okta_jwt.exceptions import ExpiredSignatureError
from okta_jwt.jwt import (generate_token, validate_token,
                          fetch_jwk_for, JWKS_CACHE, fetch_metadata_for)


def get_now_formatted(offset_s=0):
    utcnow = datetime.utcnow()
    return timegm(utcnow.timetuple()) + offset_s


def pem_to_dict(pem, alg=jwk.ALGORITHMS.RS256):
    key = jwk.construct(pem, alg)
    return key.to_dict()


def raise_request_exception(*args, **kwargs):
    raise RequestException("Failed to fetch.")


@ddt
class TestJWT(unittest.TestCase):
    priv_pem = open('tests/private.pem', 'r').read()
    pub_pem = open('tests/public.pem', 'r').read()

    @unpack
    @data(
        (MockHTTPResponse(401, 'Authentication failed.'),
         'Authentication failed.', 401),
        (MockHTTPResponse(), 'no access_token in response from /token endpoint', 401),
        (MockHTTPResponse(json={'access_token': 'access_token'}), '', None)
    )
    @patch('okta_jwt.jwt.requests.post')
    def test_generate_token(self, mockresponse, error, code, mockpost):
        mockpost.return_value = mockresponse
        if error:
            with self.assertRaises(Exception) as ctx:
                generate_token('iss', 'cid', 'csecret', 'username', 'password')
            self.assertEqual(error, ctx.exception.args[0])
            self.assertEqual(code, ctx.exception.args[1])
        else:
            token = generate_token(
                'iss', 'cid', 'csecret', 'username', 'password')
            self.assertEqual(token, 'access_token')

    @patch('okta_jwt.jwt.requests.post')
    def test_generate_token_request_error(self, mockpost):
        mockpost.side_effect = raise_request_exception
        with self.assertRaises(Exception) as ctx:
            generate_token('iss', 'cid', 'csec', 'user', 'pass')
        self.assertEqual('Error: Failed to fetch.', str(ctx.exception))

    @unpack
    @data(
        ({}, {'aud': 'aud', 'cid': 'cid', 'iss': 'iss'}, None, 'cid'),
        ({}, {'aud': 'aud', 'cid': 'cid', 'iss': 'iss'},
         None, ['cid', 'cid1']),
        ({}, {'aud': 'aud', 'cid': 'cid', 'iss': 'iss',
              'iat': get_now_formatted(), 'exp': get_now_formatted(10)}, None, 'cid'),
        ({}, {'aud': 'aud', 'cid': 'cid', 'iss': 'iss', 'iat': get_now_formatted(-10),
              'exp': get_now_formatted(-1)}, ExpiredSignatureError, 'cid'),
    )
    @patch('okta_jwt.jwt.fetch_jwk_for')
    @patch('okta_jwt.jwt.jwk')
    def test_validate_token(self, header, claims, error_t, cids, mockjwk, _):
        mockjwk.construct.return_value = jwk.construct(
            self.pub_pem, algorithm=jwk.ALGORITHMS.RS256)
        access_token = jwt.encode(
            claims, self.priv_pem, jwt.ALGORITHMS.RS256, header)
        if error_t:
            with self.assertRaises(error_t) as ctx:
                validate_token(
                    access_token, claims['iss'], claims['aud'], cids)
            self.assertEqual(error_t, type(ctx.exception))
        else:
            res = validate_token(
                access_token, claims['iss'], claims['aud'], cids)
            self.assertEqual(res, claims)

    @patch('okta_jwt.jwt.fetch_jwk_for')
    @patch('okta_jwt.jwt.jwk')
    def test_validate_token_fail(self, mockjwk, _):
        mockjwk.construct.return_value = jwk.construct(
            self.pub_pem, algorithm=jwk.ALGORITHMS.RS256)
        access_token = jwt.encode(
            {'iss': 'iss', 'aud': 'aud', 'cid': 'cid'}, self.priv_pem, jwt.ALGORITHMS.RS256)
        access_token = '=' + access_token
        with self.assertRaises(Exception) as ctx:
            validate_token(access_token, 'iss', 'aud', 'cid')
        self.assertEqual('Invalid Token', str(ctx.exception))

    @unpack
    @data(
        ({}, ValueError, 'Token header is missing "kid" value', None, None),
        ({'kid': 'kid'}, None, '', None, pem_to_dict(pub_pem)),
        ({'kid': 'kid1'}, Exception, 'Not found.',
         MockHTTPResponse(404, text='Not found.'), None),
        ({'kid': 'kid2'}, Exception, 'Error: Could not find jwk for kid: kid2',
         MockHTTPResponse(json={'keys': [{'kid': 'kid1'}]}), None),
        ({'kid': 'kid2'}, None, '', MockHTTPResponse(
            json={'keys': [{'kid': 'kid2'}]}), {'kid': 'kid2'})
    )
    @patch.dict(JWKS_CACHE, {'kid': pem_to_dict(pub_pem)})
    @patch('okta_jwt.jwt.fetch_metadata_for')
    @patch('okta_jwt.jwt.requests.get')
    def test_fetch_jwk_for(self, header, error_t, error, getresponse, expected, mockget, _):
        mockget.return_value = getresponse
        if error_t:
            with self.assertRaises(error_t) as ctx:
                fetch_jwk_for(header, {})
            self.assertEqual(error_t, type(ctx.exception))
            self.assertEqual(error, ctx.exception.args[0])
        else:
            jwk = fetch_jwk_for(header, {})
            self.assertEqual(jwk, expected)

    @patch('okta_jwt.jwt.fetch_metadata_for')
    @patch('okta_jwt.jwt.requests.get')
    def test_fetch_jwk_request_error(self, mockget, _):
        mockget.side_effect = raise_request_exception
        with self.assertRaises(Exception) as ctx:
            fetch_jwk_for({'kid': 'kid'}, {})
        self.assertEqual('Error: Failed to fetch.', str(ctx.exception))

    @unpack
    @data(
        ({'cid': 'cid', 'iss': 'iss'}, MockHTTPResponse(
            404, 'Not found.'), 'Not found.'),
        ({'cid': 'cid', 'iss': 'iss'}, MockHTTPResponse(), '')
    )
    @patch('okta_jwt.jwt.requests.get')
    def test_metadata_for(self, payload, getresponse, error, mockget):
        mockget.return_value = getresponse
        if error:
            with self.assertRaises(Exception) as ctx:
                fetch_metadata_for(payload)
            self.assertEqual(error, ctx.exception.args[0])
        else:
            meta = fetch_metadata_for(payload)
            self.assertEqual(meta, {})

    @patch('okta_jwt.jwt.requests.get')
    def test_fetch_metadata_request_error(self, mockget):
        mockget.side_effect = raise_request_exception
        with self.assertRaises(Exception) as ctx:
            fetch_metadata_for({'cid': 'cid', 'iss': 'iss'})
        self.assertEqual('Error: Failed to fetch.', str(ctx.exception))
