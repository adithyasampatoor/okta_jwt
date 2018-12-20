import unittest
from mock import patch
from ddt import ddt, data, unpack
from okta_jwt import utils
from okta_jwt.exceptions import JWTClaimsError, ExpiredSignatureError


@ddt
class TestUtils(unittest.TestCase):
    now = 1545320000
    iat = 1545315000

    @unpack
    @data(
        (None, None, None, None, 'Access Token is required'),
        ('token', None, None, None, 'Issuer is required'),
        ('token', 'issuer', None, None, 'Audience is required'),
        ('token', 'issuer', 'audience', '', 'Client ID is required')
    )
    def test_presence_of(self, access_token, issuer, audience, client_ids, error):
        with self.assertRaises(ValueError) as ctx:
            utils.check_presence_of(access_token, issuer, audience, client_ids)
        self.assertEqual(error, str(ctx.exception))

    @unpack
    @data(
        ({'iss': 'invalid'}, 'issuer', True),
        ({'iss': 'issuer'}, 'issuer', False)
    )
    def test_verify_iss(self, payload, issuer, should_raise):
        if should_raise:
            with self.assertRaises(JWTClaimsError) as ctx:
                utils.verify_iss(payload, issuer)
            self.assertEqual('Invalid Issuer', str(ctx.exception))
        else:
            self.assertIsNone(utils.verify_iss(payload, issuer))

    @unpack
    @data(
        ({'cid': 'invalid'}, 'client_id', True),
        ({'cid': 'client_id'}, 'client_id', False),
        ({'cid': 'client_id'}, ['client_id', 'other'], False)
    )
    def test_verify_cid(self, payload, cid_list, should_raise):
        if should_raise:
            with self.assertRaises(JWTClaimsError) as ctx:
                utils.verify_cid(payload, cid_list)
            self.assertEqual('Invalid Client', str(ctx.exception))
        else:
            self.assertIsNone(utils.verify_cid(payload, cid_list))

    @unpack
    @data(
        ({}, 0, False, None, ''),
        ({'exp': ''}, 0, True, JWTClaimsError,
         'Expiration Time payload (exp) must be an integer.'),
        ({'exp': now}, 0, False, None, ''),
        ({'exp': now}, 1, False, None, ''),
        ({'exp': now - 1}, 0, True, ExpiredSignatureError, 'Token is expired.')
    )
    @patch('okta_jwt.utils.timegm')
    def test_verify_exp(self, payload, leeway, should_raise, error_t, error, mocktimegm):
        mocktimegm.return_value = self.now
        if should_raise:
            with self.assertRaises(error_t) as ctx:
                utils.verify_exp(payload, leeway)
            self.assertEqual(error, str(ctx.exception))
        else:
            self.assertIsNone(utils.verify_exp(payload, leeway))

    @unpack
    @data(
        ({}, None, False, ''),
        ({'aud': None}, None, True, 'Invalid claim format in token'),
        ({'aud': [None]}, None, True, 'Invalid claim format in token'),
        ({'aud': 'invalid'}, 'api://default', True, 'Invalid Audience')
    )
    def test_verify_aud(self, payload, audience, should_raise, error):
        if should_raise:
            with self.assertRaises(JWTClaimsError) as ctx:
                utils.verify_aud(payload, audience)
            self.assertEqual(error, str(ctx.exception))
        else:
            self.assertIsNone(utils.verify_aud(payload, audience))

    @unpack
    @data(
        ({}, 0, False),
        ({'iat': iat}, 0, False),
        ({'iat': iat + 1}, 0, True)
    )
    @patch('okta_jwt.utils.timegm')
    def test_verify_iat(self, payload, leeway, should_raise, mocktimegm):
        mocktimegm.return_value = self.iat
        if should_raise:
            with self.assertRaises(JWTClaimsError) as ctx:
                utils.verify_iat(payload, leeway)
            self.assertEqual('Invalid Issued At(iat) Time', str(ctx.exception))
        else:
            self.assertIsNone(utils.verify_iat(payload, leeway))
