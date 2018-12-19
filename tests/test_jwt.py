import os
import json
import mock
import unittest
from mock import patch
from okta_jwt.exceptions import JWTClaimsError
from okta_jwt.jwt import validate_token, generate_token



class TestJWT(unittest.TestCase):

    def setUp(self):
        self.access_token = generate_token()
        self.issuer       = os.environ['OKTA_ISSUER']
        self.audience     = os.environ['OKTA_AUDIENCE']
        self.client_id    = os.environ['OKTA_CLIENT_IDS']


    @mock.patch.dict(os.environ, {'OKTA_ISSUER': ''})
    def test_presence_of_issuer(self):
        with self.assertRaises(ValueError) as context:
            validate_token(self.access_token)

        self.assertTrue('Issuer is required' in str(context.exception))


    def test_presence_of_token(self):
        self.access_token = ''

        with self.assertRaises(ValueError) as context:
            validate_token(self.access_token)

        self.assertTrue('Access Token is required' in str(context.exception))


    @mock.patch.dict(os.environ, {'OKTA_AUDIENCE': ''})
    def test_presence_of_audience(self):
        with self.assertRaises(ValueError) as context:
            validate_token(self.access_token)

        self.assertTrue('Audience is required' in str(context.exception))


    @mock.patch.dict(os.environ, {'OKTA_CLIENT_IDS': ''})
    def test_presence_of_client_id(self):
        with self.assertRaises(ValueError) as context:
            validate_token(self.access_token)

        self.assertTrue('Client ID is required' in str(context.exception))


    @mock.patch.dict(os.environ, {'OKTA_ISSUER': 'invalid'})
    def test_invalid_issuer(self):

        with self.assertRaises(JWTClaimsError) as context:
            validate_token(self.access_token)

        self.assertTrue('Invalid Issuer' in str(context.exception))


    @mock.patch.dict(os.environ, {'OKTA_AUDIENCE': 'invalid'})
    def test_invalid_audience(self):
        self.audience = 'invalid'

        with self.assertRaises(JWTClaimsError) as context:
            validate_token(self.access_token)

        self.assertTrue('Invalid Audience' in str(context.exception))


    @mock.patch.dict(os.environ, {'OKTA_CLIENT_IDS': 'invalid'})
    def test_invalid_client(self):
        self.client_id = 'invalid'

        with self.assertRaises(JWTClaimsError) as context:
            validate_token(self.access_token)

        self.assertTrue('Invalid Client' in str(context.exception))


    def test_valid_token(self):
        valid = validate_token(self.access_token)
        self.assertTrue(bool(valid))



if __name__ == "__main__":
    unittest.main()