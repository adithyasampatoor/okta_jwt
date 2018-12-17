import os
import json
import unittest
from okta_jwt.exceptions import JWTClaimsError
from okta_jwt.jwt import validate_token, generate_token



class TestJWT(unittest.TestCase):
    def setUp(self):
        self.access_token = generate_token()
        self.issuer       = os.environ['OKTA_ISSUER']
        self.audience     = os.environ['OKTA_AUDIENCE']
        self.client_id    = os.environ['OKTA_CLIENT_IDS']


    def test_presence_of_issuer(self):
        self.issuer = ''

        with self.assertRaises(ValueError) as context:
            validate_token(self.access_token, self.issuer, self.audience, self.client_id)

        self.assertTrue('Issuer is required' in str(context.exception))


    def test_presence_of_token(self):
        self.access_token = ''

        with self.assertRaises(ValueError) as context:
            validate_token(self.access_token, self.issuer, self.audience, self.client_id)

        self.assertTrue('Access Token is required' in str(context.exception))


    def test_presence_of_audience(self):
        self.audience = ''

        with self.assertRaises(ValueError) as context:
            validate_token(self.access_token, self.issuer, self.audience, self.client_id)

        self.assertTrue('Audience is required' in str(context.exception))


    def test_presence_of_client_id(self):
        self.client_id = ''

        with self.assertRaises(ValueError) as context:
            validate_token(self.access_token, self.issuer, self.audience, self.client_id)

        self.assertTrue('Client ID is required' in str(context.exception))


    def test_invalid_issuer(self):
        self.issuer = 'invalid'

        with self.assertRaises(JWTClaimsError) as context:
            validate_token(self.access_token, self.issuer, self.audience, self.client_id)

        self.assertTrue('Invalid Issuer' in str(context.exception))


    def test_invalid_audience(self):
        self.audience = 'invalid'

        with self.assertRaises(JWTClaimsError) as context:
            validate_token(self.access_token, self.issuer, self.audience, self.client_id)

        self.assertTrue('Invalid Audience' in str(context.exception))


    def test_invalid_client(self):
        self.client_id = 'invalid'

        with self.assertRaises(JWTClaimsError) as context:
            validate_token(self.access_token, self.issuer, self.audience, self.client_id)

        self.assertTrue('Invalid Client' in str(context.exception))


    def test_valid_token(self):
        valid = validate_token(self.access_token, self.issuer, self.audience, self.client_id)
        self.assertTrue(bool(valid))



if __name__ == "__main__":
    unittest.main()