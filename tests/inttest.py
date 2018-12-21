import os
import unittest
from okta_jwt import jwt


class IntegrationTest(unittest.TestCase):

    client_id       = os.environ['OKTA_CLIENT_IDS']
    client_sec      = os.environ['OKTA_CLIENT_SECRET']
    iss             = os.environ['OKTA_ISSUER']
    aud             = os.environ['OKTA_AUDIENCE']
    user            = os.environ['OKTA_USERNAME']
    passw           = os.environ['OKTA_PASSWORD']

    def test_(self):
        token = jwt.generate_token(self.iss, self.client_id, self.client_sec, self.user, self.passw)
        print(token)
        validated = jwt.validate_token(token, self.iss, self.aud, [self.client_id])
        self.assertTrue(validated)


if __name__ == '__main__':
    unittest.main()