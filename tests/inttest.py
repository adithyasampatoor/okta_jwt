import os
import unittest
from okta_jwt import jwt


class IntegrationTest(unittest.TestCase):

    domain          = os.environ['OKTA_DOMAIN']
    authserver_id   = 'default'
    authserver_aud  = 'api://default'
    client_id       = os.environ['OKTA_CLIENT_ID']
    client_sec      = os.environ['OKTA_CLIENT_SECRET']
    iss             = 'https://{}/oauth2/{}'.format(domain, authserver_id)

    user            = os.environ['OKTA_USERNAME']
    passw           = os.environ['OKTA_PASSWORD']

    def test_(self):
        token = jwt.generate_token(self.iss, self.client_id, self.client_sec, self.user, self.passw)
        print(token)
        validated = jwt.validate_token(token, self.iss, self.authserver_aud, [self.client_id])
        self.assertTrue(validated)


if __name__ == '__main__':
    unittest.main()