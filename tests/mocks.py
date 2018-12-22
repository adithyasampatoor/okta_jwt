class MockHTTPResponse(object):
    def __init__(self, status_code=200, text='', json={}):
        self.status_code = status_code
        self.text = text
        self._json = json

    def json(self):
        return self._json
