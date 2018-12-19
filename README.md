# Okta Jwt

Okta JWT Access Token Generator & verifier for Python using cached JWKs.

Link to PyPi - click [here](https://pypi.org/project/okta-jwt/)

## Installation

```python
	$ pip install okta_jwt
```

### Prerequisites

Following Environment Variables needs to be configured in your `bash_profile`

* ```OKTA_CLIENT_IDS``` (you can pass in multiple client ids)
* ```OKTA_CLIENT_SECRET```
* ```OKTA_ISSUER```
* ```OKTA_AUDIENCE```

NOTE: source your `bash_profile`

### Usage

To generate a token, run
```python
	>>> from okta_jwt.jwt import generate_token
	>>> generate_token()
```

This generates and returns Okta Access Token. You should Probably see something as below:
```python
	[Okta::Jwt] Generating Okta Token
	{token}
```

To Validate the Access Token
```python
	>>> from okta_jwt.jwt import validate_token
	>>> validate_token('access_token')
```

Pass in the Access Token generated earlier(you can pass in your own okta access token).
If the token is valid then it will return the payload.

## Running the tests

To run the unit tests, run

	$ python -m unittest

### Break down into tests

The unit tests pretty much covers all the main functionality of the package, like generating the token, Validating the token, Checking presence of ENV Variables(which is a prerequisite) and Verifying Claims.

## Contributing

Bug reports and Pull Requests(PR's) are welcome on GitHub at https://github.com/adithyasampatoor/okta_jwt. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [Contributor Covenant](http://contributor-covenant.org) code of conduct.

## Authors

* **Adithya Sampatoor**

## License

The Library is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT)
