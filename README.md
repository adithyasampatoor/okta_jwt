# okta_jwt

Okta JWT Access Token Generator & verifier for Python using cached JWKs.

## Installation

    $ pip install okta_jwt

## Usage

Following Environment Variables needs to be configured inorder to run the following

* ```OKTA_CLIENT_IDS```(you can pass in multiple client ids)
* ```OKTA_CLIENT_SECRET```
* ```OKTA_URL```
* ```OKTA_ISSUER```
* ```OKTA_AUDIENCE```

```python
	>>> from okta_jwt.jwt import generate_token
	>>> generate_token()

	This generates and returns Okta Access Token.
	You should Probably see something as below:
	[Okta::Jwt] Generating Okta Token
	{token}
```

```python
	>>> from okta_jwt.jwt import validate_token
	>>> validate_token('access_token')

	Pass in the Access Token generated earlier(you can pass
	in your own okta access token).
	If the token is valid then it will return the payload
```

## Development

## Contributing

Bug reports and Pull Requests(PR's) are welcome on GitHub at https://github.com/adithyasampatoor/okta_jwt. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [Contributor Covenant](http://contributor-covenant.org) code of conduct.

## License

The Library is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT)

## Thanks

This library was originally based heavily on the work of the folks over at 'python-jose'.
