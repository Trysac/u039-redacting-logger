# Security notes

## Threat model

`trysac-redacting-logger` is a pure library without I/O.

### Defended

Tests are in `tests/test_redacting_logger.py`.

- Sensitive keys (DEFAULT_KEYS, with key normalisation): `test_key_normalisation`.
- The 8 patterns (bearer, aws_key, jwt, private_key, github_token, url_credentials, email, card)
  in messages, args, extras, dict keys and tracebacks:
  `test_every_pattern_is_redacted_on_every_surface`.
- Hostile input (huge strings, cycles, depth, JWT-prefix floods): formatting never raises and
  stays fast; see `test_hostile_jwt_prefixes_are_fast`.

### Not defended (best effort)

- Secrets with no recognisable key or shape.
- Handlers added elsewhere that bypass this formatter or filter.
- Personal names and addresses.

## Publishing

Releases are published to PyPI with trusted publishing (OIDC) when available, never with a
long-lived token stored in the repository.

To report a vulnerability, see [SECURITY.md](../SECURITY.md).
