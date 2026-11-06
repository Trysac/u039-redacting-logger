# redacting-logger

[![PyPI version](https://img.shields.io/pypi/v/trysac-redacting-logger)](https://pypi.org/project/trysac-redacting-logger/)
[![License: MIT](https://img.shields.io/pypi/l/trysac-redacting-logger)](LICENSE)
[![CI](https://github.com/Trysac/u039-redacting-logger/actions/workflows/ci.yml/badge.svg)](https://github.com/Trysac/u039-redacting-logger/actions/workflows/ci.yml)

JSON log formatter and filter for stdlib logging that redacts secrets and personal data by key name and by bounded value patterns

## Problem

Logs are shipped to third-party platforms and routinely leak API keys, bearer tokens and emails
passed in messages, arguments, exception text or extra fields. Remembering to mask every call site
does not work. This library redacts by key name and by value pattern before anything is written.

## Install

```sh
pip install trysac-redacting-logger
# or
uv add trysac-redacting-logger
```

Requires Python 3.10 or newer. No runtime dependencies. The install name is
`trysac-redacting-logger`; the import name is `redacting_logger`.

## Usage

```python
import logging
import sys

from redacting_logger import RedactionRules, make_handler, redact

log = logging.getLogger("app")
log.addHandler(make_handler(sys.stdout))
log.setLevel(logging.INFO)
log.info("auth %s", "Bearer abcdef123456")  # message: "auth [REDACTED:bearer]"

rules = RedactionRules()
rules.add_pattern("order", r"ORD-[0-9]{8}")  # raises RedactionError if invalid
print(redact({"password": "p", "note": "ORD-12345678"}, rules))
# {'password': '[REDACTED]', 'note': '[REDACTED:order]'}
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md) and [decisions](docs/decisions/)
- [Testing](docs/TESTING.md) and [security](docs/SECURITY.md)
- [Project record](docs/PROJECT.md) and [stack](docs/STACK.md)
- [Changelog](CHANGELOG.md) and [contributing guide](CONTRIBUTING.md)

## License

[MIT](LICENSE) (c) 2026 Miguel Gomez
