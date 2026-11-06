# redacting-logger

[![PyPI version](https://img.shields.io/pypi/v/trysac-redacting-logger)](https://pypi.org/project/trysac-redacting-logger/)
[![License: MIT](https://img.shields.io/pypi/l/trysac-redacting-logger)](LICENSE)
[![CI](https://github.com/Trysac/u039-redacting-logger/actions/workflows/ci.yml/badge.svg)](https://github.com/Trysac/u039-redacting-logger/actions/workflows/ci.yml)

JSON log formatter and filter for stdlib logging that redacts secrets and personal data by key name and by bounded value patterns

## Problem

Describe in two or three sentences the concrete problem this utility solves, who hits it, and what
they do today without it. Replace this paragraph when the first real feature lands.

## Install

```sh
pip install trysac-redacting-logger
# or
uv add trysac-redacting-logger
```

Requires Python 3.10 or newer. No runtime dependencies.

## Usage

```python
import redacting_logger

# normalize() trims surrounding whitespace and lower-cases the text.
print(redacting_logger.normalize("  Hello World "))  # -> "hello world"

# Blank input is rejected explicitly instead of returning an empty string.
try:
    redacting_logger.normalize("   ")
except ValueError as exc:
    print(f"rejected: {exc}")
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md) and [decisions](docs/decisions/)
- [Testing](docs/TESTING.md) and [security](docs/SECURITY.md)
- [Project record](docs/PROJECT.md) and [stack](docs/STACK.md)
- [Changelog](CHANGELOG.md) and [contributing guide](CONTRIBUTING.md)

## License

[MIT](LICENSE) (c) 2026 Miguel Gomez
