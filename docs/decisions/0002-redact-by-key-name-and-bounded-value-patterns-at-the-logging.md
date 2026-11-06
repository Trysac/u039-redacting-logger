# Redact by key name and bounded value patterns at the logging boundary

Status: accepted (generated, pending human review)

## Context

Logs are shipped to third-party platforms and leak API keys, bearer tokens and emails passed in messages, arguments, extras and exception text. Masking at every call site does not work, and python-json-logger does not redact. The library must be safe on untrusted input: bounded work, no exceptions from the formatter, strict JSON.

## Decision

Provide a logging.Filter that redacts the record in place and a JSON formatter that redacts independently, so each is safe alone. Redaction runs on the formatted message (args are applied first), extras, dict keys and exception text. Sensitive values are identified by normalised key name (equal to a name or ending in '_' + name), and strings by eight patterns with bounded, non-nested quantifiers. Card numbers use a candidate regex plus a Luhn check with a shorter-span fallback. Strings, items and depth are capped, cycles are detected, and formatting falls back to a fixed line instead of raising. Configuration errors raise one typed RedactionError with a stable code. The standard library is the only dependency and the root logger is never touched.

## Consequences

Matching cost is linear in the capped input and output is always strict JSON. Secrets that have no recognisable key or shape, handlers attached elsewhere, and names and addresses are not covered, so redaction is best effort and documented as such. Truncation can cut a secret, leaving only a partial token that no pattern matches. Custom patterns are the caller's responsibility for backtracking. The filter mutates the shared record, so all handlers of that record see the redacted version.
