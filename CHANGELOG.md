# Changelog

All notable changes to this project will be documented in this file.

## [0.1.0] - 2026-06-25

Initial release of `SecretEngine`, a context-bound secret utility toolkit for TypeScript applications.

### Added

- Added `SecretEngine` for purpose/context-bound encryption and decryption of API keys, tokens, device credentials, and integration secrets.
- Added AES-256-GCM envelope encryption helpers with authenticated ciphertext, IV, auth tag, and salt handling.
- Added HKDF-SHA256 key derivation for deriving purpose-bound encryption keys from a root secret.
- Added masking helpers for safe secret previews in UI and logs.
- Added verification-code generation helpers.
- Added secret hashing and constant-time hash verification helpers.
- Added low-level crypto helpers for advanced integrations that need explicit key derivation or envelope handling.
- Added TypeScript declarations, package-local tests, typecheck, build, and built-dist smoke scripts.

### Security

- Encryption APIs bind ciphertext to caller-provided purpose/context values so values can be scoped to an owner, provider, or usage.
- Verification helpers avoid direct string equality for sensitive comparisons.
