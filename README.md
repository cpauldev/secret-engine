<img src="https://raw.githubusercontent.com/cpauldev/secret-engine/main/banner.png" alt="SecretEngine Banner" width="100%" />

# SecretEngine: Context-Bound Secret Utilities for TypeScript

![TypeScript](https://img.shields.io/badge/-TypeScript-3178C6?style=flat-square&logo=typescript&logoColor=white) ![Crypto](https://img.shields.io/badge/-Cryptography-111827?style=flat-square) ![Cipher](https://img.shields.io/badge/-AES--256--GCM-3F3F46?style=flat-square) ![KDF](https://img.shields.io/badge/-HKDF--SHA256-1E3A8A?style=flat-square) ![License](https://img.shields.io/badge/-MIT_License-blue?style=flat-square) [![Changelog](https://img.shields.io/badge/Changelog-v0.1.1-blue?style=flat-square)](./CHANGELOG.md)

SecretEngine helps TypeScript applications encrypt, mask, hash, generate, and verify sensitive values such as API keys, OAuth tokens, device codes, verification codes, and integration secrets. It uses AES-256-GCM for authenticated encryption and HKDF for purpose/context-bound key derivation.

It is designed for developers who need safer secret handling without scattering low-level crypto decisions across application code. Use it when encrypted values should only decrypt for the intended purpose and owner, when verification codes need constant-time checks, or when logs and UI need masked secret previews.

#### 🤖 Ask your coding assistant

> "Audit my codebase to see if adding the `secret-engine` package on npm is beneficial. If so, explain why and draft an integration plan identifying values to encrypt, purpose/context strings to use, hash-verification locations, and mask points using the package README and source code."

---

## Why use SecretEngine?

| Feature                | Without SecretEngine                                             | With **SecretEngine**                                                             |
| :--------------------- | :--------------------------------------------------------------- | :-------------------------------------------------------------------------------- |
| **Encryption Details** | Apps repeat IV, auth tag, and key derivation code.               | 🔒 **AES-256-GCM Envelopes.** AES-256-GCM envelopes are handled consistently.     |
| **Context Binding**    | A ciphertext may decrypt in the wrong feature or tenant context. | 🔗 **HKDF Derivation.** `purpose` and `context` are part of key derivation.       |
| **Code Verification**  | String comparisons can leak timing information.                  | ⚡ **Timing-Safe Checking.** `verifySecretHash()` uses constant-time comparison.  |
| **Secret Display**     | UI previews often duplicate masking logic.                       | 👁️ **UI Masking.** `maskSecret()` provides one masking primitive.                 |
| **Code Generation**    | Verification codes need consistent length/alphabet/chunking.     | 🎲 **Secure Generation.** `generateCode()` handles secure random code generation. |

---

## Installation

Install SecretEngine via your preferred package manager:

```bash
# npm
npm install secret-engine

# yarn
yarn add secret-engine

# pnpm
pnpm add secret-engine

# bun
bun add secret-engine
```

---

## Quick Start

```ts
import { SecretEngine } from "secret-engine";

const secrets = new SecretEngine({
  masterKey: process.env.SECRET_ENCRYPTION_KEY!,
});

const encrypted = await secrets.encrypt("sk_live_abc", {
  purpose: "provider-api-key",
  context: `user:${userId}`,
});

const plain = await secrets.decrypt(encrypted, {
  purpose: "provider-api-key",
  context: `user:${userId}`,
});
```

Changing either `purpose` or `context` causes decryption to fail.

Use stable, non-empty `purpose` and `context` strings. A good pattern is `purpose` for the feature boundary (`"provider-api-key"`, `"device-code"`) and `context` for the owner or tenant boundary (`"user:123"`, `"tenant:acme"`). Reusing the same pair intentionally reuses the derived key.

---

## Practical Examples

### Encrypt user-owned API keys

```ts
const encryptedKey = await secrets.encrypt(apiKey, {
  purpose: "api-key",
  context: `user:${user.id}`,
});
```

### Generate and verify codes

```ts
import { generateCode, hashSecret, verifySecretHash } from "secret-engine";

const code = generateCode({ length: 6, chunkSize: 3 });
const storedHash = hashSecret(code, {
  secret: process.env.CODE_HASH_SECRET!,
  normalize: (value) => value.replace(/-/g, "").toUpperCase(),
});

const valid = verifySecretHash(input, storedHash, {
  secret: process.env.CODE_HASH_SECRET!,
  normalize: (value) => value.replace(/-/g, "").toUpperCase(),
});
```

### Mask secrets for UI or logs

```ts
import { maskSecret } from "secret-engine";

maskSecret("sk_live_abcdef123456");
// "sk_l••••••3456"
```

### Use low-level helpers

```ts
import { decryptWithKey, deriveKeyHKDF, encryptWithKey } from "secret-engine";

const key = await deriveKeyHKDF(masterKey, "integration-secret", "tenant:acme");

const envelope = encryptWithKey("secret value", key);
const plain = decryptWithKey(envelope, key);
```

---

## API Reference

| Export                                   | Purpose                                                                |
| :--------------------------------------- | :--------------------------------------------------------------------- |
| `SecretEngine`                           | High-level encrypt/decrypt class using a caller-provided master key.   |
| `encryptWithKey(value, key)`             | Encrypts a string with AES-256-GCM.                                    |
| `decryptWithKey(envelope, key)`          | Decrypts an AES-256-GCM envelope.                                      |
| `deriveKeyHKDF(masterKey, salt, info)`   | Derives a 32-byte key for a purpose/context.                           |
| `maskSecret(value, options?)`            | Masks a secret while keeping optional prefix/suffix characters.        |
| `generateCode(options?)`                 | Generates secure random codes with configurable alphabet and chunking. |
| `hashSecret(value, options)`             | Creates an HMAC hash for later verification.                           |
| `verifySecretHash(value, hash, options)` | Verifies a hash using constant-time comparison.                        |

---

## Development

To build the package and generate TypeScript declarations:

```bash
bun run build
```

To run the package unit tests:

```bash
bun run test
```

To run the package type check:

```bash
bun run typecheck
```

After building, verify the published runtime exports:

```bash
bun run test:smoke
```

---

## Related Packages

- [`rate-engine`](https://github.com/cpauldev/rate-engine) for policy-driven rate limiting.
- [`boundary-engine`](https://github.com/cpauldev/boundary-engine) for safe HTTP route boundaries.
- [`redact-engine`](https://github.com/cpauldev/redact-engine) for sensitive data redaction.
- [`session-engine`](https://github.com/cpauldev/session-engine) for browser session and cache lifecycle management.

---

## License

MIT © [Christian Paul](https://github.com/cpauldev)
