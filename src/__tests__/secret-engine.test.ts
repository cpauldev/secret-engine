import { describe, expect, it } from "bun:test";

import {
  SecretEngine,
  decryptWithKey,
  deriveKeyHKDF,
  encryptWithKey,
  generateCode,
  hashSecret,
  maskSecret,
  verifySecretHash,
} from "../index";

const masterKey = "0123456789abcdef0123456789abcdef";

describe("secret-engine", () => {
  it("encrypts and decrypts with context-bound keys", async () => {
    const engine = new SecretEngine({ masterKey });
    const encrypted = await engine.encrypt("secret", {
      purpose: "api-key",
      context: "user:1",
    });
    await expect(
      engine.decrypt(encrypted, { purpose: "api-key", context: "user:1" }),
    ).resolves.toBe("secret");
  });

  it("uses random IVs and rejects wrong context or purpose", async () => {
    const engine = new SecretEngine({ masterKey });
    const options = { purpose: "api-key", context: "user:1" };
    const encryptedA = await engine.encrypt("secret", options);
    const encryptedB = await engine.encrypt("secret", options);
    expect(encryptedA).not.toBe(encryptedB);
    await expect(
      engine.decrypt(encryptedA, { purpose: "api-key", context: "user:2" }),
    ).rejects.toThrow();
    await expect(
      engine.decrypt(encryptedA, { purpose: "device-code", context: "user:1" }),
    ).rejects.toThrow();
  });

  it("rejects tampered data", async () => {
    const engine = new SecretEngine({ masterKey });
    const encrypted = await engine.encrypt("secret", {
      purpose: "api-key",
      context: "user:1",
    });
    await expect(
      engine.decrypt(`${encrypted.slice(0, -2)}AA`, {
        purpose: "api-key",
        context: "user:1",
      }),
    ).rejects.toThrow();
  });

  it("rejects malformed envelopes and empty key derivation boundaries", async () => {
    const engine = new SecretEngine({ masterKey });

    expect(() => decryptWithKey("not base64", Buffer.alloc(32))).toThrow(
      "Invalid encrypted data encoding",
    );
    await expect(
      engine.encrypt("secret", { purpose: " ", context: "user:1" }),
    ).rejects.toThrow("purpose must be a non-empty string");
    await expect(
      engine.decrypt("AAAA", { purpose: "api-key", context: " " }),
    ).rejects.toThrow("context must be a non-empty string");
  });

  it("exposes low-level key helpers", async () => {
    const key = await deriveKeyHKDF(masterKey, "purpose", "context");
    const encrypted = encryptWithKey("value", key);
    expect(decryptWithKey(encrypted, key)).toBe("value");
  });

  it("masks, generates, hashes, and verifies secrets", () => {
    expect(maskSecret("abcdefghijkl")).toBe("abcd••••••ijkl");
    expect(generateCode()).toMatch(/^[2-9A-HJ-NP-Z]{4}(?:-[2-9A-HJ-NP-Z]{4}){3}$/);
    const hash = hashSecret("ABCD-1234", {
      normalize: (value) => value.replace(/-/g, "").toLowerCase(),
    });
    expect(
      verifySecretHash("abcd1234", hash, {
        normalize: (value) => value.replace(/-/g, "").toLowerCase(),
      }),
    ).toBe(true);
    expect(verifySecretHash("wrong", hash)).toBe(false);

    // Keyed HMAC hashing test
    const hmacSecret = "my-hmac-salt-secret";
    const hmacHash = hashSecret("ABCD-1234", {
      secret: hmacSecret,
      normalize: (value) => value.replace(/-/g, "").toLowerCase(),
    });
    expect(
      verifySecretHash("abcd1234", hmacHash, {
        secret: hmacSecret,
        normalize: (value) => value.replace(/-/g, "").toLowerCase(),
      }),
    ).toBe(true);
    // Should fail with a different secret
    expect(
      verifySecretHash("abcd1234", hmacHash, {
        secret: "wrong-salt",
        normalize: (value) => value.replace(/-/g, "").toLowerCase(),
      }),
    ).toBe(false);
  });

  it("validates code-generation options", () => {
    expect(() => generateCode({ alphabet: "A" })).toThrow(
      "alphabet must contain at least 2 characters",
    );
    expect(() => generateCode({ length: 0 })).toThrow(
      "length must be a positive integer",
    );
    expect(() => generateCode({ chunkSize: 1.5 })).toThrow(
      "chunkSize must be an integer",
    );
  });
});
