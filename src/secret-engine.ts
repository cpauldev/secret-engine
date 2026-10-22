import crypto from "crypto";
import { promisify } from "util";

import type {
  CodeOptions,
  EncryptedEnvelopeOptions,
  HashOptions,
  MaskSecretOptions,
  SecretEngineOptions,
} from "./types.js";

const hkdfAsync = promisify(crypto.hkdf);
const ALGORITHM = "aes-256-gcm";
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;
const KEY_LENGTH = 32;
const DEFAULT_MIN_MASTER_KEY_LENGTH = 32;

export const ENCRYPTION_CONSTANTS = {
  ALGORITHM,
  IV_LENGTH,
  AUTH_TAG_LENGTH,
  KEY_LENGTH,
} as const;

function assertKeyLength(key: Buffer, operation: string): void {
  if (key.length !== KEY_LENGTH) {
    throw new Error(`${operation} key must be exactly 32 bytes (256 bits)`);
  }
}

function assertBase64Envelope(value: string): void {
  if (
    value.length % 4 !== 0 ||
    !/^[A-Za-z0-9+/]+={0,2}$/.test(value) ||
    /=[^=]/.test(value)
  ) {
    throw new Error("Invalid encrypted data encoding");
  }
}

/**
 * Encrypts a plaintext string using AES-256-GCM with a pre-derived 32-byte key.
 * Generates a random initialization vector (IV) and appends the authentication tag.
 *
 * @param plaintext The string value to encrypt.
 * @param key Cryptographically secure 32-byte Buffer key.
 * @returns A base64-encoded envelope string containing the IV, auth tag, and ciphertext.
 */
export function encryptWithKey(plaintext: string, key: Buffer): string {
  assertKeyLength(key, "Encryption");
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  const encrypted = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]);
  const combined = Buffer.concat([iv, cipher.getAuthTag(), encrypted]);
  return combined.toString("base64");
}

/**
 * Decrypts an AES-256-GCM envelope using a pre-derived 32-byte key.
 * Verifies authenticity before decrypting.
 *
 * @param encryptedData The base64-encoded envelope string.
 * @param key Cryptographically secure 32-byte Buffer key.
 * @returns The decrypted plaintext string.
 */
export function decryptWithKey(encryptedData: string, key: Buffer): string {
  assertKeyLength(key, "Decryption");
  assertBase64Envelope(encryptedData);
  const data = Buffer.from(encryptedData, "base64");
  if (data.length < IV_LENGTH + AUTH_TAG_LENGTH) {
    throw new Error("Invalid encrypted data format");
  }
  const iv = data.subarray(0, IV_LENGTH);
  const authTag = data.subarray(IV_LENGTH, IV_LENGTH + AUTH_TAG_LENGTH);
  const ciphertext = data.subarray(IV_LENGTH + AUTH_TAG_LENGTH);
  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(authTag);
  return Buffer.concat([
    decipher.update(ciphertext),
    decipher.final(),
  ]).toString("utf8");
}

/**
 * Derives a cryptographically strong 32-byte key from a master key using HKDF-SHA256.
 * Ensures the derived key is bound to a specific context and purpose.
 *
 * @param masterKey High-entropy master key.
 * @param salt Operation-specific salt (e.g. purpose name).
 * @param info Caller-specific context metadata (e.g. tenant or user ID).
 * @returns A promise resolving to a 32-byte key buffer.
 */
export async function deriveKeyHKDF(
  masterKey: string,
  salt: string,
  info: string,
): Promise<Buffer> {
  const derivedKey = await hkdfAsync(
    "sha256",
    Buffer.from(masterKey, "utf8"),
    Buffer.from(salt, "utf8"),
    Buffer.from(info, "utf8"),
    KEY_LENGTH,
  );
  return Buffer.from(derivedKey);
}

function assertMasterKey(options: SecretEngineOptions): void {
  const minimum = options.minMasterKeyLength ?? DEFAULT_MIN_MASTER_KEY_LENGTH;
  if (!options.masterKey || options.masterKey.length < minimum) {
    throw new Error(`masterKey must be at least ${minimum} characters`);
  }
}

function assertEnvelopeOptions(options: EncryptedEnvelopeOptions): void {
  if (!options.purpose.trim()) {
    throw new Error("purpose must be a non-empty string");
  }
  if (!options.context.trim()) {
    throw new Error("context must be a non-empty string");
  }
}

/**
 * A context-bound encryption engine that manages AES-256-GCM encryption
 * and HKDF-SHA256 key derivation using a configured master key.
 */
export class SecretEngine {
  /**
   * Initializes a new instance of the SecretEngine.
   *
   * @param options Configuration options containing the masterKey.
   */
  constructor(private readonly options: SecretEngineOptions) {
    assertMasterKey(options);
  }

  private deriveEnvelopeKey(
    options: EncryptedEnvelopeOptions,
  ): Promise<Buffer> {
    return deriveKeyHKDF(
      this.options.masterKey,
      options.purpose,
      options.context,
    );
  }

  /**
   * Derives a context-specific key and encrypts the raw plaintext string into a base64 envelope.
   *
   * @param plaintext The sensitive data to encrypt.
   * @param options Metadata specifying purpose and context boundary for key derivation.
   * @returns A base64-encoded envelope containing the derived IV, auth tag, and ciphertext.
   */
  async encrypt(
    plaintext: string,
    options: EncryptedEnvelopeOptions,
  ): Promise<string> {
    assertEnvelopeOptions(options);
    const key = await this.deriveEnvelopeKey(options);
    return encryptWithKey(plaintext, key);
  }

  /**
   * Derives a context-specific key and decrypts the base64-encoded envelope back into plaintext.
   *
   * @param encryptedData The base64-encoded envelope string.
   * @param options Metadata matching the exact purpose and context used for encryption.
   * @returns The decrypted plaintext string.
   */
  async decrypt(
    encryptedData: string,
    options: EncryptedEnvelopeOptions,
  ): Promise<string> {
    assertEnvelopeOptions(options);
    const key = await this.deriveEnvelopeKey(options);
    return decryptWithKey(encryptedData, key);
  }
}

/**
 * Masks a sensitive secret string (like an API key or password) to prevent exposure.
 * Displays only the configured prefixes/suffixes while covering the rest.
 *
 * @param secret The secret string to mask.
 * @param options Configurations for visible characters and custom mask strings.
 * @returns The masked secret string.
 */
export function maskSecret(
  secret: string,
  options: MaskSecretOptions = {},
): string {
  const visibleStart = options.visibleStart ?? 4;
  const visibleEnd = options.visibleEnd ?? 4;
  const mask = options.mask ?? "••••••";
  if (secret.length <= visibleStart + visibleEnd) {
    return `${options.mask ?? "••••"}${secret.slice(-visibleEnd)}`;
  }
  return `${secret.slice(0, visibleStart)}${mask}${secret.slice(-visibleEnd)}`;
}

/**
 * Generates a cryptographically secure random code (e.g. verification code or OTP).
 * Employs rejection sampling to eliminate modulo bias for custom alphabets.
 * Supports grouping into formatted chunks.
 *
 * @param options Configuration for length, alphabet, chunks, and separators.
 * @returns The generated formatted code.
 */
export function generateCode(options: CodeOptions = {}): string {
  const alphabet = options.alphabet ?? "23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
  const length = options.length ?? 16;
  const chunkSize = options.chunkSize ?? 4;
  const separator = options.separator ?? "-";
  if (alphabet.length < 2) {
    throw new Error("alphabet must contain at least 2 characters");
  }
  if (!Number.isInteger(length) || length < 1) {
    throw new Error("length must be a positive integer");
  }
  if (!Number.isInteger(chunkSize)) {
    throw new Error("chunkSize must be an integer");
  }

  // Rejection sampling to avoid modulo bias
  const maxByteValue = 256 - (256 % alphabet.length);
  let code = "";
  while (code.length < length) {
    const bytes = crypto.randomBytes(Math.ceil((length - code.length) * 1.2));
    for (const byte of bytes) {
      if (byte < maxByteValue) {
        code += alphabet[byte % alphabet.length];
        if (code.length === length) break;
      }
    }
  }

  if (chunkSize <= 0) return code;
  const chunks: string[] = [];
  for (let index = 0; index < code.length; index += chunkSize) {
    chunks.push(code.slice(index, index + chunkSize));
  }
  return chunks.join(separator);
}

/**
 * Hashes a secret value for database storage.
 * Generates a secure HMAC-SHA256 digest when a secret pepper is provided,
 * falling back to standard SHA-256 otherwise.
 *
 * @param secret The secret value to hash.
 * @param options Configurations for algorithm, secret keys, and normalization callbacks.
 * @returns A hex-encoded hash string.
 */
export function hashSecret(secret: string, options: HashOptions = {}): string {
  const normalize = options.normalize ?? ((value: string) => value);
  const algorithm = options.algorithm ?? "sha256";
  const normalized = normalize(secret);
  if (options.secret) {
    return crypto
      .createHmac(algorithm, Buffer.from(options.secret, "utf8"))
      .update(normalized)
      .digest("hex");
  }
  return crypto.createHash(algorithm).update(normalized).digest("hex");
}

/**
 * Verifies a candidate secret against an expected hash using a constant-time comparison
 * to block timing side-channel attacks.
 *
 * @param candidate The user-provided raw input to check.
 * @param expectedHash The hex-encoded target hash.
 * @param options Normalization and keyed hashing configuration (must match hashSecret options).
 * @returns True if the candidate matches the expected hash.
 */
export function verifySecretHash(
  candidate: string,
  expectedHash: string,
  options: HashOptions = {},
): boolean {
  const candidateHash = hashSecret(candidate, options);
  try {
    const a = Buffer.from(candidateHash, "hex");
    const b = Buffer.from(expectedHash, "hex");
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
  } catch {
    return false;
  }
}
