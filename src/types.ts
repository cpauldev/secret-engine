/**
 * Configuration options for the SecretEngine instance.
 */
export type SecretEngineOptions = {
  /** The high-entropy key material used to derive context-bound encryption keys. */
  masterKey: string;
  /** Custom override for minimum masterKey character length. Defaults to 32. */
  minMasterKeyLength?: number;
};

/**
 * Options for deriving a context-bound encryption key.
 */
export type EncryptedEnvelopeOptions = {
  /** The descriptive purpose or scope (e.g. 'user_session', 'api_key'). */
  purpose: string;
  /** Context metadata to bind the key (e.g. user ID, workspace ID, tenant ID). */
  context: string;
};

/**
 * Configuration options for masking a sensitive string.
 */
export type MaskSecretOptions = {
  /** The number of visible characters at the start of the string. Defaults to 4. */
  visibleStart?: number;
  /** The number of visible characters at the end of the string. Defaults to 4. */
  visibleEnd?: number;
  /** The masking character sequence. Defaults to '••••••'. */
  mask?: string;
};

/**
 * Configuration options for random code/OTP generation.
 */
export type CodeOptions = {
  /** Total character length of the generated code. Defaults to 16. */
  length?: number;
  /** Custom alphabet string. Defaults to base32-hex-like safe set (no 0, 1, I, O). */
  alphabet?: string;
  /** Number of characters in each chunk for formatting. Defaults to 4. Set to 0 to disable formatting. */
  chunkSize?: number;
  /** The separator character between formatted chunks. Defaults to '-'. */
  separator?: string;
};

/**
 * Configuration options for generating and verifying cryptographic hashes.
 */
export type HashOptions = {
  /** Optional secret pepper/key for generating HMAC signatures instead of simple hash digests. */
  secret?: string;
  /** Optional normalization callback applied to the raw input string before hashing. */
  normalize?: (value: string) => string;
  /** The hash algorithm to use. Defaults to 'sha256'. */
  algorithm?: "sha256" | "sha512";
};
