export {
  decryptWithKey,
  deriveKeyHKDF,
  ENCRYPTION_CONSTANTS,
  encryptWithKey,
  generateCode,
  hashSecret,
  maskSecret,
  SecretEngine,
  verifySecretHash,
} from "./secret-engine.js";

export type {
  CodeOptions,
  EncryptedEnvelopeOptions,
  HashOptions,
  MaskSecretOptions,
  SecretEngineOptions,
} from "./types.js";
