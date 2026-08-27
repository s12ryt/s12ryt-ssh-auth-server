import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
  scrypt,
  timingSafeEqual,
} from "node:crypto";

const passwordKeyLength = 32;
const scryptCost = 16_384;
const scryptBlockSize = 8;
const scryptParallelization = 1;

interface SecretEnvelope {
  version: 1;
  nonce: string;
  tag: string;
  ciphertext: string;
}

function derivePassword(password: string, salt: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scrypt(
      password,
      salt,
      passwordKeyLength,
      {
        N: scryptCost,
        r: scryptBlockSize,
        p: scryptParallelization,
        maxmem: 64 * 1024 * 1024,
      },
      (error, derivedKey) => {
        if (error) {
          reject(error);
          return;
        }
        resolve(derivedKey);
      },
    );
  });
}

export async function hashPassword(password: string): Promise<string> {
  if (password.length < 12) {
    throw new Error("password must contain at least 12 characters");
  }
  const salt = randomBytes(16);
  const hash = await derivePassword(password, salt);
  return [
    "scrypt",
    scryptCost,
    scryptBlockSize,
    scryptParallelization,
    salt.toString("base64url"),
    hash.toString("base64url"),
  ].join("$");
}

export async function verifyPassword(
  password: string,
  encoded: string,
): Promise<boolean> {
  const [
    algorithm,
    costSource,
    blockSizeSource,
    parallelizationSource,
    saltSource,
    hashSource,
  ] = encoded.split("$");
  if (
    algorithm !== "scrypt" ||
    costSource !== String(scryptCost) ||
    blockSizeSource !== String(scryptBlockSize) ||
    parallelizationSource !== String(scryptParallelization) ||
    !saltSource ||
    !hashSource
  ) {
    return false;
  }
  try {
    const expected = Buffer.from(hashSource, "base64url");
    const actual = await derivePassword(
      password,
      Buffer.from(saltSource, "base64url"),
    );
    return (
      expected.length === actual.length && timingSafeEqual(expected, actual)
    );
  } catch {
    return false;
  }
}

function validateMasterKey(masterKey: Buffer): void {
  if (masterKey.length !== 32) {
    throw new Error("master key must contain exactly 32 bytes");
  }
}

export function encryptSecret(masterKey: Buffer, plaintext: string): string {
  validateMasterKey(masterKey);
  const nonce = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", masterKey, nonce);
  const ciphertext = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]);
  const envelope: SecretEnvelope = {
    version: 1,
    nonce: nonce.toString("base64url"),
    tag: cipher.getAuthTag().toString("base64url"),
    ciphertext: ciphertext.toString("base64url"),
  };
  return Buffer.from(JSON.stringify(envelope), "utf8").toString("base64url");
}

export function decryptSecret(masterKey: Buffer, encoded: string): string {
  validateMasterKey(masterKey);
  const envelope = JSON.parse(
    Buffer.from(encoded, "base64url").toString("utf8"),
  ) as SecretEnvelope;
  if (
    envelope.version !== 1 ||
    !envelope.nonce ||
    !envelope.tag ||
    !envelope.ciphertext
  ) {
    throw new Error("invalid secret envelope");
  }
  const decipher = createDecipheriv(
    "aes-256-gcm",
    masterKey,
    Buffer.from(envelope.nonce, "base64url"),
  );
  decipher.setAuthTag(Buffer.from(envelope.tag, "base64url"));
  return Buffer.concat([
    decipher.update(Buffer.from(envelope.ciphertext, "base64url")),
    decipher.final(),
  ]).toString("utf8");
}

export function generateOpaqueToken(): string {
  return randomBytes(32).toString("base64url");
}

export function generatePassword(): string {
  return randomBytes(24).toString("base64url");
}

export function hashToken(token: string): string {
  return createHash("sha256").update(token, "utf8").digest("hex");
}
