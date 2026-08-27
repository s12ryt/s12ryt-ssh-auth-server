import assert from "node:assert/strict";
import test from "node:test";

import {
  decryptSecret,
  encryptSecret,
  generateOpaqueToken,
  generatePassword,
  hashPassword,
  hashToken,
  verifyPassword,
} from "../src/security/crypto.js";

test("password hashes are salted and verifiable", async () => {
  const first = await hashPassword("correct horse battery staple");
  const second = await hashPassword("correct horse battery staple");

  assert.notEqual(first, second);
  assert.equal(
    await verifyPassword("correct horse battery staple", first),
    true,
  );
  assert.equal(await verifyPassword("wrong", first), false);
  assert.equal(first.includes("correct horse"), false);
});

test("connection secrets use authenticated encryption", () => {
  const masterKey = Buffer.alloc(32, 9);
  const plaintext = JSON.stringify({
    password: "database-secret",
    accessKey: "storage-secret",
  });
  const encrypted = encryptSecret(masterKey, plaintext);

  assert.equal(encrypted.includes("database-secret"), false);
  assert.equal(encrypted.includes("storage-secret"), false);
  assert.equal(decryptSecret(masterKey, encrypted), plaintext);
  assert.throws(() => decryptSecret(Buffer.alloc(32, 1), encrypted));
});

test("opaque tokens and generated passwords have sufficient entropy", () => {
  const accessToken = generateOpaqueToken();
  const refreshToken = generateOpaqueToken();
  const password = generatePassword();

  assert.notEqual(accessToken, refreshToken);
  assert.match(accessToken, /^[A-Za-z0-9_-]{40,}$/);
  assert.match(password, /^[A-Za-z0-9_-]{24,}$/);
  assert.equal(hashToken(accessToken).length, 64);
  assert.notEqual(hashToken(accessToken), accessToken);
});
