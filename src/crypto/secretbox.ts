import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

const ALGORITHM = 'aes-256-gcm';
const NONCE_BYTES = 12;
const TAG_BYTES = 16;
const VERSION = 'v1';

/**
 * Encrypts secrets the service must be able to read back (signing keys, TOTP
 * secrets) before they are stored. AES-256-GCM both hides the value and
 * detects tampering. A database dump alone is useless without the key, which
 * lives in the environment, not the database.
 */
export class SecretBox {
  constructor(private readonly key: Buffer) {
    if (key.length !== 32) throw new Error('The key-encryption key must be 32 bytes');
  }

  static fromBase64(value: string): SecretBox {
    return new SecretBox(Buffer.from(value, 'base64'));
  }

  encrypt(plaintext: string): string {
    const nonce = randomBytes(NONCE_BYTES);
    const cipher = createCipheriv(ALGORITHM, this.key, nonce);
    const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    return [VERSION, nonce, ciphertext, cipher.getAuthTag()]
      .map((part) => (typeof part === 'string' ? part : part.toString('base64url')))
      .join('.');
  }

  decrypt(sealed: string): string {
    const [version, nonce, ciphertext, tag] = sealed.split('.');
    if (version !== VERSION || !nonce || !ciphertext || !tag) {
      throw new Error('Unrecognised ciphertext format');
    }
    const decipher = createDecipheriv(ALGORITHM, this.key, Buffer.from(nonce, 'base64url'));
    const authTag = Buffer.from(tag, 'base64url');
    if (authTag.length !== TAG_BYTES) throw new Error('Unrecognised ciphertext format');
    decipher.setAuthTag(authTag);
    return Buffer.concat([
      decipher.update(Buffer.from(ciphertext, 'base64url')),
      decipher.final(),
    ]).toString('utf8');
  }
}
