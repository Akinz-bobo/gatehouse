import { hash, verify } from '@node-rs/argon2';

export interface PasswordHasherOptions {
  /** Memory in KiB. OWASP's minimum for Argon2id is 19 MiB with 2 iterations. */
  memoryCost: number;
  timeCost: number;
}

export const DEFAULT_HASHER_OPTIONS: PasswordHasherOptions = { memoryCost: 19_456, timeCost: 2 };

/**
 * Hashes passwords with Argon2id, which is deliberately slow and memory-hard
 * so that a stolen database cannot be cracked cheaply. The parameters are
 * stored inside each hash, so they can be raised later without a migration.
 */
export class PasswordHasher {
  private dummyHash: Promise<string> | undefined;

  constructor(private readonly options: PasswordHasherOptions = DEFAULT_HASHER_OPTIONS) {}

  hash(password: string): Promise<string> {
    return hash(password, { ...this.options, parallelism: 1 });
  }

  async verify(passwordHash: string, password: string): Promise<boolean> {
    try {
      return await verify(passwordHash, password);
    } catch {
      // A malformed hash is a failed login, not a crash.
      return false;
    }
  }

  /**
   * Spends the same time as a real verification. Called when the account does
   * not exist, so response time does not reveal which emails are registered.
   */
  async verifyDummy(password: string): Promise<void> {
    this.dummyHash ??= this.hash('gatehouse-dummy-password');
    await this.verify(await this.dummyHash, password);
  }
}
