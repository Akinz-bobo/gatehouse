import type { Config, ModuleName } from '../config.js';
import type { PasswordHasher } from '../crypto/password.js';
import type { SecretBox } from '../crypto/secretbox.js';
import type { Pool } from '../db/pool.js';
import type { KeyStore } from './keys.js';
import type { User } from './users.js';

/** Something that happened, for the audit module and any other listener. */
export interface AuthEvent {
  type: string;
  actorId?: string | undefined;
  subjectId?: string | undefined;
  ip?: string | undefined;
  userAgent?: string | undefined;
  details?: Record<string, unknown>;
}

/** A second step a user must pass after their password, such as a TOTP code. */
export interface LoginChallenge {
  method: string;
}

type Queryable = Pick<Pool, 'query'>;

/**
 * The extension points modules plug into. The core knows nothing about roles,
 * second factors or audit logs; it only calls whatever has been registered.
 */
export class Hooks {
  private readonly claimSources: ((db: Queryable, user: User) => Promise<object>)[] = [];
  private readonly challengeSources: ((
    db: Queryable,
    user: User,
  ) => Promise<LoginChallenge | null>)[] = [];
  private readonly listeners: ((event: AuthEvent) => Promise<void>)[] = [];

  /** Adds claims to every access token (the rbac module adds roles and permissions). */
  addClaims(source: (db: Queryable, user: User) => Promise<object>): void {
    this.claimSources.push(source);
  }

  /** Lets a module demand a second step at sign-in. */
  addChallenge(source: (db: Queryable, user: User) => Promise<LoginChallenge | null>): void {
    this.challengeSources.push(source);
  }

  onEvent(listener: (event: AuthEvent) => Promise<void>): void {
    this.listeners.push(listener);
  }

  async claimsFor(db: Queryable, user: User): Promise<Record<string, unknown>> {
    const parts = await Promise.all(this.claimSources.map((source) => source(db, user)));
    return Object.assign({}, ...parts) as Record<string, unknown>;
  }

  async challengesFor(db: Queryable, user: User): Promise<LoginChallenge[]> {
    const found = await Promise.all(this.challengeSources.map((source) => source(db, user)));
    return found.filter((challenge) => challenge !== null);
  }

  async emit(event: AuthEvent): Promise<void> {
    await Promise.all(this.listeners.map((listener) => listener(event)));
  }
}

/** Delivers messages to users. The default implementation only logs them. */
export interface Notifier {
  passwordReset(email: string, token: string): Promise<void>;
}

/** Everything the core and the modules share. */
export interface Context {
  config: Config;
  pool: Pool;
  keys: KeyStore;
  hasher: PasswordHasher;
  secrets: SecretBox;
  hooks: Hooks;
  notifier: Notifier;
  enabled: ReadonlySet<ModuleName>;
}
