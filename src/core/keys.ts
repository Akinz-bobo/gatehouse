import { randomUUID, type webcrypto } from 'node:crypto';
import {
  SignJWT,
  createLocalJWKSet,
  exportJWK,
  generateKeyPair,
  importJWK,
  jwtVerify,
  type JWK,
  type JWTPayload,
} from 'jose';
import type { SecretBox } from '../crypto/secretbox.js';
import { withTransaction, type Pool } from '../db/pool.js';

type CryptoKey = webcrypto.CryptoKey;

const ALGORITHM = 'ES256';
const CACHE_MS = 30_000;
// Any constant works; it only has to be the same for every instance.
const KEY_CREATION_LOCK_ID = 727_101;

interface KeyRow {
  kid: string;
  public_jwk: JWK;
  private_jwk_encrypted: string;
}

export interface KeyStoreOptions {
  issuer: string;
  audience: string;
  /** How long a retired key keeps verifying. Must cover the longest-lived token it signed. */
  verifyGraceSeconds: number;
}

/**
 * Owns the keys that sign access tokens.
 *
 * Tokens are signed with ES256, an asymmetric algorithm: this service holds
 * the private key, and everyone else verifies with the public key published
 * at the JWKS endpoint. No other service ever needs a shared secret.
 *
 * Private keys are encrypted before they reach the database, and are rotated
 * without downtime: a retired key stops signing at once but stays published
 * until every token it signed has expired.
 */
export class KeyStore {
  private active: { kid: string; key: CryptoKey; loadedAt: number } | undefined;
  private published: { jwks: { keys: JWK[] }; loadedAt: number } | undefined;

  constructor(
    private readonly pool: Pool,
    private readonly secrets: SecretBox,
    private readonly options: KeyStoreOptions,
  ) {}

  /** Signs a token with the active key, creating the first key on demand. */
  async sign(
    payload: JWTPayload,
    { subject, audience, ttlSeconds }: { subject: string; audience?: string; ttlSeconds: number },
  ): Promise<string> {
    const { kid, key } = await this.activeKey();
    return new SignJWT(payload)
      .setProtectedHeader({ alg: ALGORITHM, kid, typ: 'JWT' })
      .setIssuer(this.options.issuer)
      .setAudience(audience ?? this.options.audience)
      .setSubject(subject)
      .setJti(randomUUID())
      .setIssuedAt()
      .setExpirationTime(`${ttlSeconds}s`)
      .sign(key);
  }

  /**
   * Verifies signature, issuer, audience and expiry, and accepts only the
   * one algorithm this service signs with. Pinning the algorithm closes off
   * the classic attacks of swapping in `none` or an HMAC variant.
   */
  async verify(token: string, audience?: string): Promise<JWTPayload> {
    const verifyWith = async (jwks: { keys: JWK[] }) =>
      jwtVerify(token, createLocalJWKSet(jwks), {
        issuer: this.options.issuer,
        audience: audience ?? this.options.audience,
        algorithms: [ALGORITHM],
      });
    try {
      return (await verifyWith(await this.jwks())).payload;
    } catch (error) {
      // The token may be signed by a key another instance created moments ago.
      if ((error as { code?: string }).code !== 'ERR_JWKS_NO_MATCHING_KEY') throw error;
      this.published = undefined;
      return (await verifyWith(await this.jwks())).payload;
    }
  }

  /** The public keys other services use to verify tokens. */
  async jwks(): Promise<{ keys: JWK[] }> {
    if (this.published && Date.now() - this.published.loadedAt < CACHE_MS) {
      return this.published.jwks;
    }
    await this.activeKey();
    const result = await this.pool.query<{ kid: string; public_jwk: JWK }>(
      `SELECT kid, public_jwk FROM signing_keys
       WHERE retired_at IS NULL OR verify_until > now()
       ORDER BY created_at DESC`,
    );
    const jwks = {
      keys: result.rows.map((row) => ({
        ...row.public_jwk,
        kid: row.kid,
        alg: ALGORITHM,
        use: 'sig',
      })),
    };
    this.published = { jwks, loadedAt: Date.now() };
    return jwks;
  }

  /** Retires the active key and starts signing with a new one. Returns the new key id. */
  async rotate(): Promise<string> {
    const kid = await withTransaction(this.pool, async (client) => {
      await client.query('SELECT pg_advisory_xact_lock($1)', [KEY_CREATION_LOCK_ID]);
      await client.query(
        `UPDATE signing_keys
         SET retired_at = now(), verify_until = now() + make_interval(secs => $1)
         WHERE retired_at IS NULL`,
        [this.options.verifyGraceSeconds],
      );
      return (await this.create(client)).kid;
    });
    this.active = undefined;
    this.published = undefined;
    return kid;
  }

  private async activeKey(): Promise<{ kid: string; key: CryptoKey }> {
    if (this.active && Date.now() - this.active.loadedAt < CACHE_MS) return this.active;

    const row = await withTransaction(this.pool, async (client) => {
      const select = 'SELECT * FROM signing_keys WHERE retired_at IS NULL';
      const existing = await client.query<KeyRow>(select);
      if (existing.rows[0]) return existing.rows[0];

      // No key yet. Take a lock so that instances starting together create one key, not several.
      await client.query('SELECT pg_advisory_xact_lock($1)', [KEY_CREATION_LOCK_ID]);
      const afterLock = await client.query<KeyRow>(select);
      return afterLock.rows[0] ?? (await this.create(client));
    });

    const privateJwk = JSON.parse(this.secrets.decrypt(row.private_jwk_encrypted)) as JWK;
    const key = (await importJWK(privateJwk, ALGORITHM)) as CryptoKey;
    this.active = { kid: row.kid, key, loadedAt: Date.now() };
    return this.active;
  }

  private async create(client: Pick<Pool, 'query'>): Promise<KeyRow> {
    const { publicKey, privateKey } = await generateKeyPair(ALGORITHM, { extractable: true });
    const row: KeyRow = {
      kid: randomUUID(),
      public_jwk: await exportJWK(publicKey),
      private_jwk_encrypted: this.secrets.encrypt(JSON.stringify(await exportJWK(privateKey))),
    };
    await client.query(
      `INSERT INTO signing_keys (kid, alg, public_jwk, private_jwk_encrypted)
       VALUES ($1, $2, $3, $4)`,
      [row.kid, ALGORITHM, row.public_jwk, row.private_jwk_encrypted],
    );
    return row;
  }
}
