import type { Request, Response, NextFunction } from 'express';
import type pg from 'pg';
import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import type { Config } from './config';
import { checkPassword, passwordHash, randomToken, tokenHash, secureEqual } from './secrets';
import { transaction, appendAudit, get } from './db';
import { DEFAULT_SETTINGS, type Role } from '../shared/state';
import type { AppSettings } from '../src/types';
import { HttpError } from './validation';
export interface Operator {
  id: string;
  username: string;
  role: Role;
  sessionHash: string;
  csrf: string;
  expiresAt: string;
}
declare global {
  namespace Express {
    interface Request {
      operator?: Operator;
    }
  }
}
export const asyncRoute =
  (fn: (req: Request, res: Response, next: NextFunction) => Promise<unknown>) =>
  (req: Request, res: Response, next: NextFunction) => {
    void fn(req, res, next).catch(next);
  };
export function cookieName(config: Config) {
  return config.NODE_ENV === 'production' ? '__Host-vulnstream' : 'vulnstream';
}
export function requireAuth(pool: pg.Pool, config: Config) {
  return asyncRoute(async (req, res, next) => {
    const prefix = cookieName(config) + '=';
    const token =
      (req.headers.cookie || '')
        .split(';')
        .map((s) => s.trim())
        .find((s) => s.startsWith(prefix))
        ?.slice(prefix.length) || '';
    if (!/^[\w-]{43}$/.test(token)) throw new HttpError(401, 'Authentication required');
    const hash = tokenHash(token);
    const found = (
      await pool.query(
        `SELECT u.id,u.username,u.role,s.csrf,s.expires_at FROM sessions s JOIN users u ON u.id=s.user_id WHERE token_hash=$1 AND s.expires_at>now() AND s.absolute_expires_at>now() AND NOT u.disabled`,
        [hash],
      )
    ).rows[0];
    if (!found) throw new HttpError(401, 'Session expired');
    req.operator = {
      id: found.id,
      username: found.username,
      role: found.role,
      sessionHash: hash,
      csrf: found.csrf,
      expiresAt: found.expires_at.toISOString(),
    };
    if (
      !['GET', 'HEAD', 'OPTIONS'].includes(req.method) &&
      !secureEqual(String(req.headers['x-csrf-token'] || ''), found.csrf)
    )
      throw new HttpError(403, 'Invalid CSRF token');
    next();
  });
}
export function requireRole(...roles: Role[]) {
  return (req: Request, _res: Response, next: NextFunction) =>
    roles.includes(req.operator!.role) ? next() : next(new HttpError(403, 'Insufficient role'));
}
export async function createUser(pool: pg.Pool, username: string, password: string, role: Role, ipAddress = '') {
  z.string()
    .regex(/^[a-zA-Z0-9._@-]{3,100}$/)
    .parse(username);
  z.string().min(14).max(128).parse(password);
  z.enum(['ADMIN', 'OPERATOR', 'VIEWER']).parse(role);
  const policy = (await get<AppSettings>(pool, 'settings', 'main')) || DEFAULT_SETTINGS;
  if (password.length < policy.securityPolicy.minPasswordLen)
    throw new HttpError(400, 'Password does not meet configured minimum');
  const hash = await passwordHash(password);
  await transaction(pool, async (db) => {
    await db.query('INSERT INTO users(id,username,password_hash,role) VALUES($1,$2,$3,$4)', [
      randomUUID(),
      username.toLowerCase(),
      hash,
      role,
    ]);
    await appendAudit(db, 'Operator created', `Role ${role}`, username.toLowerCase(), 'SECURITY', 'INFO', ipAddress);
  });
}
export function loginHandler(pool: pg.Pool, config: Config) {
  return asyncRoute(async (req, res) => {
    const { username, password } = z
      .object({
        username: z
          .string()
          .min(1)
          .max(100)
          .transform((s) => s.toLowerCase()),
        password: z.string().min(1).max(128),
      })
      .parse(req.body);
    const keys = ['ip:' + tokenHash(req.ip || ''), 'user:' + tokenHash(username)];
    // Increment before doing expensive password work, atomically across workers.
    const allowed = await transaction(pool, async (db) => {
      let okay = true;
      for (const key of keys) {
        const result = await db.query(
          `INSERT INTO login_attempts(key,attempts,window_start) VALUES($1,1,now()) ON CONFLICT(key) DO UPDATE SET attempts=CASE WHEN login_attempts.window_start<now()-interval '15 minutes' THEN 1 ELSE login_attempts.attempts+1 END,window_start=CASE WHEN login_attempts.window_start<now()-interval '15 minutes' THEN now() ELSE login_attempts.window_start END RETURNING attempts`,
          [key],
        );
        if (result.rows[0].attempts > (key.startsWith('ip:') ? 25 : 5)) okay = false;
      }
      return okay;
    });
    if (!allowed) {
      res.setHeader('Retry-After', '900');
      throw new HttpError(429, 'Too many login attempts; retry in 15 minutes');
    }
    const user = (await pool.query('SELECT * FROM users WHERE username=$1', [username])).rows[0];
    // A fixed valid dummy hash keeps nonexistent accounts on the same password KDF path.
    const dummy = 'scrypt131072$00000000000000000000000000000000$' + '0'.repeat(128);
    const valid = await checkPassword(password, user?.password_hash || dummy);
    if (!user || user.disabled || !valid) throw new HttpError(401, 'Invalid username or password');
    const settings = (await get<AppSettings>(pool, 'settings', 'main')) || DEFAULT_SETTINGS;
    const token = randomToken(),
      csrf = randomToken(),
      expires = new Date(Date.now() + settings.securityPolicy.sessionTimeoutMins * 60000);
    await transaction(pool, async (db) => {
      await db.query('DELETE FROM login_attempts WHERE key=$1', [keys[1]]);
      await db.query(
        "INSERT INTO sessions(token_hash,user_id,csrf,expires_at,absolute_expires_at) VALUES($1,$2,$3,$4,now()+interval '12 hours')",
        [tokenHash(token), user.id, csrf, expires],
      );
      await appendAudit(db, 'Login succeeded', 'Operator session established', username, 'SECURITY', 'INFO', req.ip || '');
    });
    res.cookie(cookieName(config), token, {
      httpOnly: true,
      secure: config.NODE_ENV === 'production',
      sameSite: 'strict',
      path: '/',
      maxAge: 12 * 3600000,
    });
    res.json({ username, role: user.role, csrfToken: csrf, expiresAt: expires.toISOString() });
  });
}
